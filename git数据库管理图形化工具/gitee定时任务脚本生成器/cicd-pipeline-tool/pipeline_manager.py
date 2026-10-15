#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CI/CD 定时编译任务管理工具 (Gitee Go 流水线 / GitHub Actions)
零第三方依赖，单文件，Python 3.7+ 内置 tkinter。

功能：
  1. 扫描本地仓库中的定时任务（Gitee: .workflow/*.yml / GitHub: .github/workflows/*.yml）
  2. 可视化编辑 cron（每天/每周/每月 + 时间），自动适配两平台表达式格式
  3. git 提交并推送（凭据自动从界面令牌构造）
  4. 手动触发流水线 / workflow，查看运行历史（走官方 API，可选代理）
"""

import json
import os
import re
import subprocess
import threading
import urllib.request
import urllib.error
import urllib.parse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "CI/CD 定时编译任务管理工具"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# ---------------------------------------------------------------- HTTP 层

class ApiError(Exception):
    pass

def http_json(method, url, headers=None, data=None, proxy=None, timeout=20):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", "cicd-scheduler-tool/1.0")
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise ApiError(f"HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise ApiError(f"网络错误: {e.reason}")

# ---------------------------------------------------------------- 平台 API

class GiteeAPI:
    BASE = "https://gitee.com/api/v5"

    def __init__(self, token, proxy=None):
        self.token = token
        self.proxy = proxy

    def _url(self, path, **qs):
        qs["access_token"] = self.token
        return f"{self.BASE}{path}?{urllib.parse.urlencode(qs)}"

    def list_pipelines(self, owner, repo):
        return http_json("GET", self._url(f"/repos/{owner}/{repo}/pipelines", page=1, per_page=50),
                         proxy=self.proxy)

    def list_runs(self, owner, repo, pipeline_id):
        return http_json("GET", self._url(f"/repos/{owner}/{repo}/pipelines/{pipeline_id}/runs",
                                          page=1, per_page=10), proxy=self.proxy)

    def trigger(self, owner, repo, pipeline_id, branch):
        return http_json("POST", self._url(f"/repos/{owner}/{repo}/pipelines/{pipeline_id}/runs"),
                         data={"ref": branch}, proxy=self.proxy)

class GitHubAPI:
    BASE = "https://api.github.com"

    def __init__(self, token, proxy=None):
        self.headers = {"Authorization": f"token {token}"} if token else {}
        self.proxy = proxy

    def list_workflows(self, owner, repo):
        return http_json("GET", f"{self.BASE}/repos/{owner}/{repo}/actions/workflows?per_page=50",
                         headers=self.headers, proxy=self.proxy)

    def list_runs(self, owner, repo, workflow_id):
        return http_json("GET", f"{self.BASE}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs?per_page=10",
                         headers=self.headers, proxy=self.proxy)

    def trigger(self, owner, repo, workflow_id, branch):
        return http_json("POST", f"{self.BASE}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
                         headers=self.headers, data={"ref": branch}, proxy=self.proxy)

    def set_enabled(self, owner, repo, workflow_id, enabled):
        action = "enable" if enabled else "disable"
        return http_json("PUT", f"{self.BASE}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/{action}",
                         headers=self.headers, proxy=self.proxy)

# ---------------------------------------------------------------- cron 处理

DOW_NAMES = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"]

def build_cron(platform, freq, hour, minute, day_of_month=1, day_of_week=1):
    """按平台生成 cron。Gitee: 6位 quartz(秒 分 时 天 月 星期); GitHub: 5位(分 时 天 月 星期)"""
    if platform == "gitee":
        if freq == "daily":
            return f"0 {minute} {hour} * * ?"
        if freq == "weekly":
            return f"0 {minute} {hour} ? * {day_of_week}"
        return f"0 {minute} {hour} {day_of_month} * ?"
    else:  # github
        if freq == "daily":
            return f"{minute} {hour} * * *"
        if freq == "weekly":
            return f"{minute} {hour} * * {day_of_week}"
        return f"{minute} {hour} {day_of_month} * *"

def describe_cron(expr):
    """尽量把 cron 翻译成中文描述"""
    parts = expr.split()
    try:
        if len(parts) == 6:   # quartz: 秒 分 时 天 月 星期
            _, mi, hh, dom, _mon, dow = parts
        elif len(parts) == 5: # posix: 分 时 天 月 星期
            mi, hh, dom, _mon, dow = parts
        else:
            return expr
        time_s = f"{int(hh):02d}:{int(mi):02d}"
        if dom not in ("*", "?") and dow in ("*", "?"):
            return f"每月 {int(dom)} 号 {time_s}"
        if dow not in ("*", "?") and dom in ("*", "?"):
            d = int(dow) % 7
            return f"每{DOW_NAMES[d]} {time_s}"
        if dom in ("*", "?") and dow in ("*", "?"):
            return f"每天 {time_s}"
    except (ValueError, IndexError):
        pass
    return expr

CRON_LINE_RE = re.compile(r"^(\s*-?\s*cron\s*:\s*)['\"]?([^'\"\n]+?)['\"]?\s*$", re.M)

def extract_crons(text):
    return [m.group(2).strip() for m in CRON_LINE_RE.finditer(text)]

def replace_cron(text, new_expr):
    """替换文件中第一个 cron 表达式，返回新文本；找不到返回 None"""
    m = CRON_LINE_RE.search(text)
    if not m:
        return None
    return text[:m.start(2)] + new_expr + text[m.end(2):]

def scan_tasks(repo_dir):
    """扫描本地仓库中的定时任务文件 -> [{platform, path, rel, crons, release}]"""
    tasks = []
    groups = [("gitee", os.path.join(repo_dir, ".workflow")),
              ("github", os.path.join(repo_dir, ".github", "workflows"))]
    for platform, folder in groups:
        if not os.path.isdir(folder):
            continue
        for fn in sorted(os.listdir(folder)):
            if not fn.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(folder, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()
            except OSError:
                continue
            crons = extract_crons(text)
            if crons:
                marker = "ci-release.sh" if platform == "gitee" else "action-gh-release"
                tasks.append({"platform": platform, "path": path,
                              "rel": os.path.relpath(path, repo_dir), "crons": crons,
                              "release": marker in text})
    return tasks

# ---------------------------------------------------------------- 产物自动发布

GITEE_CI_RELEASE_SH = r"""#!/bin/bash
# Gitee Go 流水线：编译完成后创建 Gitee Release 并上传 bin/ 产物
# 前置条件：流水线编辑界面「变量设置」添加私密变量 RELEASE_TOKEN = Gitee 私人令牌
set -e

if [ -z "$RELEASE_TOKEN" ]; then
    echo "[ci-release] 未设置 RELEASE_TOKEN 私密变量，跳过 Release 发布"
    exit 0
fi

REMOTE=$(git remote get-url origin 2>/dev/null || echo "")
OWNER_REPO=$(echo "$REMOTE" | sed -E 's#.*gitee\.com[:/]##; s#\.git$##')
if [ -z "$OWNER_REPO" ] || [ "$OWNER_REPO" = "$REMOTE" ]; then
    echo "[ci-release] 无法从 remote 解析 owner/repo: $REMOTE，跳过"
    exit 0
fi

[ -d bin ] || { echo "[ci-release] 未找到 bin/ 目录，跳过"; exit 0; }

SHA=$(git rev-parse HEAD)
SHORT=$(git rev-parse --short HEAD)
TAG="auto-$(date +%Y.%m.%d-%H%M)-${SHORT}"
API="https://gitee.com/api/v5/repos/${OWNER_REPO}/releases"

echo "[ci-release] 创建 Release: ${TAG} (commit ${SHORT})"
RESP=$(curl -sS -X POST "$API" \
    -H "Content-Type: application/json;charset=UTF-8" \
    -d "{\"access_token\":\"${RELEASE_TOKEN}\",\"tag_name\":\"${TAG}\",\"name\":\"Auto build ${TAG}\",\"body\":\"流水线自动构建\\n\\ncommit: ${SHA}\",\"target_commitish\":\"${SHA}\",\"prerelease\":true}")

RID=$(echo "$RESP" | jq -r '.id // empty' 2>/dev/null)
if [ -z "$RID" ]; then
    echo "[ci-release] Release 创建失败，API 返回:"
    echo "$RESP"
    exit 1
fi

find bin -type f | while read -r f; do
    echo "[ci-release] 上传附件: $f"
    curl -sS -X POST "${API}/${RID}/attach_files" \
        -F "access_token=${RELEASE_TOKEN}" \
        -F "file=@${f}" > /dev/null
done

echo "[ci-release] 发布完成: https://gitee.com/${OWNER_REPO}/releases/${TAG}"
"""

GITHUB_RELEASE_STEP = (
    "\n      - name: Upload binaries to release\n"
    "        uses: softprops/action-gh-release@v2\n"
    "        with:\n"
    "          tag_name: auto-${{ github.run_id }}\n"
    "          name: Auto build ${{ github.run_id }}\n"
    "          files: bin/**\n"
    "          prerelease: true\n"
)

def _commands_block_end(lines, key_idx):
    """返回 commands: 列表的最后一项行号与列表项缩进"""
    item_indent = None
    last_item = None
    for j in range(key_idx + 1, len(lines)):
        ln = lines[j]
        m = re.match(r"^(\s*)-\s", ln)
        if m and (item_indent is None or m.group(1) == item_indent):
            item_indent = item_indent or m.group(1)
            last_item = j
            continue
        if ln.strip().startswith("#") or not ln.strip():
            continue
        break
    return last_item, item_indent

def _gitee_yml_enable_release(text):
    """向 Gitee 流水线 yml 注入：commands 末尾加 ci-release.sh 调用 + artifacts 暂存段
    注意：Gitee 自建变量是文本替换机制（不注入环境变量），必须显式传参 RELEASE_TOKEN=${RELEASE_TOKEN}"""
    lines = text.split("\n")
    key_idx = next((i for i, ln in enumerate(lines)
                    if re.match(r"^\s*commands\s*:\s*$", ln)), None)
    if key_idx is None:
        raise RuntimeError("yml 中未找到 commands: 列表，无法自动注入")
    last_item, indent = _commands_block_end(lines, key_idx)
    if last_item is None:
        raise RuntimeError("commands: 列表为空，无法自动注入")
    insert_at = last_item + 1
    if "ci-release.sh" not in text:
        lines.insert(insert_at, f"{indent}- RELEASE_TOKEN=${{RELEASE_TOKEN}} bash ./ci-release.sh")
        insert_at += 1
    if not re.search(r"^\s*artifacts\s*:", text, re.M):
        step_indent = indent[:-2] if len(indent) >= 2 else indent
        lines[insert_at:insert_at] = [
            f"{step_indent}artifacts:",
            f"{step_indent}  - name: BUILD_ARTIFACT",
            f"{step_indent}    path:",
            f"{step_indent}      - ./bin",
        ]
    return "\n".join(lines)

def enable_release(task, repo_dir):
    """为选中任务启用产物自动发布，返回修改的文件相对路径列表"""
    path = task["path"]
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    changed = [task["rel"]]
    if task["platform"] == "gitee":
        new_text = text if "ci-release.sh" in text and re.search(r"^\s*artifacts\s*:", text, re.M) \
            else _gitee_yml_enable_release(text)
        sh_path = os.path.join(repo_dir, "ci-release.sh")
        if not os.path.exists(sh_path):
            with open(sh_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(GITEE_CI_RELEASE_SH)
            changed.append("ci-release.sh")
    else:
        new_text = text if "action-gh-release" in text else text.rstrip("\n") + GITHUB_RELEASE_STEP
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(new_text)
    return changed

# ---------------------------------------------------------------- git

def run_git(repo_dir, args):
    p = subprocess.run(["git", "-C", repo_dir] + args,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip())
    return p.stdout.strip()

def authed_remote_url(platform, owner, repo, token):
    if platform == "gitee":
        return f"https://{owner}:{token}@gitee.com/{owner}/{repo}.git"
    return f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"

def git_push_file(repo_dir, rel_paths, message, remote_url, branch):
    if isinstance(rel_paths, str):
        rel_paths = [rel_paths]
    run_git(repo_dir, ["add"] + rel_paths)
    run_git(repo_dir, ["commit", "-m", message])
    run_git(repo_dir, ["push", remote_url, f"HEAD:{branch}"])

# ---------------------------------------------------------------- GUI

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x640")
        self.minsize(860, 560)
        self.tasks = []          # 扫描出的定时任务
        self.remote_items = []   # API 拉到的流水线/workflow
        self._build_top()
        self._build_notebook()
        self._load_config()

    # ---------------- 顶部连接区
    def _build_top(self):
        frm = ttk.LabelFrame(self, text=" 连接设置 ")
        frm.pack(fill="x", padx=8, pady=6)

        ttk.Label(frm, text="平台:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        self.platform_var = tk.StringVar(value="gitee")
        ttk.Combobox(frm, textvariable=self.platform_var, width=8, state="readonly",
                     values=["gitee", "github"]).grid(row=0, column=1, sticky="w")

        ttk.Label(frm, text="仓库(owner/repo):").grid(row=0, column=2, sticky="e", padx=4)
        self.repo_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.repo_var, width=34).grid(row=0, column=3, sticky="w")

        ttk.Label(frm, text="分支:").grid(row=0, column=4, sticky="e", padx=4)
        self.branch_var = tk.StringVar(value="main")
        ttk.Entry(frm, textvariable=self.branch_var, width=10).grid(row=0, column=5, sticky="w")

        ttk.Label(frm, text="令牌:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.token_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.token_var, width=44, show="*").grid(row=1, column=1,
                                                                              columnspan=3, sticky="w")
        ttk.Label(frm, text="代理(可选):").grid(row=1, column=4, sticky="e", padx=4)
        self.proxy_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.proxy_var, width=20).grid(row=1, column=5, sticky="w")

        ttk.Label(frm, text="本地仓库路径:").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        self.local_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.local_var, width=56).grid(row=2, column=1,
                                                                    columnspan=4, sticky="w")
        ttk.Button(frm, text="浏览...", command=self._browse).grid(row=2, column=5, sticky="w", padx=4)

        ttk.Button(frm, text="保存配置", command=self._save_config).grid(row=3, column=3, sticky="e", pady=4)
        ttk.Button(frm, text="连接并刷新", command=self.refresh_all).grid(row=3, column=5, sticky="w", padx=4)

    def _browse(self):
        d = filedialog.askdirectory(title="选择本地仓库目录")
        if d:
            self.local_var.set(d)

    # ---------------- 选项卡
    def _build_notebook(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=4)

        # --- Tab1 定时任务
        tab1 = ttk.Frame(nb)
        nb.add(tab1, text=" 定时任务 ")
        cols = ("platform", "file", "cron", "desc", "release")
        self.task_tree = ttk.Treeview(tab1, columns=cols, show="headings", height=10)
        for cid, txt, w in [("platform", "平台", 70), ("file", "文件", 330),
                            ("cron", "cron 表达式", 180), ("desc", "含义", 180),
                            ("release", "自动发布", 80)]:
            self.task_tree.heading(cid, text=txt)
            self.task_tree.column(cid, width=w, anchor="w")
        self.task_tree.pack(fill="both", expand=True, padx=6, pady=6)
        self.task_tree.bind("<<TreeviewSelect>>", self._on_task_select)
        bar = ttk.Frame(tab1)
        bar.pack(fill="x", padx=6, pady=4)
        ttk.Button(bar, text="扫描本地任务", command=self.scan_local).pack(side="left", padx=4)
        ttk.Button(bar, text="编辑选中任务定时", command=self.load_selected_to_editor).pack(side="left", padx=4)
        ttk.Button(bar, text="启用产物自动发布并推送", command=self.enable_release_selected).pack(side="left", padx=4)

        # --- Tab2 定时编辑器
        tab2 = ttk.LabelFrame(nb, text=" 定时编辑器 ")
        nb.add(tab2, text=" 编辑定时 ")
        self.edit_file_var = tk.StringVar()
        ttk.Label(tab2, text="目标文件:").grid(row=0, column=0, sticky="e", padx=6, pady=8)
        ttk.Entry(tab2, textvariable=self.edit_file_var, width=70, state="readonly").grid(
            row=0, column=1, columnspan=5, sticky="w")

        self.freq_var = tk.StringVar(value="monthly")
        ttk.Label(tab2, text="频率:").grid(row=1, column=0, sticky="e", padx=6)
        ttk.Radiobutton(tab2, text="每天", variable=self.freq_var, value="daily",
                        command=self._update_cron_preview).grid(row=1, column=1, sticky="w")
        ttk.Radiobutton(tab2, text="每周", variable=self.freq_var, value="weekly",
                        command=self._update_cron_preview).grid(row=1, column=2, sticky="w")
        ttk.Radiobutton(tab2, text="每月", variable=self.freq_var, value="monthly",
                        command=self._update_cron_preview).grid(row=1, column=3, sticky="w")

        ttk.Label(tab2, text="时间(时:分):").grid(row=2, column=0, sticky="e", padx=6, pady=8)
        self.hour_var = tk.IntVar(value=10)
        self.min_var = tk.IntVar(value=0)
        ttk.Spinbox(tab2, from_=0, to=23, width=4, textvariable=self.hour_var,
                    command=self._update_cron_preview).grid(row=2, column=1, sticky="w")
        ttk.Spinbox(tab2, from_=0, to=59, width=4, textvariable=self.min_var,
                    command=self._update_cron_preview).grid(row=2, column=2, sticky="w")

        ttk.Label(tab2, text="每月几号:").grid(row=3, column=0, sticky="e", padx=6)
        self.dom_var = tk.IntVar(value=1)
        ttk.Spinbox(tab2, from_=1, to=28, width=4, textvariable=self.dom_var,
                    command=self._update_cron_preview).grid(row=3, column=1, sticky="w")
        ttk.Label(tab2, text="每周几:").grid(row=3, column=2, sticky="e", padx=6)
        self.dow_var = tk.StringVar(value="周一")
        cb = ttk.Combobox(tab2, textvariable=self.dow_var, width=6, state="readonly", values=DOW_NAMES)
        cb.grid(row=3, column=3, sticky="w")
        cb.bind("<<ComboboxSelected>>", lambda _e: self._update_cron_preview())

        ttk.Label(tab2, text="cron 预览:").grid(row=4, column=0, sticky="e", padx=6, pady=8)
        self.cron_preview = tk.StringVar()
        ttk.Entry(tab2, textvariable=self.cron_preview, width=40).grid(row=4, column=1,
                                                                        columnspan=3, sticky="w")
        ttk.Label(tab2, text="(可直接修改预览框中的表达式)").grid(row=4, column=4, sticky="w")

        ttk.Button(tab2, text="保存并推送到远程", command=self.save_and_push).grid(
            row=5, column=1, sticky="w", pady=10)
        ttk.Button(tab2, text="仅保存到本地文件", command=lambda: self.save_and_push(push=False)).grid(
            row=5, column=2, sticky="w", pady=10)

        # --- Tab3 远程流水线 / 运行历史
        tab3 = ttk.Frame(nb)
        nb.add(tab3, text=" 远程任务与运行 ")
        cols = ("id", "name", "state")
        self.remote_tree = ttk.Treeview(tab3, columns=cols, show="headings", height=7)
        for cid, txt, w in [("id", "ID", 110), ("name", "名称", 320), ("state", "状态", 160)]:
            self.remote_tree.heading(cid, text=txt)
            self.remote_tree.column(cid, width=w, anchor="w")
        self.remote_tree.pack(fill="both", expand=True, padx=6, pady=6)
        bar3 = ttk.Frame(tab3)
        bar3.pack(fill="x", padx=6, pady=2)
        ttk.Button(bar3, text="加载远程列表", command=self.load_remote).pack(side="left", padx=4)
        ttk.Button(bar3, text="手动触发选中", command=self.trigger_selected).pack(side="left", padx=4)
        ttk.Button(bar3, text="查看运行历史", command=self.load_runs).pack(side="left", padx=4)
        ttk.Button(bar3, text="启用/禁用(GitHub)", command=self.toggle_selected).pack(side="left", padx=4)

        cols = ("run", "status", "conclusion", "time")
        self.runs_tree = ttk.Treeview(tab3, columns=cols, show="headings", height=8)
        for cid, txt, w in [("run", "运行 #", 100), ("status", "状态", 110),
                            ("conclusion", "结果", 110), ("time", "时间", 220)]:
            self.runs_tree.heading(cid, text=txt)
            self.runs_tree.column(cid, width=w, anchor="w")
        self.runs_tree.pack(fill="both", expand=True, padx=6, pady=6)

        # --- Tab4 日志
        tab4 = ttk.Frame(nb)
        nb.add(tab4, text=" 日志 ")
        self.log_text = tk.Text(tab4, wrap="word", state="disabled", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

        self._update_cron_preview()

    # ---------------- 配置持久化
    def _load_config(self):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            self.platform_var.set(cfg.get("platform", "gitee"))
            self.repo_var.set(cfg.get("repo", ""))
            self.branch_var.set(cfg.get("branch", "main"))
            self.token_var.set(cfg.get("token", ""))
            self.proxy_var.set(cfg.get("proxy", ""))
            self.local_var.set(cfg.get("local", ""))
        except (OSError, json.JSONDecodeError):
            pass

    def _save_config(self):
        cfg = {"platform": self.platform_var.get(), "repo": self.repo_var.get(),
               "branch": self.branch_var.get(), "token": self.token_var.get(),
               "proxy": self.proxy_var.get(), "local": self.local_var.get()}
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        self.log("配置已保存到 config.json")

    # ---------------- 工具
    def log(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _api(self):
        platform = self.platform_var.get()
        if platform == "gitee":
            return GiteeAPI(self.token_var.get().strip(), proxy=self.proxy_var.get().strip() or None)
        return GitHubAPI(self.token_var.get().strip(), proxy=self.proxy_var.get().strip() or None)

    def _owner_repo(self):
        parts = self.repo_var.get().strip().strip("/").split("/")
        if len(parts) != 2 or not all(parts):
            raise ValueError("仓库格式应为 owner/repo")
        return parts[0], parts[1]

    def _bg(self, fn, *args):
        def wrap():
            try:
                fn(*args)
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: self.log(f"[错误] {e}"))
        threading.Thread(target=wrap, daemon=True).start()

    def refresh_all(self):
        self.scan_local()
        self.load_remote()

    # ---------------- Tab1 本地扫描
    def scan_local(self):
        repo = self.local_var.get().strip()
        if not repo or not os.path.isdir(repo):
            messagebox.showwarning(APP_TITLE, "请先填写有效的本地仓库路径")
            return
        self.tasks = scan_tasks(repo)
        self.task_tree.delete(*self.task_tree.get_children())
        for i, t in enumerate(self.tasks):
            cron = t["crons"][0]
            self.task_tree.insert("", "end", iid=str(i), values=(
                t["platform"], t["rel"], cron, describe_cron(cron),
                "已启用" if t.get("release") else "未启用"))
        self.log(f"扫描完成：发现 {len(self.tasks)} 个含定时任务的文件")

    def _on_task_select(self, _evt):
        pass

    def enable_release_selected(self):
        sel = self.task_tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "请先在列表中选中一个任务")
            return
        t = self.tasks[int(sel[0])]
        if t.get("release"):
            messagebox.showinfo(APP_TITLE, "该任务已启用产物自动发布")
            return
        repo = self.local_var.get().strip()
        try:
            changed = enable_release(t, repo)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(APP_TITLE, f"启用失败: {e}")
            return
        for rel in changed:
            self.log(f"已修改: {rel}")
        if t["platform"] == "gitee":
            self.log("提示: 请确认流水线「变量设置」中存在私密变量 RELEASE_TOKEN")
        else:
            self.log("提示: GitHub 发布使用 GITHUB_TOKEN（workflow 自动授予，无需配置）")
        if not messagebox.askyesno(APP_TITLE, f"已修改 {len(changed)} 个文件，是否提交并推送到远程？"):
            self.scan_local()
            return
        def work():
            owner, name = self._owner_repo()
            url = authed_remote_url(t["platform"], owner, name, self.token_var.get().strip())
            branch = self.branch_var.get().strip() or "main"
            git_push_file(repo, changed, "ci: enable artifact auto-release", url, branch)
            self.after(0, lambda: self.log(f"已推送 {len(changed)} 个文件到 {t['platform']} 远程分支 {branch}"))
            self.after(0, self.scan_local)
        self._bg(work)

    def load_selected_to_editor(self):
        sel = self.task_tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "请先在列表中选中一个任务")
            return
        t = self.tasks[int(sel[0])]
        self.edit_file_var.set(t["path"])
        self.edit_platform = t["platform"]
        self._update_cron_preview()
        self.log(f"已载入编辑器: {t['rel']} (平台 {t['platform']})")

    # ---------------- Tab2 编辑/保存
    def _update_cron_preview(self):
        platform = getattr(self, "edit_platform", self.platform_var.get())
        dow = DOW_NAMES.index(self.dow_var.get()) if self.dow_var.get() in DOW_NAMES else 1
        # quartz 周日=1..周六=7；posix 周日=0..周六=6
        dow_num = (dow + 1) if platform == "gitee" else dow
        expr = build_cron(platform, self.freq_var.get(), self.hour_var.get(),
                          self.min_var.get(), self.dom_var.get(), dow_num)
        self.cron_preview.set(expr)

    def save_and_push(self, push=True):
        path = self.edit_file_var.get()
        if not path:
            messagebox.showinfo(APP_TITLE, "请先在「定时任务」页选择任务载入编辑器")
            return
        expr = self.cron_preview.get().strip()
        if not expr:
            messagebox.showwarning(APP_TITLE, "cron 表达式为空")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"读取文件失败: {e}")
            return
        new_text = replace_cron(text, expr)
        if new_text is None:
            messagebox.showerror(APP_TITLE, "文件中未找到 cron 配置行")
            return
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_text)
        self.log(f"已更新 {os.path.basename(path)} 的 cron -> {expr} ({describe_cron(expr)})")

        if push:
            self._bg(self._do_push, path, expr)

    def _do_push(self, path, expr):
        repo = self.local_var.get().strip()
        rel = os.path.relpath(path, repo)
        platform = getattr(self, "edit_platform", self.platform_var.get())
        owner, name = self._owner_repo()
        url = authed_remote_url(platform, owner, name, self.token_var.get().strip())
        branch = self.branch_var.get().strip() or "main"
        msg = f"ci: update schedule to '{expr}' for {os.path.basename(path)}"
        git_push_file(repo, rel, msg, url, branch)
        self.after(0, lambda: self.log(f"已推送: {rel} -> {platform} 远程分支 {branch}"))
        self.after(0, self.scan_local)

    # ---------------- Tab3 远程操作
    def load_remote(self):
        def work():
            owner, repo = self._owner_repo()
            platform = self.platform_var.get()
            api = self._api()
            items = []
            if platform == "gitee":
                data = api.list_pipelines(owner, repo)
                for p in (data if isinstance(data, list) else []):
                    items.append((str(p.get("id", "?")), p.get("name", "?"),
                                  p.get("status", p.get("state", "?"))))
            else:
                data = api.list_workflows(owner, repo)
                for w in data.get("workflows", []):
                    items.append((str(w.get("id")), w.get("name"), w.get("state")))
            self.remote_items = items
            def fill():
                self.remote_tree.delete(*self.remote_tree.get_children())
                for i, it in enumerate(items):
                    self.remote_tree.insert("", "end", iid=str(i), values=it)
                self.log(f"远程列表加载完成：{len(items)} 条")
            self.after(0, fill)
        self._bg(work)

    def _selected_remote(self):
        sel = self.remote_tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "请先选中一条远程任务")
            return None
        return self.remote_items[int(sel[0])]

    def trigger_selected(self):
        item = self._selected_remote()
        if not item:
            return
        def work():
            owner, repo = self._owner_repo()
            platform = self.platform_var.get()
            api = self._api()
            branch = self.branch_var.get().strip() or "main"
            if platform == "gitee":
                api.trigger(owner, repo, item[0], branch)
            else:
                api.trigger(owner, repo, item[0], branch)
            self.after(0, lambda: self.log(f"已触发: {item[1]} (分支 {branch})"))
        self._bg(work)

    def load_runs(self):
        item = self._selected_remote()
        if not item:
            return
        def work():
            owner, repo = self._owner_repo()
            platform = self.platform_var.get()
            api = self._api()
            rows = []
            if platform == "gitee":
                data = api.list_runs(owner, repo, item[0])
                for r in (data if isinstance(data, list) else data.get("runs", [])):
                    rows.append((str(r.get("number", r.get("id", "?"))),
                                 str(r.get("status", "?")), str(r.get("conclusion", r.get("result", "-"))),
                                 str(r.get("created_at", r.get("created", "?")))))
            else:
                data = api.list_runs(owner, repo, item[0])
                for r in data.get("workflow_runs", []):
                    rows.append((str(r.get("run_number")), str(r.get("status")),
                                 str(r.get("conclusion")), str(r.get("created_at"))))
            def fill():
                self.runs_tree.delete(*self.runs_tree.get_children())
                for i, row in enumerate(rows):
                    self.runs_tree.insert("", "end", iid=str(i), values=row)
                self.log(f"运行历史：{len(rows)} 条 ({item[1]})")
            self.after(0, fill)
        self._bg(work)

    def toggle_selected(self):
        item = self._selected_remote()
        if not item:
            return
        if self.platform_var.get() != "github":
            messagebox.showinfo(APP_TITLE, "启用/禁用仅支持 GitHub Actions")
            return
        enable = "disabled" not in item[2]
        def work():
            owner, repo = self._owner_repo()
            self._api().set_enabled(owner, repo, item[0], enable)
            self.after(0, lambda: self.log(f"{'已启用' if enable else '已禁用'}: {item[1]}"))
            self.after(0, self.load_remote)
        self._bg(work)

if __name__ == "__main__":
    App().mainloop()

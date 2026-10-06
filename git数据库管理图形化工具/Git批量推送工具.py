#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================
 通用 Git 批量推送工具 (Windows / 纯标准库 Tkinter GUI)
================================================================
用途: 把任意多个【本地文件/目录】批量复制进一个 Git 暂存工作区,
      自动 init/fetch/同步/提交/推送到指定远程仓库。
适用: GitHub / Gitee / GitLab / Gitea / 自建 Git, 支持 HTTPS(账号+令牌)
      与 SSH(本机已配好密钥) 两种远程地址。

设计要点 (避免"看似成功但远端没有文件"):
  * 暂存工作区由本工具管理: 远程分支已存在时 fetch 后 reset --hard 对齐,
    不在"无初始提交"的仓库上执行 stash/pull, 从根本上避免首次推送中断。
  * 远程分支是否存在用 ls-remote 显式判断: 不存在 -> 首次 push 建分支;
    存在 -> 对齐后叠加本次文件。
  * "工作区有改动"与"有没有提交"分开处理: git add -A 后用
    diff --cached 判断是否真的需要 commit; 没有改动也给出明确提示。
  * 令牌只在单条 git 命令的一次性 URL 中使用, 不写入 remote、不写入配置、
    不打印到日志; remote origin 永远保存不含凭证的干净 URL。
  * GIT_TERMINAL_PROMPT=0: 认证失败直接报错, 绝不弹窗假死。
================================================================
"""
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    print("当前 Python 无 tkinter, 无法启动图形界面。")
    raise

# 首次启动的预填值 (针对当前任务); 换仓库/换文件时直接在界面改即可, 通用。
DEFAULT_REMOTE = "https://github.com/qlljcf666/nradi-NROS2.2.5-1.9.4-ipk.git"
DEFAULT_BRANCH = "main"
DEFAULT_SOURCES = [
    r"c:\Users\ZH\Desktop\临时文件\nradi-NROS1.9.4-ipk",
    r"c:\Users\ZH\Desktop\临时文件\nradi-NROS2.2.5-ipk",
]
def _app_dir():
    """源码态=脚本所在目录; PyInstaller 冻结态=exe 所在目录(非临时解压目录)。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


DEFAULT_WORKSPACE = os.path.join(_app_dir(), "_git_push_workspace")
# 仅保存非敏感配置 (不含令牌)
CONFIG_PATH = os.path.join(os.path.expanduser("~"),
                           ".git_batch_push_gui.json")
GITHUB_HARD_LIMIT = 100 * 1024 * 1024   # 单文件 100MB, GitHub/Gitee 硬限制


# ============================================================== Git 核心
class PushError(Exception):
    pass


def mask_url(url):
    """日志用: 隐藏 URL 中的账号密码/令牌。"""
    return re.sub(r"(https?://)[^/@]*@", r"\1***@", url)


def build_auth_url(url, user, token):
    """构造一次性带凭证 URL; 非 http(s) 或无令牌时原样返回(SSH 等)。"""
    if not token or not url.startswith(("http://", "https://")):
        return url
    m = re.match(r"^(https?://)([^/]+)/(.*)$", url.strip())
    if not m:
        raise PushError("远程地址格式不正确: " + url)
    scheme, host, path = m.groups()
    u = urllib.parse.quote((user or "x-access-token").strip(), safe="")
    t = urllib.parse.quote(token.strip(), safe="")
    return f"{scheme}{u}:{t}@{host}/{path}"


class GitPusher:
    def __init__(self, remote, branch, user, token, workspace,
                 committer_name, committer_email, log):
        self.remote = remote.strip()
        self.branch = branch.strip() or "main"
        self.user = (user or "").strip()
        self.token = (token or "").strip()
        self.ws = os.path.abspath(workspace)
        self.cname = (committer_name or "git-push-tool").strip()
        self.cemail = (committer_email or
                       "git-push-tool@localhost").strip()
        self.log = log

    # ---------- 底层命令 ----------
    def _git(self, args, check=True, auth=False):
        """执行 git; auth=True 时把 origin 参数替换为带凭证的一次性 URL。"""
        url = build_auth_url(self.remote, self.user, self.token) \
            if auth else None
        argv = ["git"]
        for a in args:
            if a == "__URL__":
                argv.append(url if url else self.remote)
            else:
                argv.append(a)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env.setdefault("LC_ALL", "C")
        shown = " ".join('"' + mask_url(x) + '"' if " " in x
                         else mask_url(x) for x in argv[1:])
        self.log("$ git " + shown, "dim")
        p = subprocess.run(argv, cwd=self.ws, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = (p.stdout or b"").decode("utf-8", "replace")
        err = (p.stderr or b"").decode("utf-8", "replace")
        if out.strip():
            self.log(out.rstrip(), "dim")
        if check and p.returncode != 0:
            hint = ""
            low = (out + err).lower()
            if "authentication failed" in low or "403" in low \
                    or "could not read username" in low \
                    or "invalid username or password" in low:
                hint = ("\n  -> 认证失败: 请检查用户名/令牌(GitHub 用 PAT, "
                        "Gitee 用账号+私人令牌), 令牌需要 repo 写权限。")
            if "timed out" in low or "could not resolve host" in low \
                    or "failed to connect" in low:
                hint = "\n  -> 网络不通: GitHub 可能需要代理/稍后重试。"
            raise PushError("git " + args[0] + " 失败(exit "
                            + str(p.returncode) + "):\n"
                            + (err or out).strip() + hint)
        return p.returncode, out, err

    # ---------- 前置检查 ----------
    def precheck(self):
        if not self.remote:
            raise PushError("请填写远程仓库地址")
        if shutil.which("git") is None:
            raise PushError("未找到 git, 请先安装 Git for Windows 并加入 PATH")

    def _ensure_identity(self):
        _, name, _ = self._git(["config", "user.name"], check=False)
        _, mail, _ = self._git(["config", "user.email"], check=False)
        if not name.strip():
            self._git(["config", "user.name", self.cname])
        if not mail.strip():
            self._git(["config", "user.email", self.cemail])

    def _remote_branch_exists(self):
        """用 ls-remote 判断远程分支是否存在(不依赖本地 origin/分支引用)。"""
        rc, out, err = self._git(
            ["ls-remote", "--heads", "__URL__", self.branch], auth=True,
            check=False)
        if rc != 0:
            raise PushError("无法连接远程仓库(ls-remote 失败):\n"
                            + err.strip())
        return bool(out.strip())

    # ---------- 主流程 ----------
    def sync_workspace(self):
        os.makedirs(self.ws, exist_ok=True)
        if not os.path.isdir(os.path.join(self.ws, ".git")):
            self.log("初始化暂存工作区: " + self.ws)
            rc, _, _ = self._git(["init"], check=False)
            if rc != 0:
                self._git(["init", "-b", self.branch], check=False)
        # origin 永远存干净 URL (不含令牌)
        rc, out, _ = self._git(["remote"], check=False)
        remotes = out.split()
        if "origin" not in remotes:
            self._git(["remote", "add", "origin", self.remote])
        else:
            self._git(["remote", "set-url", "origin", self.remote])

        self._ensure_identity()

        if self._remote_branch_exists():
            self.log(f"远程分支 {self.branch} 已存在, 拉取并对齐工作区...")
            # 通配 fetch, 同步全部 refs/remotes/origin/*
            self._git(["fetch", "__URL__",
                       "+refs/heads/*:refs/remotes/origin/*", "--prune"],
                      auth=True)
            self._git(["checkout", "-B", self.branch,
                       "origin/" + self.branch])
            self._git(["reset", "--hard", "origin/" + self.branch])
            self._git(["clean", "-fdq"])
        else:
            self.log(f"远程尚无分支 {self.branch}: 将走首次推送(自动建分支)。")
            rc, out, _ = self._git(["rev-parse", "--verify", "HEAD"],
                                   check=False)
            if rc == 0:
                self._git(["checkout", "-B", self.branch])
            else:
                # 全新空仓库: 先建无提交分支
                rc2, _, _ = self._git(["checkout", "-b", self.branch],
                                      check=False)
                if rc2 != 0:
                    self._git(["checkout", "--orphan", self.branch],
                              check=False)

    def copy_items(self, items, allow_oversize=False):
        """items: [(源路径, 仓库内目标相对路径, 模式 add|mirror), ...]"""
        big_warn, big_kill = [], []
        total = 0
        for idx, (src, dest, mode) in enumerate(items, 1):
            if not os.path.exists(src):
                raise PushError(f"源不存在: {src}")
            dest = dest.replace("\\", "/").strip("/")
            if not dest or dest.startswith("/") or ".." in dest.split("/"):
                raise PushError(f"仓库内目标路径非法: {dest!r} (源: {src})")
            target = os.path.join(self.ws, *dest.split("/"))
            kind = "目录" if os.path.isdir(src) else "文件"
            self.log(f"[{idx}/{len(items)}] 复制{kind}: {src}  ->  {dest}"
                     + ("  (镜像: 先清空目标)" if mode == "mirror" else ""))
            if mode == "mirror" and os.path.exists(target):
                if os.path.isdir(target) and not os.path.islink(target):
                    shutil.rmtree(target)
                else:
                    os.remove(target)
            os.makedirs(os.path.dirname(target) or self.ws, exist_ok=True)
            if os.path.isdir(src):
                shutil.copytree(src, target, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns(".git"))
            else:
                shutil.copy2(src, target)
            # 大文件扫描
            for root, _dirs, files in os.walk(target) if os.path.isdir(target) \
                    else [("", [], [target])]:
                for fn in files:
                    fp = os.path.join(root, fn) if root else fn
                    try:
                        sz = os.path.getsize(fp)
                    except OSError:
                        continue
                    total += 1
                    if sz >= GITHUB_HARD_LIMIT:
                        big_kill.append((os.path.relpath(fp, self.ws), sz))
                    elif sz >= 50 * 1024 * 1024:
                        big_warn.append((os.path.relpath(fp, self.ws), sz))
        for rel, sz in big_warn:
            self.log(f"  注意: {rel} 为 {sz/1024/1024:.1f}MB "
                     "(>50MB, GitHub 会警告但通常可传)", "warn")
        if big_kill and not allow_oversize:
            lines = "\n".join(f"  {rel}  ({sz/1024/1024:.1f}MB)"
                              for rel, sz in big_kill[:20])
            more = ("\n  ... 另有 %d 个" % (len(big_kill) - 20)
                    if len(big_kill) > 20 else "")
            raise PushError("存在超过 100MB 的文件, GitHub/Gitee 会拒绝推送:"
                            f"\n{lines}{more}\n如用支持大文件的自建 Git, "
                            "可勾选'跳过 100MB 检查'后重试。")
        self.log(f"暂存区文件统计完成 (约 {total} 个文件)。")

    def commit_and_push(self, message):
        self._git(["add", "-A"])
        rc, out, _ = self._git(["diff", "--cached", "--name-only"],
                               check=False)
        changed = [x for x in out.splitlines() if x.strip()]
        if not changed:
            # 仍检查有无未推送提交(独立于工作区改动)
            rc2, ahead, _ = self._git(
                ["rev-list", "--count", "HEAD"], check=False)
            n_ahead = int(ahead.strip() or 0) if rc2 == 0 else 0
            if n_ahead and not self._remote_branch_exists():
                self.log("工作区无新改动, 但存在尚未推送的初始提交, 继续推送。",
                         "warn")
            else:
                self.log("没有需要提交的改动 (源目录内容与远端一致), 推送跳过。",
                         "ok")
                return False
        else:
            self.log(f"本次变更 {len(changed)} 个文件, 创建提交...")
            msg = message.strip() or ("批量推送 " +
                                      datetime.now().strftime("%Y-%m-%d %H:%M"))
            self._git(["commit", "-m", msg])

        self.log(f"推送到 {mask_url(self.remote)} 分支 {self.branch} ...")
        if self._remote_branch_exists():
            self._git(["push", "__URL__",
                       f"{self.branch}:{self.branch}"], auth=True)
        else:
            self._git(["push", "-u", "__URL__",
                       f"{self.branch}:{self.branch}"], auth=True)
            # upstream 指向不含凭证的 origin, 方便以后手工操作
            self._git(["branch", "--set-upstream-to=" +
                       "origin/" + self.branch, self.branch], check=False)
        self.log("推送完成 ✓", "ok")
        return True


# ============================================================== GUI
class App:
    def __init__(self, root):
        self.root = root
        root.title("通用 Git 批量推送工具  (GitHub / Gitee / 任意 Git 仓库)")
        root.geometry("980x760")
        self.q = queue.Queue()
        self.running = False
        self._build()
        self._load_config()
        self.root.after(120, self._poll)

    # ---------- 界面 ----------
    def _build(self):
        pad = {"padx": 6, "pady": 3}

        # 远程仓库
        f1 = ttk.LabelFrame(self.root, text="1. 远程仓库")
        f1.pack(fill="x", **pad)
        self.var_url = tk.StringVar(value=DEFAULT_REMOTE)
        self.var_branch = tk.StringVar(value=DEFAULT_BRANCH)
        self.var_user = tk.StringVar()
        self.var_token = tk.StringVar()
        self.var_show = tk.BooleanVar(value=False)
        ttk.Label(f1, text="仓库地址:").grid(row=0, column=0, sticky="e")
        ttk.Entry(f1, textvariable=self.var_url).grid(
            row=0, column=1, columnspan=5, sticky="we", padx=4)
        ttk.Label(f1, text="分支:").grid(row=1, column=0, sticky="e")
        ttk.Entry(f1, textvariable=self.var_branch, width=14).grid(
            row=1, column=1, sticky="w")
        ttk.Label(f1, text="用户名(HTTPS):").grid(row=1, column=2, sticky="e")
        ttk.Entry(f1, textvariable=self.var_user, width=20).grid(
            row=1, column=3, sticky="w")
        ttk.Label(f1, text="令牌/密码:").grid(row=1, column=4, sticky="e")
        self.ent_token = ttk.Entry(f1, textvariable=self.var_token,
                                   width=26, show="*")
        self.ent_token.grid(row=1, column=5, sticky="w")
        ttk.Checkbutton(f1, text="显示", variable=self.var_show,
                        command=self._toggle_token).grid(
            row=1, column=6, padx=4)
        ttk.Label(f1, foreground="#666",
                  text="HTTPS 推送必填: GitHub 用户名可随意(令牌用 PAT, 需 "
                       "repo 权限); Gitee 填账号+私人令牌。用 SSH 地址"
                       "(git@...) 且本机已配密钥则留空。"
                  ).grid(row=2, column=0, columnspan=7, sticky="w", padx=6)
        f1.columnconfigure(1, weight=1)

        # 工作区 + 提交信息
        f2 = ttk.LabelFrame(self.root, text="2. 暂存工作区与提交信息")
        f2.pack(fill="x", **pad)
        self.var_ws = tk.StringVar(value=DEFAULT_WORKSPACE)
        ttk.Label(f2, text="工作区目录:").grid(row=0, column=0, sticky="e")
        ttk.Entry(f2, textvariable=self.var_ws).grid(
            row=0, column=1, columnspan=4, sticky="we", padx=4)
        ttk.Button(f2, text="浏览...", command=self._browse_ws).grid(
            row=0, column=5)
        self.var_cname = tk.StringVar(value="qlljcf666")
        self.var_cmail = tk.StringVar(
            value="qlljcf666@users.noreply.github.com")
        self.var_msg = tk.StringVar(
            value="批量推送 NROS 1.9.4 / 2.2.5 ipk 文件 "
                  + datetime.now().strftime("%Y-%m-%d"))
        ttk.Label(f2, text="提交署名:").grid(row=1, column=0, sticky="e")
        ttk.Entry(f2, textvariable=self.var_cname, width=18).grid(
            row=1, column=1, sticky="w")
        ttk.Label(f2, text="邮箱:").grid(row=1, column=2, sticky="e")
        ttk.Entry(f2, textvariable=self.var_cmail, width=30).grid(
            row=1, column=3, sticky="w")
        ttk.Label(f2, text="提交信息:").grid(row=2, column=0, sticky="e")
        ttk.Entry(f2, textvariable=self.var_msg).grid(
            row=2, column=1, columnspan=4, sticky="we", padx=4)
        self.var_big = tk.BooleanVar(value=False)
        ttk.Checkbutton(f2, text="跳过 100MB 单文件检查",
                        variable=self.var_big).grid(
            row=1, column=4, columnspan=2, sticky="e")
        ttk.Label(f2, foreground="#666",
                  text="工作区是本工具管理的本地暂存目录(自动与远端对齐), "
                       "不要把自己未备份的文件放进去。"
                  ).grid(row=3, column=0, columnspan=6, sticky="w", padx=6)
        f2.columnconfigure(1, weight=1)

        # 待推送清单
        f3 = ttk.LabelFrame(self.root, text="3. 待推送文件/目录 (目标路径双击可改; "
                                           "模式双击切换 增量/镜像)")
        f3.pack(fill="both", expand=True, **pad)
        cols = ("src", "dest", "mode")
        self.tv = ttk.Treeview(f3, columns=cols, show="headings", height=8)
        self.tv.heading("src", text="本地源路径 (文件或目录)")
        self.tv.heading("dest", text="仓库内目标路径")
        self.tv.heading("mode", text="模式")
        self.tv.column("src", width=470, anchor="w")
        self.tv.column("dest", width=300, anchor="w")
        self.tv.column("mode", width=70, anchor="center")
        self.tv.grid(row=0, column=0, columnspan=7, sticky="nsew",
                     padx=(6, 0), pady=4)
        sb = ttk.Scrollbar(f3, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=sb.set)
        sb.grid(row=0, column=7, sticky="ns", pady=4)
        self.tv.bind("<Double-1>", self._tv_double_click)
        ttk.Button(f3, text="+ 添加目录", command=self._add_dir).grid(
            row=1, column=0, sticky="w", padx=6, pady=3)
        ttk.Button(f3, text="+ 添加文件", command=self._add_file).grid(
            row=1, column=1, sticky="w")
        ttk.Button(f3, text="删除选中", command=self._del_sel).grid(
            row=1, column=2, sticky="w")
        ttk.Button(f3, text="清空列表", command=lambda: self.tv.delete(
            *self.tv.get_children())).grid(row=1, column=3, sticky="w")
        ttk.Label(f3, foreground="#666",
                  text="增量=覆盖同名/保留其他文件; 镜像=先删除仓库内目标再复制"
                  ).grid(row=1, column=4, columnspan=3, sticky="e", padx=6)
        f3.columnconfigure(4, weight=1)
        f3.rowconfigure(0, weight=1)

        # 执行 + 日志
        f4 = ttk.Frame(self.root)
        f4.pack(fill="x", **pad)
        self.btn_run = ttk.Button(f4, text="★ 开始同步并推送",
                                  command=self._start)
        self.btn_run.pack(side="left", padx=6)
        ttk.Button(f4, text="清空日志",
                   command=lambda: self.logbox.configure(state="normal")
                   or self.logbox.delete("1.0", "end")
                   or self.logbox.configure(state="disabled")
                   ).pack(side="left")
        self.var_status = tk.StringVar(value="就绪")
        ttk.Label(f4, textvariable=self.var_status,
                  foreground="#1a5fb4").pack(side="right", padx=10)

        lf = ttk.LabelFrame(self.root, text="日志")
        lf.pack(fill="both", expand=True, **pad)
        self.logbox = tk.Text(lf, height=10, bg="#1e1e1e", fg="#d4d4d4",
                              insertbackground="#fff", state="disabled")
        self.logbox.tag_config("ok", foreground="#6abf69")
        self.logbox.tag_config("warn", foreground="#e0a32e")
        self.logbox.tag_config("err", foreground="#f48771")
        self.logbox.tag_config("dim", foreground="#9aa0a6")
        self.logbox.pack(side="left", fill="both", expand=True, padx=(6, 0),
                         pady=4)
        sb2 = ttk.Scrollbar(lf, orient="vertical",
                            command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=sb2.set)
        sb2.pack(side="right", fill="y", pady=4)

    # ---------- 清单操作 ----------
    def _add_paths(self, paths):
        existing = {self.tv.item(i)["values"][0]
                    for i in self.tv.get_children()}
        for p in paths:
            if p in existing:
                continue
            self.tv.insert("", "end",
                           values=(p, os.path.basename(os.path.normpath(p)),
                                   "增量"))

    def _add_dir(self):
        d = filedialog.askdirectory(title="选择要推送的目录")
        if d:
            self._add_paths([os.path.normpath(d)])

    def _add_file(self):
        fs = filedialog.askopenfilenames(title="选择要推送的文件(可多选)")
        rows = []
        for f in fs:
            f = os.path.normpath(f)
            # 多个文件默认放到仓库根目录(只保留文件名)
            rows.append((f, os.path.basename(f), "增量"))
        for v in rows:
            if not any(self.tv.item(i)["values"][0] == v[0]
                       for i in self.tv.get_children()):
                self.tv.insert("", "end", values=v)

    def _del_sel(self):
        self.tv.delete(*self.tv.selection())

    def _tv_double_click(self, event):
        row = self.tv.identify_row(event.y)
        col = self.tv.identify_column(event.x)
        if not row:
            return
        if col == "#3":
            vals = list(self.tv.item(row)["values"])
            vals[2] = "镜像" if vals[2] == "增量" else "增量"
            self.tv.item(row, values=vals)
            return
        if col != "#2":
            return
        x, y, w, h = self.tv.bbox(row, col)
        old = self.tv.item(row)["values"][1]
        top = self.tv.winfo_rootx() - self.tv.master.winfo_rootx() + x
        left = self.tv.winfo_rooty() - self.tv.master.winfo_rooty() + y
        ent = tk.Entry(self.tv)
        ent.place(x=top, y=left, width=w, height=h)
        ent.insert(0, old)
        ent.focus_set()
        ent.select_range(0, "end")

        def commit(_=None):
            new = ent.get().strip().replace("\\", "/").strip("/") or old
            vals = list(self.tv.item(row)["values"])
            vals[1] = new
            self.tv.item(row, values=vals)
            ent.destroy()
        ent.bind("<Return>", commit)
        ent.bind("<FocusOut>", commit)
        ent.bind("<Escape>", lambda e: ent.destroy())

    def _browse_ws(self):
        d = filedialog.askdirectory(title="选择暂存工作区目录")
        if d:
            self.var_ws.set(os.path.normpath(d))

    def _toggle_token(self):
        self.ent_token.configure(show="" if self.var_show.get() else "*")

    # ---------- 配置持久化(不含令牌) ----------
    def _load_config(self):
        for p in DEFAULT_SOURCES:
            if os.path.exists(p):
                self._add_paths([p])
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fp:
                cfg = json.load(fp)
            self.var_url.set(cfg.get("url", self.var_url.get()))
            self.var_branch.set(cfg.get("branch", self.var_branch.get()))
            self.var_user.set(cfg.get("user", ""))
            self.var_ws.set(cfg.get("ws", self.var_ws.get()))
            self.var_cname.set(cfg.get("cname", self.var_cname.get()))
            self.var_cmail.set(cfg.get("cmail", self.var_cmail.get()))
            self.var_msg.set(cfg.get("msg", self.var_msg.get()))
            self.tv.delete(*self.tv.get_children())
            for it in cfg.get("items", []):
                if len(it) >= 2 and os.path.exists(it[0]):
                    self.tv.insert("", "end",
                                   values=(it[0], it[1],
                                           it[2] if len(it) > 2 else "增量"))
        except (OSError, ValueError):
            pass

    def _save_config(self):
        try:
            cfg = {
                "url": self.var_url.get(), "branch": self.var_branch.get(),
                "user": self.var_user.get(), "ws": self.var_ws.get(),
                "cname": self.var_cname.get(), "cmail": self.var_cmail.get(),
                "msg": self.var_msg.get(),
                "items": [self.tv.item(i)["values"]
                          for i in self.tv.get_children()],
            }
            with open(CONFIG_PATH, "w", encoding="utf-8") as fp:
                json.dump(cfg, fp, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ---------- 日志/线程 ----------
    def log(self, msg, tag=None):
        self.q.put((str(msg), tag))

    def _poll(self):
        try:
            while True:
                msg, tag = self.q.get_nowait()
                if msg == "__DONE__":
                    self.running = False
                    self.btn_run.configure(state="normal")
                    self.var_status.set("成功完成" if tag == "ok"
                                        else "失败, 请看日志")
                    continue
                self.logbox.configure(state="normal")
                self.logbox.insert("end", msg + "\n", tag if tag else ())
                self.logbox.see("end")
                self.logbox.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _start(self):
        if self.running:
            return
        items = []
        for i in self.tv.get_children():
            src, dest, mode = self.tv.item(i)["values"]
            items.append((src, dest, mode))
        if not items:
            messagebox.showwarning("提示", "请先添加至少一个文件或目录")
            return
        if not self.var_url.get().strip():
            messagebox.showwarning("提示", "请填写远程仓库地址")
            return
        if not messagebox.askokcancel(
                "确认推送",
                f"将把 {len(items)} 个条目推送到:\n"
                f"{self.var_url.get()}  分支 {self.var_branch.get()}\n\n"
                "继续?"):
            return
        self.running = True
        self.btn_run.configure(state="disabled")
        self.var_status.set("正在推送...")
        t = threading.Thread(target=self._worker, args=(items,),
                             daemon=True)
        t.start()

    def _worker(self, items):
        ok = False
        try:
            p = GitPusher(self.var_url.get(), self.var_branch.get(),
                          self.var_user.get(), self.var_token.get(),
                          self.var_ws.get(), self.var_cname.get(),
                          self.var_cmail.get(), self.log)
            t0 = time.time()
            p.precheck()
            p.sync_workspace()
            p.copy_items(items, self.var_big.get())
            pushed = p.commit_and_push(self.var_msg.get())
            ok = True
            self.log(f"全部完成, 用时 {time.time()-t0:.1f}s。"
                     + ("" if pushed else "(本次无新提交)"), "ok")
            self.q.put(("__DONE__", "ok"))
        except PushError as e:
            self.log("✗ " + str(e), "err")
            self.q.put(("__DONE__", "err"))
        except Exception as e:  # noqa: BLE001
            self.log("✗ 意外错误: " + repr(e), "err")
            self.q.put(("__DONE__", "err"))
        finally:
            if ok:
                self._save_config()

def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()

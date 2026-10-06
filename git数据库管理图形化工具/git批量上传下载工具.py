# -*- coding: utf-8 -*-
"""
Git 批量上传下载管理工具
支持 GitHub / Gitee / GitLab 等平台的大量文件上传与下载
零第三方依赖，单文件 tkinter 实现
"""

import os
import sys
import re
import json
import shutil
import threading
import subprocess
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# ============================================================
#  Git 命令封装
# ============================================================
class GitRunner:
    """统一封装 git 命令调用，自动定位 git.exe，支持实时输出"""

    def __init__(self, log_callback=None):
        self.git_path = self._find_git()
        self.log = log_callback or (lambda msg: None)

    def _find_git(self):
        """定位 git 可执行文件"""
        # 1. 优先从 PATH 查找
        found = shutil.which("git")
        if found:
            return found
        # 2. 常见安装路径兜底
        candidates = [
            r"C:\Program Files\Git\cmd\git.exe",
            r"C:\Program Files (x86)\Git\cmd\git.exe",
            r"C:\Git\cmd\git.exe",
            os.path.expanduser(r"~\AppData\Local\Programs\Git\cmd\git.exe"),
        ]
        for p in candidates:
            if os.path.isfile(p):
                return p
        return None

    def available(self):
        return self.git_path is not None

    def run(self, args, cwd=None, env=None, stream=True):
        """
        执行 git 命令
        返回 (returncode, stdout, stderr)
        stream=True 时实时输出到日志
        """
        if not self.git_path:
            return 127, "", "git 未找到，请先安装 Git for Windows 或配置 PATH"

        cmd = [self.git_path] + args
        full_env = os.environ.copy()
        if env:
            full_env.update(env)

        # 中文输出编码处理
        full_env["LANG"] = "zh_CN.UTF-8"
        full_env["LC_ALL"] = "zh_CN.UTF-8"

        try:
            if stream:
                proc = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    env=full_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    universal_newlines=True,
                    encoding="utf-8",
                    errors="replace",
                )
                output_lines = []
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    output_lines.append(line)
                    self.log(line)
                proc.wait()
                return proc.returncode, "\n".join(output_lines), ""
            else:
                proc = subprocess.run(
                    cmd,
                    cwd=cwd,
                    env=full_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    encoding="utf-8",
                    errors="replace",
                )
                return proc.returncode, proc.stdout, proc.stderr
        except FileNotFoundError:
            return 127, "", f"git 可执行文件不存在: {self.git_path}"
        except Exception as e:
            return 1, "", str(e)


# ============================================================
#  凭据与远程 URL 处理
# ============================================================
def detect_platform(url):
    """根据 URL 识别平台"""
    u = url.lower()
    if "github.com" in u:
        return "GitHub"
    if "gitee.com" in u:
        return "Gitee"
    if "gitlab" in u:
        return "GitLab"
    if "gitcode" in u:
        return "GitCode"
    return "Git"


def sanitize_url_for_log(url):
    """脱敏 URL，移除其中的 token / 密码"""
    if not url:
        return url
    # 移除 https://user:token@host 中的凭据
    url = re.sub(r"(https?://)([^/@\s]+:[^/@\s]+@)", r"\1", url)
    return url


def build_auth_env(username, token):
    """
    构建认证环境变量，避免将 token 写入 remote URL
    利用 git 的 http.extraHeader 或 GIT_ASKPASS 机制
    这里使用更安全的方式：通过环境变量 + credential helper
    """
    env = {}
    if username and token:
        # 使用 git 的 credential.helper 方式
        # 通过设置 http.extraheader 携带 Basic Auth
        import base64
        auth_str = f"{username}:{token}"
        b64 = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
        env["GIT_HTTP_EXTRAHEADER"] = f"Authorization: Basic {b64}"
    return env


def mask_token(token):
    """脱敏显示 token"""
    if not token:
        return ""
    if len(token) <= 8:
        return "*" * len(token)
    return token[:4] + "*" * (len(token) - 8) + token[-4:]


# ============================================================
#  主应用
# ============================================================
class GitManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Git 批量上传下载管理工具  v1.0")
        self.root.geometry("960x680")
        self.root.minsize(860, 600)

        self.config_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "git_manager_config.json"
        )

        self.git = GitRunner(log_callback=self._log)

        self._build_ui()
        self._load_config()

        if not self.git.available():
            self._log("[警告] 未检测到 git，请先安装 Git for Windows")
            messagebox.showwarning(
                "未检测到 Git",
                "未在系统中找到 git.exe。\n"
                "请安装 Git for Windows 后重启本工具，\n"
                "或在「设置」中手动指定 git.exe 路径。",
            )
        else:
            self._log(f"[就绪] git 路径: {self.git.git_path}")

    # ---------------- UI 构建 ----------------
    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # 顶部：仓库信息
        top = ttk.LabelFrame(self.root, text="仓库信息", padding=8)
        top.pack(fill="x", padx=8, pady=6)

        row = 0
        ttk.Label(top, text="本地路径:").grid(row=row, column=0, sticky="w", padx=2, pady=3)
        self.var_local = tk.StringVar()
        ttk.Entry(top, textvariable=self.var_local, width=70).grid(row=row, column=1, sticky="ew", padx=2, pady=3)
        ttk.Button(top, text="浏览...", command=self._choose_dir).grid(row=row, column=2, padx=2, pady=3)
        ttk.Button(top, text="打开", command=self._open_local).grid(row=row, column=3, padx=2, pady=3)

        row = 1
        ttk.Label(top, text="远程仓库 URL:").grid(row=row, column=0, sticky="w", padx=2, pady=3)
        self.var_url = tk.StringVar()
        ttk.Entry(top, textvariable=self.var_url, width=70).grid(row=row, column=1, sticky="ew", padx=2, pady=3)
        self.lbl_platform = ttk.Label(top, text="", foreground="blue")
        self.lbl_platform.grid(row=row, column=2, columnspan=2, sticky="w", padx=2)
        self.var_url.trace_add("write", lambda *a: self._update_platform_label())

        row = 2
        ttk.Label(top, text="用户名:").grid(row=row, column=0, sticky="w", padx=2, pady=3)
        self.var_user = tk.StringVar()
        ttk.Entry(top, textvariable=self.var_user, width=30).grid(row=row, column=1, sticky="w", padx=2, pady=3)

        ttk.Label(top, text="Token/密码:").grid(row=row, column=2, sticky="e", padx=2, pady=3)
        self.var_token = tk.StringVar()
        tk.Entry(top, textvariable=self.var_token, width=30, show="*").grid(row=row, column=3, sticky="w", padx=2, pady=3)

        row = 3
        ttk.Label(top, text="分支:").grid(row=row, column=0, sticky="w", padx=2, pady=3)
        self.var_branch = tk.StringVar(value="main")
        ttk.Combobox(top, textvariable=self.var_branch, values=["main", "master"], width=15).grid(
            row=row, column=1, sticky="w", padx=2, pady=3
        )

        ttk.Label(top, text="提交信息:").grid(row=row, column=2, sticky="e", padx=2, pady=3)
        self.var_commit = tk.StringVar(value=f"update {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        ttk.Entry(top, textvariable=self.var_commit, width=35).grid(row=row, column=3, sticky="w", padx=2, pady=3)

        top.columnconfigure(1, weight=1)

        # 中部：操作按钮
        ops = ttk.LabelFrame(self.root, text="操作", padding=8)
        ops.pack(fill="x", padx=8, pady=4)

        btns = [
            ("初始化仓库", self.do_init),
            ("克隆仓库", self.do_clone),
            ("拉取更新", self.do_pull),
            ("查看状态", self.do_status),
            ("提交 (commit)", self.do_commit),
            ("推送 (push)", self.do_push),
            ("一键上传 (add+commit+push)", self.do_upload_all),
            ("查看日志", self.do_log),
            ("设置远程", self.do_remote_set),
        ]
        for i, (text, cmd) in enumerate(btns):
            b = ttk.Button(ops, text=text, command=cmd)
            b.grid(row=i // 3, column=i % 3, padx=4, pady=4, sticky="ew")
        for c in range(3):
            ops.columnconfigure(c, weight=1)

        # .gitignore 与设置行
        util = ttk.Frame(self.root)
        util.pack(fill="x", padx=8, pady=4)
        ttk.Button(util, text="编辑 .gitignore", command=self._edit_gitignore).pack(side="left", padx=2)
        ttk.Button(util, text="保存配置", command=self._save_config).pack(side="left", padx=2)
        ttk.Button(util, text="清空日志", command=self._clear_log).pack(side="left", padx=2)
        ttk.Button(util, text="设置 git.exe 路径", command=self._set_git_path).pack(side="right", padx=2)

        # 底部：日志
        log_frame = ttk.LabelFrame(self.root, text="运行日志", padding=4)
        log_frame.pack(fill="both", expand=True, padx=8, pady=6)

        self.txt_log = scrolledtext.ScrolledText(
            log_frame, wrap="word", height=18, font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4"
        )
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.configure(state="disabled")

        # 状态栏
        self.var_status = tk.StringVar(value="就绪")
        ttk.Label(self.root, textvariable=self.var_status, anchor="w").pack(fill="x", padx=8, pady=2)

    # ---------------- 日志 ----------------
    def _log(self, msg):
        def _append():
            self.txt_log.configure(state="normal")
            self.txt_log.insert("end", str(msg) + "\n")
            self.txt_log.see("end")
            self.txt_log.configure(state="disabled")
            self.var_status.set(str(msg)[:120])
        self.root.after(0, _append)

    def _clear_log(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    # ---------------- 工具方法 ----------------
    def _choose_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.var_local.set(d)
            self._auto_detect_remote(d)

    def _open_local(self):
        d = self.var_local.get().strip()
        if d and os.path.isdir(d):
            os.startfile(d)

    def _update_platform_label(self):
        url = self.var_url.get().strip()
        if url:
            self.lbl_platform.config(text=f"[{detect_platform(url)}]")
        else:
            self.lbl_platform.config(text="")

    def _auto_detect_remote(self, local):
        """尝试从本地 .git/config 读取远程 URL"""
        cfg = os.path.join(local, ".git", "config")
        if os.path.isfile(cfg):
            try:
                with open(cfg, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                m = re.search(r"url\s*=\s*(.+)", content)
                if m:
                    self.var_url.set(m.group(1).strip())
                    self._log(f"[自动检测] 远程仓库: {sanitize_url_for_log(m.group(1).strip())}")
                m = re.search(r"\[branch \"([^\"]+)\"\]", content)
                if m:
                    self.var_branch.set(m.group(1))
            except Exception:
                pass

    def _get_local(self):
        d = self.var_local.get().strip()
        if not d:
            messagebox.showwarning("提示", "请先选择本地路径")
            return None
        if not os.path.isdir(d):
            messagebox.showerror("错误", f"路径不存在: {d}")
            return None
        return d

    def _get_auth_env(self):
        user = self.var_user.get().strip()
        token = self.var_token.get().strip()
        return build_auth_env(user, token)

    def _run_async(self, func, *args):
        """在后台线程运行，避免界面卡死"""
        def wrapper():
            try:
                func(*args)
            except Exception as e:
                self._log(f"[异常] {e}")
        t = threading.Thread(target=wrapper, daemon=True)
        t.start()

    # ---------------- 核心操作 ----------------
    def do_init(self):
        local = self._get_local()
        if not local:
            return
        self._run_async(self._init, local)

    def _init(self, local):
        self._log(f"=== 初始化仓库: {local} ===")
        rc, out, err = self.git.run(["init"], cwd=local)
        if rc == 0:
            self._log("[成功] 仓库已初始化")
            # 设置默认分支
            branch = self.var_branch.get().strip() or "main"
            self.git.run(["checkout", "-b", branch], cwd=local)
            # 配置用户名邮箱（如未配置）
            self._ensure_git_identity(local)
        else:
            self._log(f"[失败] rc={rc}: {err or out}")

    def _ensure_git_identity(self, local):
        user = self.var_user.get().strip()
        rc, _, _ = self.git.run(["config", "user.name"], cwd=local, stream=False)
        if rc != 0 and user:
            self.git.run(["config", "user.name", user], cwd=local)
            self.git.run(["config", "user.email", f"{user}@users.noreply.github.com"], cwd=local)
            self._log(f"[配置] user.name = {user}")

    def do_clone(self):
        url = self.var_url.get().strip()
        if not url:
            messagebox.showwarning("提示", "请填写远程仓库 URL")
            return
        local = self.var_local.get().strip()
        if not local:
            messagebox.showwarning("提示", "请选择本地存放路径")
            return
        self._run_async(self._clone, url, local)

    def _clone(self, url, local):
        self._log(f"=== 克隆仓库 ===")
        self._log(f"远程: {sanitize_url_for_log(url)}")
        self._log(f"目标: {local}")
        env = self._get_auth_env()
        # 克隆到 local 下以仓库名命名的目录，或若 local 为空目录则直接克隆到 local
        target = local
        args = ["clone", "--progress", url]
        if os.path.isdir(local) and len(os.listdir(local)) == 0:
            args.append(".")
            target = local
        else:
            # 使用 URL 末段作为目录名
            name = url.rstrip("/").split("/")[-1]
            if name.endswith(".git"):
                name = name[:-4]
            target = os.path.join(local, name)
            self._log(f"将克隆到: {target}")
        rc, out, err = self.git.run(args, cwd=local if args[-1] == "." else local, env=env)
        if rc == 0:
            self._log("[成功] 克隆完成")
            if args[-1] != ".":
                self.var_local.set(target)
        else:
            self._log(f"[失败] rc={rc}: {err or out}")

    def do_pull(self):
        local = self._get_local()
        if not local:
            return
        self._run_async(self._pull, local)

    def _pull(self, local):
        self._log(f"=== 拉取更新: {local} ===")
        env = self._get_auth_env()
        branch = self.var_branch.get().strip()
        args = ["pull", "origin", branch] if branch else ["pull"]
        rc, out, err = self.git.run(args, cwd=local, env=env)
        if rc == 0:
            self._log("[成功] 已拉取最新代码")
        else:
            self._log(f"[失败] rc={rc}: {err or out}")

    def do_status(self):
        local = self._get_local()
        if not local:
            return
        self._run_async(self._status, local)

    def _status(self, local):
        self._log(f"=== 仓库状态: {local} ===")
        rc, out, err = self.git.run(["status", "--short"], cwd=local, stream=False)
        if rc == 0:
            lines = out.splitlines()
            self._log(f"变更文件数: {len(lines)}")
            for line in lines[:200]:
                self._log(line)
            if len(lines) > 200:
                self._log(f"... 还有 {len(lines) - 200} 个文件未显示")
        else:
            self._log(f"[失败] {err or out}")

    def do_commit(self):
        local = self._get_local()
        if not local:
            return
        msg = self.var_commit.get().strip()
        if not msg:
            messagebox.showwarning("提示", "请填写提交信息")
            return
        self._run_async(self._commit, local, msg)

    def _commit(self, local, msg):
        self._log(f"=== 提交 ===")
        self._ensure_git_identity(local)
        rc, out, err = self.git.run(["add", "-A"], cwd=local)
        if rc != 0:
            self._log(f"[add 失败] {err or out}")
            return
        self._log("[add] 已暂存所有变更")
        rc, out, err = self.git.run(["commit", "-m", msg], cwd=local)
        if rc == 0:
            self._log(f"[成功] 已提交: {msg}")
        elif "nothing to commit" in (out + err):
            self._log("[提示] 没有可提交的变更")
        else:
            self._log(f"[失败] rc={rc}: {err or out}")

    def do_push(self):
        local = self._get_local()
        if not local:
            return
        self._run_async(self._push, local)

    def _push(self, local):
        self._log(f"=== 推送 ===")
        env = self._get_auth_env()
        branch = self.var_branch.get().strip()
        args = ["push", "-u", "origin", branch] if branch else ["push"]
        rc, out, err = self.git.run(args, cwd=local, env=env)
        if rc == 0:
            self._log("[成功] 已推送到远程仓库")
        else:
            self._log(f"[失败] rc={rc}: {err or out}")

    def do_upload_all(self):
        """一键上传：add + commit + push，适合大量文件"""
        local = self._get_local()
        if not local:
            return
        url = self.var_url.get().strip()
        if not url:
            if not messagebox.askyesno("确认", "未填写远程 URL，仍要继续（仅提交不推送）？"):
                return
        msg = self.var_commit.get().strip()
        if not msg:
            messagebox.showwarning("提示", "请填写提交信息")
            return
        self._run_async(self._upload_all, local, msg, url)

    def _upload_all(self, local, msg, url):
        self._log("=" * 50)
        self._log("=== 一键上传（大量文件）===")
        self._log(f"路径: {local}")
        self._log(f"提交信息: {msg}")
        self._log("=" * 50)

        # 1. 确保是 git 仓库
        if not os.path.isdir(os.path.join(local, ".git")):
            self._log("[步骤 1/5] 初始化仓库...")
            rc, _, err = self.git.run(["init"], cwd=local)
            if rc != 0:
                self._log(f"[失败] init: {err}")
                return
            branch = self.var_branch.get().strip() or "main"
            self.git.run(["checkout", "-b", branch], cwd=local)

        # 2. 确保远程配置
        if url:
            self._log("[步骤 2/5] 配置远程仓库...")
            rc, _, _ = self.git.run(["remote", "get-url", "origin"], cwd=local, stream=False)
            if rc == 0:
                self.git.run(["remote", "set-url", "origin", url], cwd=local)
                self._log("[远程] 已更新 origin")
            else:
                self.git.run(["remote", "add", "origin", url], cwd=local)
                self._log("[远程] 已添加 origin")

        # 3. 身份配置
        self._ensure_git_identity(local)

        # 4. add + commit
        self._log("[步骤 3/5] 暂存文件 (git add -A)...")
        rc, out, err = self.git.run(["add", "-A"], cwd=local)
        if rc != 0:
            self._log(f"[失败] add: {err or out}")
            return
        self._log("[完成] 文件已暂存")

        self._log("[步骤 4/5] 提交...")
        rc, out, err = self.git.run(["commit", "-m", msg, "--allow-empty"], cwd=local)
        if rc != 0:
            if "nothing to commit" not in (out + err):
                self._log(f"[失败] commit: {err or out}")
                return
        self._log("[完成] 已提交")

        # 5. push
        if url:
            self._log("[步骤 5/5] 推送...")
            env = self._get_auth_env()
            branch = self.var_branch.get().strip() or "main"
            rc, out, err = self.git.run(["push", "-u", "origin", branch], cwd=local, env=env)
            if rc == 0:
                self._log("[成功] 推送完成！")
            else:
                self._log(f"[失败] push: {err or out}")
        else:
            self._log("[跳过] 未配置远程 URL，仅完成本地提交")

        self._log("=" * 50)

    def do_log(self):
        local = self._get_local()
        if not local:
            return
        self._run_async(self._log_git, local)

    def _log_git(self, local):
        self._log(f"=== 最近提交 ===")
        rc, out, err = self.git.run(
            ["log", "--oneline", "-15", "--graph", "--decorate"], cwd=local, stream=False
        )
        if rc == 0:
            for line in out.splitlines():
                self._log(line)
        else:
            self._log(f"[失败] {err or out}")

    def do_remote_set(self):
        local = self._get_local()
        if not local:
            return
        url = self.var_url.get().strip()
        if not url:
            messagebox.showwarning("提示", "请填写远程仓库 URL")
            return
        self._run_async(self._remote_set, local, url)

    def _remote_set(self, local, url):
        rc, _, _ = self.git.run(["remote", "get-url", "origin"], cwd=local, stream=False)
        if rc == 0:
            self.git.run(["remote", "set-url", "origin", url], cwd=local)
            self._log(f"[远程] 已更新 origin = {sanitize_url_for_log(url)}")
        else:
            self.git.run(["remote", "add", "origin", url], cwd=local)
            self._log(f"[远程] 已添加 origin = {sanitize_url_for_log(url)}")

    # ---------------- .gitignore ----------------
    def _edit_gitignore(self):
        local = self._get_local()
        if not local:
            return
        gi_path = os.path.join(local, ".gitignore")
        content = ""
        if os.path.isfile(gi_path):
            try:
                with open(gi_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                messagebox.showerror("错误", str(e))
                return

        win = tk.Toplevel(self.root)
        win.title(".gitignore 编辑")
        win.geometry("600x500")

        top = ttk.Frame(win)
        top.pack(fill="x", padx=6, pady=6)
        ttk.Label(top, text="常用模板:").pack(side="left")
        tpl = tk.StringVar(value="通用")
        combo = ttk.Combobox(top, textvariable=tpl, state="readonly", width=15,
                             values=["通用", "Python", "Node.js", "Java", "C/C++", "C#", "IDE", "空"])
        combo.pack(side="left", padx=4)
        ttk.Button(top, text="应用模板", command=lambda: self._apply_template(txt, tpl.get())).pack(side="left")

        txt = scrolledtext.ScrolledText(win, wrap="none", font=("Consolas", 10))
        txt.pack(fill="both", expand=True, padx=6, pady=4)
        txt.insert("1.0", content)

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=6, pady=6)
        ttk.Button(btns, text="保存", command=lambda: self._save_gitignore(gi_path, txt, win)).pack(side="right", padx=4)
        ttk.Button(btns, text="取消", command=win.destroy).pack(side="right")

    def _apply_template(self, txt, name):
        templates = {
            "通用": "# OS\n.DS_Store\nThumbs.db\ndesktop.ini\n\n# 日志\n*.log\nlogs/\n\n# 临时\n*.tmp\n*.temp\n*.swp\n*~\n\n# 压缩\n*.zip\n*.rar\n*.7z\n*.tar.gz\n",
            "Python": "__pycache__/\n*.py[cod]\n*$py.class\n*.so\n.Python\nbuild/\ndevelop-eggs/\ndist/\ndownloads/\neggs/\n.eggs/\nlib/\nlib64/\nparts/\nsdist/\nvar/\nwheels/\n*.egg-info/\n.installed.cfg\n*.egg\n.venv/\nvenv/\nenv/\nENV/\n.idea/\n.vscode/\n*.pyc\n",
            "Node.js": "node_modules/\nnpm-debug.log*\nyarn-debug.log*\nyarn-error.log*\n.DS_Store\n.env\n.env.local\ndist/\nbuild/\n*.log\n.idea/\n.vscode/\n",
            "Java": "*.class\n*.jar\n*.war\n*.ear\n*.log\ntarget/\nbuild/\n.idea/\n*.iml\n.vscode/\n.project\n.classpath\n.settings/\n",
            "C/C++": "*.o\n*.obj\n*.exe\n*.out\n*.a\n*.lib\n*.dll\n*.so\n*.dylib\n*.log\nbuild/\n.vs/\n.vscode/\n.idea/\nCMakeCache.txt\nCMakeFiles/\n",
            "C#": "bin/\nobj/\n*.user\n*.suo\n*.userosscache\n*.sln.docstates\n*.userprefs\n*.log\n.vs/\npackages/\n",
            "IDE": ".idea/\n.vscode/\n*.swp\n*.swo\n*~\n.project\n.classpath\n.settings/\n.vs/\n",
            "空": "",
        }
        txt.delete("1.0", "end")
        txt.insert("1.0", templates.get(name, ""))

    def _save_gitignore(self, path, txt, win):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt.get("1.0", "end-1c"))
            self._log(f"[保存] {path}")
            win.destroy()
        except Exception as e:
            messagebox.showerror("错误", str(e))

    # ---------------- 设置 ----------------
    def _set_git_path(self):
        p = filedialog.askopenfilename(
            title="选择 git.exe",
            filetypes=[("git.exe", "git.exe"), ("可执行文件", "*.exe")],
        )
        if p:
            self.git.git_path = p
            self._log(f"[设置] git 路径: {p}")
            rc, out, _ = self.git.run(["--version"], stream=False)
            if rc == 0:
                self._log(f"[验证] {out.strip()}")
            else:
                messagebox.showerror("错误", "该文件不是有效的 git")

    # ---------------- 配置持久化 ----------------
    def _save_config(self):
        cfg = {
            "local": self.var_local.get(),
            "url": self.var_url.get(),
            "user": self.var_user.get(),
            "branch": self.var_branch.get(),
            "git_path": self.git.git_path or "",
        }
        # token 不强制保存，提示用户
        token = self.var_token.get()
        if token:
            if messagebox.askyesno("保存 Token？", "Token 是敏感信息，明文保存在配置文件中有风险。\n是否仍要保存？"):
                cfg["token"] = token
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            self._log(f"[配置] 已保存到 {self.config_file}")
            messagebox.showinfo("成功", "配置已保存")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _load_config(self):
        if not os.path.isfile(self.config_file):
            return
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            self.var_local.set(cfg.get("local", ""))
            self.var_url.set(cfg.get("url", ""))
            self.var_user.set(cfg.get("user", ""))
            self.var_branch.set(cfg.get("branch", "main"))
            if cfg.get("token"):
                self.var_token.set(cfg["token"])
            gp = cfg.get("git_path")
            if gp and os.path.isfile(gp):
                self.git.git_path = gp
            self._update_platform_label()
        except Exception:
            pass


def main():
    root = tk.Tk()
    GitManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

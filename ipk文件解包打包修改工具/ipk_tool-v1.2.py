#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ipk 解包/打包 图形化工具 V1.2（纯 Python tkinter，零第三方依赖，单文件）

V1.2 新增：
  - 右键菜单增加“打开包内文件”：提取到临时目录后用系统默认程序打开查看
    （只读，不回写包内；支持图片/PDF 等任意类型，可多选批量打开）

V1.1 修复：
  - 修复内置文本编辑器只显示窗口、文本区空白且无法编辑的问题
    （同一 Toplevel 内 pack/grid 混用导致 Text 控件未映射，现统一分层布局）
  - 编辑器打开后自动聚焦，可直接输入；Ctrl+S 全局可触发保存

功能：
  1. 解包 ipk 到目录（control/ + data/ + debian-binary）
  2. 从目录打包为 ipk
  3. 替换包内文件（保留原成员权限等元数据）
  4. 双击直接编辑包内文本文件并保存自动写回；二进制文件可用系统编辑器打开（自动监视回写）
  5. 不解包直接编辑 control：版本号、依赖增删、架构自定义（一键改 all）
  6. 批量文本替换（全部文件 / 仅选中文件）
  7. 文件列表过滤框 + 鼠标中键拖动滚动 / 滚轮滚动
  8. 右键“打开包内文件”：系统默认程序只读查看（支持多选）
"""

import io
import os
import re
import sys
import time
import tarfile
import tempfile
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

GNU_FORMAT = tarfile.GNU_FORMAT
APP_VERSION = "V1.2"


# ==================== 核心逻辑（与 GUI 解耦，便于自动化测试） ====================

def display_path(name):
    """tar 成员名归一为显示路径（去掉 ./ 前缀）"""
    return name[2:] if name.startswith("./") else name


def parse_control(text):
    """解析 control 文本为 [[key, value], ...]，Description 续行并入 value"""
    fields = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[:1] in (" ", "\t") and fields:
            fields[-1][1] += "\n" + line.strip()
        elif ":" in line:
            k, _, v = line.partition(":")
            fields.append([k.strip(), v.strip()])
    return fields


def serialize_control(fields):
    out = []
    for k, v in fields:
        if "\n" in v:
            lines = v.split("\n")
            out.append("%s: %s\n" % (k, lines[0]))
            for extra in lines[1:]:
                out.append(" %s\n" % extra)
        else:
            out.append("%s: %s\n" % (k, v))
    return "".join(out)


def is_text(data):
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def fmt_size(n):
    if n >= 1024 * 1024:
        return "%.1f MB" % (n / 1024 / 1024)
    if n >= 1024:
        return "%.1f KB" % (n / 1024)
    return "%d B" % n


def default_mode(relpath, isdir=False):
    """从目录打包时按 OpenWrt 惯例设置权限"""
    if isdir:
        return 0o755
    p = relpath.lower()
    if p.endswith(".sh"):
        return 0o755
    for pre in ("etc/init.d/", "etc/hotplug.d/", "etc/uci-defaults/", "usr/libexec/rpcd/"):
        if p.startswith(pre):
            return 0o755
    return 0o644


def bulk_replace(members, indices, find, repl, ignorecase=False):
    """对成员列表执行批量文本替换，返回 (替换的文件数, 替换次数)"""
    flags = re.IGNORECASE if ignorecase else 0
    pat = re.compile(re.escape(find), flags)
    n_files = n_total = 0
    for i in indices:
        m, d = members[i]
        if not m.isfile() or not is_text(d):
            continue
        text = d.decode("utf-8")
        new, n = pat.subn(repl, text)
        if n:
            newb = new.encode("utf-8")
            m.size = len(newb)
            m.mtime = int(time.time())
            members[i][1] = newb
            n_files += 1
            n_total += n
    return n_files, n_total


class IpkArchive:
    """内存中的 ipk：debian-binary + control.tar.gz 成员集 + data.tar.gz 成员集"""

    def __init__(self):
        self.loaded = False
        self.source_path = None
        self.debian = b"2.0\n"
        self.outer_prefix = "./"
        self.control_members = []  # [[TarInfo, bytes], ...]
        self.data_members = []

    # ---------- 读取 ----------
    def load(self, path):
        with tarfile.open(path, "r:gz") as tf:
            entries = []
            for m in tf.getmembers():
                data = tf.extractfile(m).read() if m.isfile() else b""
                entries.append((m.name, data))
        for name, data in entries:
            base = display_path(name).lower()
            if "debian-binary" in base:
                self.debian = data
                self.outer_prefix = "./" if name.startswith("./") else ""
            elif "control.tar" in base:
                self.control_members = self._read_inner(data)
            elif "data.tar" in base:
                self.data_members = self._read_inner(data)
        self.source_path = path
        self.loaded = True

    @staticmethod
    def _read_inner(blob):
        out = []
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for m in tf.getmembers():
                data = tf.extractfile(m).read() if m.isfile() else b""
                out.append([m, data])
        return out

    @staticmethod
    def _build_inner(members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", format=GNU_FORMAT) as tf:
            for m, d in members:
                if m.isfile():
                    m.size = len(d)
                    tf.addfile(m, io.BytesIO(d))
                else:
                    tf.addfile(m)
        return buf.getvalue()

    # ---------- 构建/保存 ----------
    def build(self):
        control_tar = self._build_inner(self.control_members)
        data_tar = self._build_inner(self.data_members)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", format=GNU_FORMAT) as tf:
            for name, blob in (("debian-binary", self.debian),
                               ("data.tar.gz", data_tar),
                               ("control.tar.gz", control_tar)):
                ti = tarfile.TarInfo(self.outer_prefix + name)
                ti.size = len(blob)
                ti.mode = 0o644
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mtime = int(time.time())
                tf.addfile(ti, io.BytesIO(blob))
        return buf.getvalue()

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.build())

    # ---------- control ----------
    def control_file_index(self):
        for i, (m, d) in enumerate(self.control_members):
            if display_path(m.name).lower() == "control":
                return i
        return -1

    def get_fields(self):
        i = self.control_file_index()
        if i < 0:
            return []
        return parse_control(self.control_members[i][1].decode("utf-8", "replace"))

    def get_field(self, key, default=""):
        for k, v in self.get_fields():
            if k.lower() == key.lower():
                return v
        return default

    def set_field(self, key, value):
        i = self.control_file_index()
        if i < 0:
            raise RuntimeError("包内未找到 control 文件")
        fields = self.get_fields()
        for f in fields:
            if f[0].lower() == key.lower():
                if value == "":
                    fields.remove(f)
                else:
                    f[1] = value
                break
        else:
            if value != "":
                fields.append([key, value])
        self.control_members[i][1] = serialize_control(fields).encode("utf-8")

    # ---------- data 文件操作 ----------
    def find_data(self, path):
        for i, (m, d) in enumerate(self.data_members):
            if display_path(m.name) == path and m.isfile():
                return i
        return -1

    def replace_file(self, path, data):
        i = self.find_data(path)
        if i < 0:
            raise RuntimeError("包内未找到文件: %s" % path)
        m = self.data_members[i][0]
        m.size = len(data)
        m.mtime = int(time.time())
        self.data_members[i][1] = data

    def delete_file(self, path):
        i = self.find_data(path)
        if i >= 0:
            return self.data_members.pop(i)
        return None

    def get_data(self, path):
        i = self.find_data(path)
        return self.data_members[i][1] if i >= 0 else None

    # ---------- 解包 ----------
    def unpack(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "debian-binary"), "wb") as f:
            f.write(self.debian)
        _write_members(self.control_members, os.path.join(outdir, "control"))
        _write_members(self.data_members, os.path.join(outdir, "data"))


def _write_members(members, outdir):
    os.makedirs(outdir, exist_ok=True)
    for m, d in members:
        rel = display_path(m.name)
        if not rel or rel == ".":
            continue
        p = os.path.join(outdir, rel.replace("/", os.sep))
        if m.isdir():
            os.makedirs(p, exist_ok=True)
        elif m.issym() or m.islnk():
            # Windows 下符号链接降级：写入目标说明文件
            with open(p + ".symlink.txt", "w", encoding="utf-8") as f:
                f.write("symlink -> " + (m.linkname or ""))
        elif m.isfile():
            os.makedirs(os.path.dirname(p) or outdir, exist_ok=True)
            with open(p, "wb") as f:
                f.write(d)
            try:
                os.chmod(p, m.mode & 0o777)
            except OSError:
                pass


def read_dir_members(basedir):
    """目录 → tar 成员列表（./ 前缀，root 条目在最前）"""
    out = []
    if not os.path.isdir(basedir):
        return out
    root_ti = tarfile.TarInfo("./")
    root_ti.type = tarfile.DIRTYPE
    root_ti.mode = 0o755
    root_ti.uid = root_ti.gid = 0
    root_ti.uname = root_ti.gname = ""
    root_ti.mtime = int(time.time())
    out.append([root_ti, b""])
    for root, dirs, files in os.walk(basedir):
        rel = os.path.relpath(root, basedir).replace("\\", "/")
        rel = "" if rel == "." else rel
        for dd in sorted(dirs):
            ti = tarfile.TarInfo("./" + (rel + "/" if rel else "") + dd + "/")
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mtime = int(os.stat(os.path.join(root, dd)).st_mtime)
            out.append([ti, b""])
        for f in sorted(files):
            p = os.path.join(root, f)
            arc = "./" + (rel + "/" if rel else "") + f
            ti = tarfile.TarInfo(arc)
            ti.size = os.path.getsize(p)
            ti.mode = default_mode(display_path(arc))
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mtime = int(os.stat(p).st_mtime)
            with open(p, "rb") as fp:
                out.append([ti, fp.read()])
    return out


def pack_from_dir(rootdir):
    """从 解包目录（control/ + data/ + 可选 debian-binary）构建 IpkArchive"""
    a = IpkArchive()
    a.outer_prefix = "./"
    db = os.path.join(rootdir, "debian-binary")
    if os.path.isfile(db):
        with open(db, "rb") as f:
            a.debian = f.read()
    a.control_members = read_dir_members(os.path.join(rootdir, "control"))
    a.data_members = read_dir_members(os.path.join(rootdir, "data"))
    a.loaded = True
    a.source_path = rootdir
    return a


# ==================== 内置文本编辑器 ====================

class EditorWindow(tk.Toplevel):
    def __init__(self, master, path, text, on_save):
        super().__init__(master)
        self.title("编辑(包内) - %s" % path)
        self.geometry("860x600")
        self.on_save = on_save
        # 按钮栏（Toplevel 内统一使用 pack，禁止与 grid 混用同一父容器）
        bar = ttk.Frame(self)
        bar.pack(side="top", fill="x")
        ttk.Button(bar, text="保存并写回包内 (Ctrl+S)", command=self.do_save).pack(side="left", padx=4, pady=4)
        ttk.Label(bar, text="utf-8").pack(side="right", padx=6)
        # 文本区整体放入 body 框架：Toplevel pack body，body 内部才使用 grid
        body = ttk.Frame(self)
        body.pack(side="top", fill="both", expand=True)
        self.text = tk.Text(body, wrap="none", undo=True,
                            font=("Consolas", 10))
        ysb = ttk.Scrollbar(body, orient="vertical", command=self.text.yview)
        xsb = ttk.Scrollbar(body, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.text.insert("1.0", text)
        self.text.edit_reset()
        self.text.focus_set()
        self.text.bind("<Control-s>", lambda e: self.do_save())
        self.bind("<Control-s>", lambda e: self.do_save())

    def do_save(self):
        data = self.text.get("1.0", "end-1c").encode("utf-8")
        self.on_save(data)
        messagebox.showinfo("已保存", "修改已写回包内数据（需保存 ipk 后落盘）", parent=self)
        return "break"


# ==================== 外部编辑器监视窗口 ====================

class ExternalEditWindow(tk.Toplevel):
    """用系统默认程序打开临时副本，轮询检测保存并自动写回包内"""

    def __init__(self, master, path, data, on_change):
        super().__init__(master)
        self.title("外部编辑器监视 - %s" % os.path.basename(path))
        self.geometry("460x150")
        self.on_change = on_change
        self.tmppath = os.path.join(tempfile.gettempdir(), "ipk_edit_" + os.path.basename(path))
        self._stopped = False
        self._count = 0
        with open(self.tmppath, "wb") as f:
            f.write(data)
        st = os.stat(self.tmppath)
        self._key = (st.st_mtime, st.st_size)
        ttk.Label(self, text="文件: %s" % path, wraplength=440).pack(anchor="w", padx=8, pady=(8, 2))
        self.lbl = ttk.Label(self, text="监视中…在系统编辑器中修改并保存后自动写回包内", foreground="#0a7")
        self.lbl.pack(anchor="w", padx=8)
        ttk.Button(self, text="停止监视并关闭", command=self.close).pack(pady=8)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self._open_external()
        self.after(700, self._poll)

    def _open_external(self):
        try:
            if sys.platform == "win32":
                os.startfile(self.tmppath)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.tmppath])
            else:
                subprocess.Popen(["xdg-open", self.tmppath])
        except OSError as e:
            messagebox.showerror("错误", "无法打开系统编辑器: %s" % e, parent=self)

    def _poll(self):
        if self._stopped:
            return
        try:
            st = os.stat(self.tmppath)
            key = (st.st_mtime, st.st_size)
            if key != self._key:
                self._key = key
                with open(self.tmppath, "rb") as f:
                    data = f.read()
                self.on_change(data)
                self._count += 1
                self.lbl.config(text="已捕获 %d 次修改并自动写回包内" % self._count)
        except OSError:
            pass
        self.after(700, self._poll)

    def close(self):
        self._stopped = True
        try:
            os.remove(self.tmppath)
        except OSError:
            pass
        self.destroy()


# ==================== 批量替换对话框 ====================

class BatchReplaceWindow(tk.Toplevel):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.title("批量文本替换（包内文件）")
        self.geometry("440x260")
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="查找:").grid(row=0, column=0, sticky="w", pady=3)
        self.e_find = ttk.Entry(frm, width=36)
        self.e_find.grid(row=0, column=1, pady=3)
        ttk.Label(frm, text="替换为:").grid(row=1, column=0, sticky="w", pady=3)
        self.e_repl = ttk.Entry(frm, width=36)
        self.e_repl.grid(row=1, column=1, pady=3)
        self.scope = tk.StringVar(value="all")
        ttk.Radiobutton(frm, text="全部文本文件", variable=self.scope, value="all").grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(frm, text="仅列表中选中的文件", variable=self.scope, value="sel").grid(row=3, column=0, columnspan=2, sticky="w")
        self.case = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="忽略大小写", variable=self.case).grid(row=4, column=0, columnspan=2, sticky="w")
        ttk.Button(frm, text="执行替换", command=self.run).grid(row=5, column=0, columnspan=2, pady=10)
        self.e_find.focus_set()

    def run(self):
        find = self.e_find.get()
        if not find:
            messagebox.showwarning("提示", "请输入查找内容", parent=self)
            return
        if self.scope.get() == "sel":
            iids = self.app.tree.selection()
            if not iids:
                messagebox.showwarning("提示", "请先在文件列表中选中文件", parent=self)
                return
            indices = [int(i) for i in iids]
        else:
            indices = list(range(len(self.app.arc.data_members)))
        if not messagebox.askyesno("确认", "将对 %d 个条目执行批量替换，是否继续？" % len(indices), parent=self):
            return
        n_files, n_total = bulk_replace(self.app.arc.data_members, indices,
                                        find, self.e_repl.get(), self.case.get())
        self.app.mark_dirty()
        self.app.refresh_tree()
        messagebox.showinfo("完成", "替换了 %d 个文件中的 %d 处" % (n_files, n_total), parent=self)


# ==================== 主窗口 ====================

ARCH_LIST = ["all", "x86_64", "i386", "aarch64_generic", "arm_cortex-a7_neon-vfpv4",
             "arm_cortex-a9", "arm_cortex-a15_neon-vfpv4", "mips_24kc", "mipsel_24kc",
             "mips64_24kc", "mips64_mips64r2", "powerpc_8540", "riscv64", "loongarch64"]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ipk 解包打包工具 %s" % APP_VERSION)
        self.geometry("1000x680")
        self.arc = IpkArchive()
        self.dirty = False
        self._mid_y = None
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
            self.load_ipk(sys.argv[1])

    # ---------- UI ----------
    def _build_ui(self):
        bar = ttk.Frame(self, padding=4)
        bar.pack(fill="x")
        for text, cmd in (("打开 ipk", self.open_ipk),
                          ("解包到目录…", self.unpack_to),
                          ("从目录打包 ipk…", self.pack_from),
                          ("保存 ipk", self.save_ipk),
                          ("另存为…", self.save_as),
                          ("批量替换", lambda: BatchReplaceWindow(self, self))):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=3)
        ttk.Label(bar, text=APP_VERSION, foreground="#888").pack(side="right", padx=6)

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True)

        # --- control 区 ---
        cf = ttk.Labelframe(paned, text="包信息（control，可直接编辑，保存时写回）", padding=6)
        paned.add(cf, weight=1)
        left = ttk.Frame(cf)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        right = ttk.Frame(cf)
        right.grid(row=0, column=1, sticky="nsew")
        cf.columnconfigure(0, weight=1)
        cf.columnconfigure(1, weight=1)
        cf.rowconfigure(0, weight=1)

        self.var_pkg = tk.StringVar()
        self.var_ver = tk.StringVar()
        self.var_arch = tk.StringVar()
        self.var_maint = tk.StringVar()
        self.var_desc = tk.StringVar()
        rows = [("Package 包名", self.var_pkg, None),
                ("Version 版本号", self.var_ver, None),
                ("Architecture 架构", self.var_arch, "arch"),
                ("Maintainer 维护者", self.var_maint, None),
                ("Description 描述", self.var_desc, None)]
        for i, (lab, var, extra) in enumerate(rows):
            ttk.Label(left, text=lab).grid(row=i, column=0, sticky="w", pady=2)
            if extra == "arch":
                combo = ttk.Combobox(left, textvariable=var, values=ARCH_LIST, width=28)
                combo.grid(row=i, column=1, sticky="we", pady=2)
                ttk.Button(left, text="一键改为 all", command=lambda: self.var_arch.set("all")).grid(row=i, column=2, padx=4)
            else:
                e = ttk.Entry(left, textvariable=var)
                e.grid(row=i, column=1, columnspan=2, sticky="we", pady=2)
                e.bind("<KeyRelease>", lambda e: self.mark_dirty())
        left.columnconfigure(1, weight=1)

        ttk.Label(right, text="Depends 依赖（增删后保存时写回）").grid(row=0, column=0, sticky="w")
        self.dep_list = tk.Listbox(right, height=5, exportselection=False)
        self.dep_list.grid(row=1, column=0, rowspan=3, sticky="nsew", pady=2)
        self.e_dep = ttk.Entry(right)
        self.e_dep.grid(row=1, column=1, sticky="we", padx=4)
        ttk.Button(right, text="添加", width=8, command=self.dep_add).grid(row=2, column=1, sticky="we", padx=4, pady=2)
        ttk.Button(right, text="删除选中", width=8, command=self.dep_del).grid(row=3, column=1, sticky="we", padx=4)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        # --- 文件区 ---
        ff = ttk.Labelframe(paned, text="包内文件（data.tar.gz）— 双击编辑文本文件；右键更多操作", padding=4)
        paned.add(ff, weight=3)
        ftop = ttk.Frame(ff)
        ftop.pack(fill="x")
        ttk.Label(ftop, text="过滤:").pack(side="left")
        self.var_filter = tk.StringVar()
        self.var_filter.trace_add("write", lambda *a: self.refresh_tree())
        ttk.Entry(ftop, textvariable=self.var_filter, width=40).pack(side="left", padx=4)
        self.lbl_count = ttk.Label(ftop, text="")
        self.lbl_count.pack(side="left", padx=8)

        cols = ("path", "size", "mode")
        self.tree = ttk.Treeview(ff, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("path", text="路径（不含 ./ 前缀）")
        self.tree.heading("size", text="大小")
        self.tree.heading("mode", text="权限")
        self.tree.column("path", width=620)
        self.tree.column("size", width=90, anchor="e")
        self.tree.column("mode", width=70, anchor="center")
        ysb = ttk.Scrollbar(ff, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="left", fill="y")

        # 中键拖动滚动 + 滚轮
        self.tree.bind("<Button-2>", self._mid_press)
        self.tree.bind("<B2-Motion>", self._mid_drag)
        self.tree.bind("<MouseWheel>", self._wheel)
        self.tree.bind("<Button-4>", lambda e: self.tree.yview_scroll(-2, "units"))
        self.tree.bind("<Button-5>", lambda e: self.tree.yview_scroll(2, "units"))
        self.tree.bind("<Double-1>", lambda e: self.edit_selected())
        self.tree.bind("<Button-3>", self._popup_menu)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="编辑文本文件（内置编辑器）", command=self.edit_selected)
        self.menu.add_command(label="打开包内文件（系统默认程序，只读查看）", command=self.open_in_system)
        self.menu.add_command(label="用系统编辑器打开（保存自动回写）", command=self.external_edit)
        self.menu.add_command(label="替换此文件…", command=self.replace_selected)
        self.menu.add_command(label="导出…", command=self.export_selected)
        self.menu.add_separator()
        self.menu.add_command(label="删除选中", command=self.delete_selected)
        self.menu.add_separator()
        self.menu.add_command(label="批量文本替换…", command=lambda: BatchReplaceWindow(self, self))

        # --- 状态栏 ---
        self.status = ttk.Label(self, text="请打开一个 ipk 文件", anchor="w", padding=(6, 2),
                                relief="sunken")
        self.status.pack(fill="x", side="bottom")

    # ---------- 中键/滚轮 ----------
    def _mid_press(self, e):
        self._mid_y = e.y
        return "break"

    def _mid_drag(self, e):
        if self._mid_y is None:
            return
        delta = e.y - self._mid_y
        if delta:
            self.tree.yview_scroll(-delta // 3, "units")
            self._mid_y = e.y
        return "break"

    def _wheel(self, e):
        self.tree.yview_scroll(-(e.delta // 120), "units")
        return "break"

    def _popup_menu(self, e):
        iid = self.tree.identify_row(e.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        self.menu.tk_popup(e.x_root, e.y_root)

    # ---------- 状态 ----------
    def log(self, msg):
        self.status.config(text=("● " if self.dirty else "") + msg)

    def mark_dirty(self):
        if not self.dirty:
            self.dirty = True
        self.log("有未保存的修改")

    # ---------- 打开/解包/打包/保存 ----------
    def open_ipk(self):
        p = filedialog.askopenfilename(title="选择 ipk 文件",
                                       filetypes=[("ipk 包", "*.ipk"), ("所有文件", "*.*")])
        if p:
            self.load_ipk(p)

    def load_ipk(self, p):
        try:
            self.arc = IpkArchive()
            self.arc.load(p)
        except Exception as e:
            messagebox.showerror("错误", "打开失败:\n%s" % e)
            return
        self.dirty = False
        self.fill_control()
        self.refresh_tree()
        self.log("已打开: %s（%d 个文件）" % (p, len(self.arc.data_members)))

    def fill_control(self):
        self.var_pkg.set(self.arc.get_field("Package"))
        self.var_ver.set(self.arc.get_field("Version"))
        self.var_arch.set(self.arc.get_field("Architecture"))
        self.var_maint.set(self.arc.get_field("Maintainer"))
        self.var_desc.set(self.arc.get_field("Description"))
        self.dep_list.delete(0, "end")
        for dep in self.arc.get_field("Depends").split(","):
            dep = dep.strip()
            if dep:
                self.dep_list.insert("end", dep)

    def collect_gui(self):
        self.arc.set_field("Package", self.var_pkg.get().strip())
        self.arc.set_field("Version", self.var_ver.get().strip())
        self.arc.set_field("Architecture", self.var_arch.get().strip())
        self.arc.set_field("Maintainer", self.var_maint.get().strip())
        self.arc.set_field("Description", self.var_desc.get().strip())
        deps = ", ".join(self.dep_list.get(0, "end"))
        self.arc.set_field("Depends", deps)

    def unpack_to(self):
        if not self.arc.loaded:
            messagebox.showwarning("提示", "请先打开 ipk")
            return
        d = filedialog.askdirectory(title="选择解包输出目录")
        if not d:
            return
        try:
            self.arc.unpack(d)
            self.log("已解包到: %s" % d)
            messagebox.showinfo("完成", "已解包到:\n%s\n（control/ + data/ + debian-binary）" % d)
        except Exception as e:
            messagebox.showerror("错误", "解包失败:\n%s" % e)

    def pack_from(self):
        d = filedialog.askdirectory(title="选择解包目录（内含 control/ 与 data/）")
        if not d:
            return
        if not (os.path.isdir(os.path.join(d, "data")) and os.path.isdir(os.path.join(d, "control"))):
            messagebox.showerror("错误", "所选目录下必须包含 control/ 与 data/ 子目录")
            return
        try:
            self.arc = pack_from_dir(d)
        except Exception as e:
            messagebox.showerror("错误", "打包失败:\n%s" % e)
            return
        self.dirty = True
        self.fill_control()
        self.refresh_tree()
        self.log("已从目录构建 ipk 数据: %s（请保存 ipk 落盘）" % d)

    def save_ipk(self):
        if not self.arc.loaded:
            messagebox.showwarning("提示", "请先打开或从目录构建 ipk")
            return
        self.collect_gui()
        if self.arc.source_path and self.arc.source_path.lower().endswith(".ipk"):
            if not messagebox.askyesno("确认", "覆盖保存到:\n%s ?" % self.arc.source_path):
                return
            out = self.arc.source_path
        else:
            out = self.save_as()
            if not out:
                return
        try:
            self.arc.save(out)
        except Exception as e:
            messagebox.showerror("错误", "保存失败:\n%s" % e)
            return
        self.dirty = False
        self.log("已保存: %s" % out)

    def save_as(self):
        self.collect_gui()
        name = "package.ipk"
        if self.var_pkg.get().strip():
            name = "%s_%s_%s.ipk" % (self.var_pkg.get().strip(),
                                     self.var_ver.get().strip() or "1.0",
                                     self.var_arch.get().strip() or "all")
        p = filedialog.asksaveasfilename(title="另存 ipk", defaultextension=".ipk",
                                         initialfile=name,
                                         filetypes=[("ipk 包", "*.ipk")])
        if not p:
            return None
        try:
            self.arc.save(p)
        except Exception as e:
            messagebox.showerror("错误", "保存失败:\n%s" % e)
            return None
        self.arc.source_path = p
        self.dirty = False
        self.log("已另存: %s" % p)
        return p

    # ---------- 文件列表 ----------
    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        flt = self.var_filter.get().lower()
        n_show = 0
        for i, (m, d) in enumerate(self.arc.data_members):
            disp = display_path(m.name)
            if flt and flt not in disp.lower():
                continue
            if m.isdir():
                size, mode = "", "dir"
            elif m.issym() or m.islnk():
                size, mode = "", "link"
            else:
                size, mode = fmt_size(len(d)), "%o" % (m.mode & 0o7777)
            self.tree.insert("", "end", iid=str(i), values=(disp, size, mode))
            n_show += 1
        total = len(self.arc.data_members)
        self.lbl_count.config(text="显示 %d / %d 项" % (n_show, total))

    def _selected_paths(self):
        return [display_path(self.arc.data_members[int(i)][0].name) for i in self.tree.selection()]

    # ---------- 文件操作 ----------
    def edit_selected(self):
        sel = self.tree.selection()
        if len(sel) != 1:
            messagebox.showwarning("提示", "请先选中一个文件（双击编辑）")
            return
        path = self._selected_paths()[0]
        data = self.arc.get_data(path)
        if data is None:
            return
        if not is_text(data):
            messagebox.showinfo("二进制文件", "该文件不是 utf-8 文本，无法内置编辑。\n可用右键『替换此文件』或『用系统编辑器打开』。")
            return
        EditorWindow(self, path, data.decode("utf-8"),
                     on_save=lambda d: self._write_back(path, d))

    def open_in_system(self):
        """提取选中文件到临时目录，用系统默认程序打开（只读查看，不回写包内）"""
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选中要打开的文件")
            return
        paths = self._selected_paths()
        if len(paths) > 10:
            messagebox.showwarning("提示", "一次最多打开 10 个文件，请减少选中数量")
            return
        outdir = os.path.join(tempfile.gettempdir(), "ipk_open")
        os.makedirs(outdir, exist_ok=True)
        opened = 0
        for path in paths:
            data = self.arc.get_data(path)
            if data is None:
                continue
            # 展平层级为安全文件名，保留扩展名以便系统识别文件类型
            safe = path.replace("/", "_").replace("\\", "_")
            tmp = os.path.join(outdir, safe)
            with open(tmp, "wb") as f:
                f.write(data)
            try:
                if sys.platform == "win32":
                    os.startfile(tmp)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", tmp])
                else:
                    subprocess.Popen(["xdg-open", tmp])
                opened += 1
            except OSError as e:
                messagebox.showerror("错误", "无法打开 %s:\n%s" % (path, e))
        if opened:
            self.log("已用系统默认程序打开 %d 个包内文件（只读副本：%s）" % (opened, outdir))

    def external_edit(self):
        sel = self.tree.selection()
        if len(sel) != 1:
            messagebox.showwarning("提示", "请先选中一个文件")
            return
        path = self._selected_paths()[0]
        data = self.arc.get_data(path)
        if data is None:
            return
        ExternalEditWindow(self, path, data, on_change=lambda d: self._write_back(path, d))

    def _write_back(self, path, data):
        self.arc.replace_file(path, data)
        self.mark_dirty()
        self.refresh_tree()

    def replace_selected(self):
        sel = self.tree.selection()
        if len(sel) != 1:
            messagebox.showwarning("提示", "请先选中一个要替换的文件")
            return
        path = self._selected_paths()[0]
        p = filedialog.askopenfilename(title="选择用于替换的新文件")
        if not p:
            return
        with open(p, "rb") as f:
            data = f.read()
        self.arc.replace_file(path, data)
        self.mark_dirty()
        self.refresh_tree()
        self.log("已替换: %s ← %s" % (path, os.path.basename(p)))

    def export_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选中文件")
            return
        d = filedialog.askdirectory(title="选择导出目录")
        if not d:
            return
        for path in self._selected_paths():
            data = self.arc.get_data(path)
            if data is None:
                continue
            out = os.path.join(d, os.path.basename(path))
            with open(out, "wb") as f:
                f.write(data)
        self.log("已导出 %d 个文件到 %s" % (len(sel), d))

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        paths = self._selected_paths()
        if not messagebox.askyesno("确认", "从包内删除 %d 个条目？" % len(paths)):
            return
        for p in paths:
            self.arc.delete_file(p)
        self.mark_dirty()
        self.refresh_tree()
        self.log("已删除 %d 个条目" % len(paths))

    # ---------- 依赖 ----------
    def dep_add(self):
        v = self.e_dep.get().strip()
        if v:
            self.dep_list.insert("end", v)
            self.e_dep.delete(0, "end")
            self.mark_dirty()

    def dep_del(self):
        for i in reversed(self.dep_list.curselection()):
            self.dep_list.delete(i)
        self.mark_dirty()

    def on_close(self):
        if self.dirty and not messagebox.askyesno("退出", "有未保存的修改，确定丢弃并退出？"):
            return
        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()

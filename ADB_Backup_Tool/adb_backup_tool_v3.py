# -*- coding: utf-8 -*-
"""
ADB 分区备份与编程器固件提取工具（单文件 tkinter 实现）

功能：
  1. ADB 硬件识别
  2. 查询 /proc/mtd、ls /dev、df -h，复制/导出分区表
  3. 按分区逐个备份到 F/E/D 盘（优先 F，其次 E，最后 D）的设备名文件夹
  4. 备份编程器固件（整块闪存设备原始数据）
  5. 权限检测、adb 可写提权、恢复原始读写权限
  6. 设备文件浏览、读取、编辑、上传、下载
  7. Netcat 扫描/安装/配置 PATH，以及通过 Netcat 将分区直接传输到 PC
"""

import os
import re
import sys
import csv
import queue
import shlex
import shutil
import socket
import tempfile
import threading
import time
import posixpath
import subprocess
import urllib.request
import webbrowser
import zipfile
from datetime import datetime
from urllib.parse import urljoin
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog

APP_TITLE = "ADB 分区备份与编程器固件工具 V3.0"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
MOUNT_KEYS = ("/", "/system", "/vendor", "/product", "/odm", "/data", "/cache", "/metadata", "/persist")
NETCAT_PAGE = "https://eternallybored.org/misc/netcat/"
NETCAT_ZIP_URLS = (
    "https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip",
    "https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip",
)
ADB_DOCS_PAGE = "https://android-docs.cn/tools/releases/platform-tools"
ADB_123PAN_PAGE = "https://1812340715.share.123pan.cn/123pan/iRg8Vv-Al5zv?pwd=pwls#"
ADB_123PAN_PWD = "pwls"


# ----------------------------------------------------------------------------
# 通用工具函数
# ----------------------------------------------------------------------------
def human_size(num):
    if num is None:
        return "未知"
    try:
        num = float(num)
    except (TypeError, ValueError):
        return "未知"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024.0 or unit == "TB":
            if unit == "B":
                return "%d B" % int(num)
            return "%.2f %s" % (num, unit)
        num /= 1024.0
    return "%.2f TB" % num


def sanitize_name(name):
    name = (name or "").strip()
    name = re.sub(r'[\\/:*?"<>|\r\n\t]+', "_", name)
    name = name.strip(" .")
    return name or "unknown_device"


def is_whole_disk(name):
    return bool(re.match(r"^(mmcblk\d+|mmcblk\d+boot\d+|mmcblk\d+rpmb|sd[a-z]+|nvme\d+n\d+|mtdblock\d+|ubi\d+)$", name))


def is_block_partition(name):
    return bool(re.match(r"^(mmcblk\d+p\d+|sd[a-z]+\d+|nvme\d+n\d+p\d+|mmcblk\d+boot\d+|mmcblk\d+rpmb|mtdblock\d+|ubi\d+_\d+)$", name))


def find_adb():
    base = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
    candidates = [
        os.path.join(base, "adb.exe"),
        os.path.join(base, "adb"),
        os.path.join(base, "platform-tools", "adb.exe"),
        os.path.join(base, "platform-tools", "adb"),
        "C:\\adb\\adb.exe",
        "C:\\platform-tools\\adb.exe",
        os.path.join(os.path.expanduser("~"), "Android", "Sdk", "platform-tools", "adb"),
        "/usr/lib/android-sdk/platform-tools/adb",
        "/opt/platform-tools/adb",
        os.path.join(platform_tools_dir(), "adb"),
        os.path.join(platform_tools_dir(), "adb.exe"),
    ]
    la = os.environ.get("LOCALAPPDATA")
    if la:
        candidates.append(os.path.join(la, "Android", "Sdk", "platform-tools", "adb.exe"))
    which = shutil.which("adb")
    if which:
        candidates.insert(0, which)
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return ""


def app_data_dir():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    else:
        base = os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "AdbBackupTool")


def netcat_tools_dir():
    return os.path.join(app_data_dir(), "netcat")


def platform_tools_dir():
    return os.path.join(app_data_dir(), "platform-tools")


def path_has_folder(folder):
    try:
        target = os.path.normcase(os.path.abspath(folder))
    except OSError:
        return False
    for item in os.environ.get("PATH", "").split(os.pathsep):
        item = item.strip().strip('"')
        if not item:
            continue
        try:
            if os.path.normcase(os.path.abspath(item)) == target:
                return True
        except OSError:
            continue
    return False


def find_netcat():
    """扫描系统中的 nc / netcat / ncat，返回去重后的可执行文件路径列表。"""
    names = ("nc.exe", "nc", "nc64.exe", "netcat.exe", "netcat", "ncat.exe", "ncat")
    found = []
    seen = set()

    def add(path):
        if not path:
            return
        try:
            path = os.path.abspath(path)
        except OSError:
            pass
        key = path.lower()
        if key in seen or not os.path.isfile(path):
            return
        seen.add(key)
        found.append(path)

    for name in names:
        add(shutil.which(name))

    here = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
    extra = [
        os.path.join(here, "nc.exe"),
        os.path.join(here, "nc"),
        os.path.join(netcat_tools_dir(), "nc.exe"),
        os.path.join(netcat_tools_dir(), "nc"),
        "C:\\Windows\\System32\\nc.exe",
        "C:\\netcat\\nc.exe",
        "C:\\Program Files\\Nmap\\ncat.exe",
        "C:\\Program Files (x86)\\Nmap\\ncat.exe",
    ]
    for path in extra:
        add(path)
    return found


def local_ipv4():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def port_is_free(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def add_to_user_path(folder):
    """把目录写入当前用户 PATH（HKCU\\Environment），并立即更新当前进程 PATH。"""
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        return False, "目录不存在：%s" % folder
    current = os.environ.get("PATH", "")
    parts = [p for p in current.split(os.pathsep) if p]
    if folder.lower() not in [p.lower() for p in parts]:
        os.environ["PATH"] = current + os.pathsep + folder if current else folder

    if os.name != "nt":
        return True, "已加入当前进程 PATH（非 Windows 系统请手动写入 shell 配置）"
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            try:
                value, value_type = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                value, value_type = "", winreg.REG_EXPAND_SZ
            entries = [p for p in value.split(";") if p]
            if folder.lower() not in [p.lower() for p in entries]:
                entries.append(folder)
                winreg.SetValueEx(key, "Path", 0, value_type, ";".join(entries))
    except OSError as exc:
        return False, "写入用户 PATH 失败：%s" % exc

    try:
        import ctypes
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF, 0x001A, 0, "Environment", 0x0002, 5000, None)
    except Exception:
        pass
    return True, "已写入用户 PATH：%s" % folder


def is_gzip_file(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def parse_partition_table(mtd_text, parts_text, byname_text, mtd_dir_exists=False):
    """解析 /proc/mtd、/proc/partitions、by-name 软链接，返回 (分区列表, 块设备字典, 块设备列表)"""
    parts = {}
    for line in (parts_text or "").splitlines():
        m = re.match(r"^\s*\d+\s+\d+\s+(\d+)\s+(\S+)\s*$", line)
        if m:
            parts[m.group(2)] = int(m.group(1)) * 1024

    entries = []
    seen_paths = set()
    seen_names = set()

    # 1) MTD 分区
    for line in (mtd_text or "").splitlines():
        line = line.strip()
        m = re.match(r'^(mtd\d+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"?(.*?)"?$', line)
        if not m:
            continue
        mtd_name = m.group(1)
        try:
            size = int(m.group(2), 16)
        except ValueError:
            size = None
        part_name = m.group(4).strip('" ') or mtd_name
        path = "/dev/mtd/%s" % mtd_name if mtd_dir_exists else "/dev/%s" % mtd_name
        if part_name in seen_names:
            part_name = "%s_%s" % (part_name, mtd_name)
        entries.append({"name": part_name, "type": "mtd", "path": path, "size": size})
        seen_names.add(part_name)
        seen_paths.add(path)

    # 2) by-name 软链接
    byname_names = set()
    for line in (byname_text or "").splitlines():
        m = re.search(r"([^\s/]+)\s*->\s*(\S+)", line)
        if not m:
            continue
        name, target = m.group(1), m.group(2)
        if name in ("by-name", "platform", "by-name/"):
            continue
        real = target.rstrip("/").split("/")[-1]
        path = target if target.startswith("/") else "/dev/block/%s" % real
        if path in seen_paths:
            continue
        size = parts.get(real)
        entries.append({"name": name, "type": "block", "path": path, "size": size})
        seen_paths.add(path)
        seen_names.add(name)
        byname_names.add(name)

    # 3) /proc/partitions 中未被 by-name 覆盖的分区
    for name, size in parts.items():
        if name in byname_names or name in seen_names:
            continue
        if is_whole_disk(name):
            continue
        if re.match(r"^(loop|zram|ram|dm-)", name):
            continue
        if mtd_dir_exists and name.startswith("mtdblock"):
            continue
        if not is_block_partition(name):
            continue
        path = "/dev/block/%s" % name
        if path in seen_paths:
            continue
        entries.append({"name": name, "type": "block", "path": path, "size": size})
        seen_paths.add(path)
        seen_names.add(name)

    # 4) 整块闪存设备（用于编程器固件）
    block_devices = []
    for name, size in sorted(parts.items()):
        if is_whole_disk(name) and not name.startswith("mtdblock"):
            block_devices.append({"name": name, "path": "/dev/block/%s" % name, "size": size})
    if not block_devices:
        for name, size in sorted(parts.items()):
            if name.startswith("mtdblock"):
                block_devices.append({"name": name, "path": "/dev/block/%s" % name, "size": size})

    return entries, parts, block_devices


# ----------------------------------------------------------------------------
# 主程序
# ----------------------------------------------------------------------------
class AdbBackupApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1320x860")
        self.root.minsize(1100, 720)

        try:
            self.root.option_add("*Font", ("Microsoft YaHei UI", 9))
        except tk.TclError:
            pass

        self.adb_exe = find_adb()
        self.adb_path_var = tk.StringVar(value=self.adb_exe)
        self.serial_var = tk.StringVar(value="")
        self.device_map = {}
        self.device_model = ""
        self.device_folder = ""
        self.partitions = []
        self.block_devices = []
        self.parts_map = {}
        self.root_mode = "none"
        self.exec_out_ok = None

        self._perm_snapshot = None
        self._stop_backup = False
        self._dump_proc = None
        self._backup_running = False

        self.nc_path = ""
        self.net_items = {}
        self._net_stop = False
        self._net_running = False
        self._net_listener = None
        self._net_sender = None
        self._adb_downloading = False

        self.log_queue = queue.Queue()
        self.raw_texts = {}
        self.backup_items = {}
        self.fw_map = {}
        self.file_rows = {}

        self._build_ui()
        self._poll_log()
        self.refresh_dest_labels()

        self.root.after(400, self.refresh_devices)
        self.root.after(600, lambda: self.scan_netcat(quiet=True))

    # ------------------------------------------------------------------
    # 界面
    # ------------------------------------------------------------------
    def _build_ui(self):
        top = ttk.Frame(self.root, padding=(8, 6))
        top.pack(fill="x")

        ttk.Label(top, text="ADB 路径:").pack(side="left")
        ttk.Entry(top, textvariable=self.adb_path_var, width=42).pack(side="left", padx=(4, 4))
        ttk.Button(top, text="浏览…", width=7, command=self._browse_adb).pack(side="left")
        ttk.Button(top, text="刷新设备", width=9, command=self.refresh_devices).pack(side="left", padx=(8, 4))

        ttk.Label(top, text="设备:").pack(side="left", padx=(10, 2))
        self.device_combo = ttk.Combobox(top, state="readonly", width=44)
        self.device_combo.pack(side="left", padx=2)
        self.device_combo.bind("<<ComboboxSelected>>", self._on_device_selected)

        self.conn_label = ttk.Label(top, text="未连接", foreground="#b71c1c")
        self.conn_label.pack(side="left", padx=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        self._build_device_tab()
        self._build_partition_tab()
        self._build_backup_tab()
        self._build_firmware_tab()
        self._build_permission_tab()
        self._build_file_tab()
        self._build_network_tab()
        self._build_adb_env_tab()

        log_frame = ttk.LabelFrame(self.root, text="运行日志", padding=4)
        log_frame.pack(fill="x", padx=8, pady=(0, 2))
        log_top = ttk.Frame(log_frame)
        log_top.pack(fill="x")
        ttk.Button(log_top, text="清空日志", width=9, command=self._clear_log).pack(side="right")
        ttk.Button(log_top, text="导出日志", width=9, command=self.export_log).pack(side="right", padx=(0, 4))
        ttk.Button(log_top, text="复制日志", width=9, command=self.copy_log).pack(side="right", padx=(0, 4))
        self.log_text = scrolledtext.ScrolledText(log_frame, height=7, wrap="word", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_config("error", foreground="#c62828")
        self.log_text.tag_config("warn", foreground="#e65100")
        self.log_text.tag_config("ok", foreground="#2e7d32")
        self.log_text.config(state="disabled")

        self.status_label = ttk.Label(self.root, text="就绪", anchor="w", relief="sunken", padding=(6, 2))
        self.status_label.pack(fill="x", side="bottom")

    def _build_device_tab(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="1. 设备识别")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="查询硬件识别信息", command=self.query_device_info).pack(side="left")
        ttk.Button(bar, text="复制信息", command=lambda: self.copy_widget(self.device_info_text)).pack(side="left", padx=6)
        ttk.Button(bar, text="导出信息", command=self.export_device_info).pack(side="left")

        self.device_info_text = scrolledtext.ScrolledText(tab, wrap="none", font=("Consolas", 10))
        self.device_info_text.pack(fill="both", expand=True)
        self._set_text(self.device_info_text, "请连接设备后点击“刷新设备”。\n")

    def _build_partition_tab(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="2. 分区查询")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="查询分区信息", command=self.query_partitions).pack(side="left")
        ttk.Button(bar, text="复制分区表", command=self.copy_partition_table).pack(side="left", padx=6)
        ttk.Button(bar, text="导出分区表(TXT)", command=lambda: self.export_partition_table("txt")).pack(side="left")
        ttk.Button(bar, text="导出分区表(CSV)", command=lambda: self.export_partition_table("csv")).pack(side="left", padx=6)
        self.partition_status_label = ttk.Label(bar, text="分区数：0")
        self.partition_status_label.pack(side="left", padx=12)

        paned = ttk.Panedwindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True)

        left = ttk.LabelFrame(paned, text="解析出的分区表", padding=4)
        columns = ("name", "type", "size", "path")
        self.partition_tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        headings = {"name": ("分区名", 180), "type": ("类型", 70), "size": ("大小", 110), "path": ("设备路径", 340)}
        for col in columns:
            text, width = headings[col]
            self.partition_tree.heading(col, text=text)
            self.partition_tree.column(col, width=width, anchor="w")
        vs = ttk.Scrollbar(left, orient="vertical", command=self.partition_tree.yview)
        hs = ttk.Scrollbar(left, orient="horizontal", command=self.partition_tree.xview)
        self.partition_tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.partition_tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        paned.add(left, weight=3)

        right = ttk.Notebook(paned)
        raw_defs = [
            ("mtd", "/proc/mtd"),
            ("dev", "ls /dev"),
            ("parts", "/proc/partitions"),
            ("df", "df -h"),
        ]
        for key, title in raw_defs:
            frame, text = self._make_raw_panel(right, title)
            right.add(frame, text=title)
            self.raw_texts[key] = text
        paned.add(right, weight=2)

    def _make_raw_panel(self, parent, title):
        frame = ttk.Frame(parent, padding=4)
        top = ttk.Frame(frame)
        top.pack(fill="x")
        ttk.Label(top, text=title).pack(side="left")
        txt = scrolledtext.ScrolledText(frame, wrap="none", height=12, font=("Consolas", 9))
        txt.pack(fill="both", expand=True)
        ttk.Button(top, text="复制", width=6, command=lambda: self.copy_widget(txt)).pack(side="right")
        self._set_text(txt, "")
        return frame, txt

    def _build_backup_tab(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="3. 分区备份")

        info = ttk.LabelFrame(tab, text="备份位置", padding=6)
        info.pack(fill="x", pady=(0, 6))
        self.backup_drive_label = ttk.Label(info, text="")
        self.backup_drive_label.pack(side="left")
        ttk.Button(info, text="重新检测磁盘", command=self.refresh_dest_labels).pack(side="right")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="刷新分区列表", command=self.query_partitions).pack(side="left")
        ttk.Button(bar, text="全选", command=self.select_all_partitions).pack(side="left", padx=6)
        ttk.Button(bar, text="取消选择", command=self.clear_partition_selection).pack(side="left")
        self.backup_btn = ttk.Button(bar, text="开始备份选中分区", command=self.start_backup)
        self.backup_btn.pack(side="left", padx=10)
        self.stop_btn = ttk.Button(bar, text="停止", command=self.stop_backup, state="disabled")
        self.stop_btn.pack(side="left")
        ttk.Button(bar, text="打开备份目录", command=self.open_backup_dir).pack(side="left", padx=10)
        self.backup_selection_label = ttk.Label(bar, text="已选：0")
        self.backup_selection_label.pack(side="left", padx=8)

        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True)

        columns = ("name", "type", "size", "path", "status")
        self.backup_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
        headings = {
            "name": ("分区名", 180),
            "type": ("类型", 70),
            "size": ("大小", 100),
            "path": ("设备路径", 360),
            "status": ("状态", 150),
        }
        for col in columns:
            text, width = headings[col]
            self.backup_tree.heading(col, text=text)
            self.backup_tree.column(col, width=width, anchor="w")
        vs = ttk.Scrollbar(tree_frame, orient="vertical", command=self.backup_tree.yview)
        hs = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.backup_tree.xview)
        self.backup_tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.backup_tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.backup_tree.bind("<<TreeviewSelect>>", lambda e: self._update_backup_selection())

        bottom = ttk.Frame(tab)
        bottom.pack(fill="x", pady=(6, 0))
        self.backup_progress = ttk.Progressbar(bottom, mode="determinate", maximum=100)
        self.backup_progress.pack(fill="x", side="top")
        self.backup_progress_label = ttk.Label(bottom, text="等待操作")
        self.backup_progress_label.pack(anchor="w", pady=(2, 0))

    def _build_firmware_tab(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="4. 编程器固件")

        note = (
            "编程器固件 = 整块闪存芯片的原始镜像（例如 eMMC 的 /dev/block/mmcblk0）。\n"
            "提示：读取整盘通常需要 root 权限，文件体积可能很大，请确保目标磁盘空间充足。\n"
            "如果设备是 MTD/NAND 闪存，请选择对应的整盘设备；MTD 分区请在“分区备份”标签页操作。"
        )
        ttk.Label(tab, text=note, justify="left").pack(anchor="w", pady=(0, 8))

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="闪存设备:").pack(side="left")
        self.fw_combo = ttk.Combobox(bar, state="readonly", width=48)
        self.fw_combo.pack(side="left", padx=6)
        self.fw_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_dest_labels())
        ttk.Button(bar, text="扫描设备", command=self.scan_firmware_devices).pack(side="left", padx=6)
        self.fw_btn = ttk.Button(bar, text="开始备份编程器固件", command=self.start_firmware_backup)
        self.fw_btn.pack(side="left", padx=10)
        ttk.Button(bar, text="打开固件目录", command=self.open_firmware_dir).pack(side="left")

        self.fw_dir_label = ttk.Label(tab, text="")
        self.fw_dir_label.pack(anchor="w", pady=(0, 6))

        self.fw_progress = ttk.Progressbar(tab, mode="determinate", maximum=100)
        self.fw_progress.pack(fill="x", pady=(0, 4))
        self.fw_status_label = ttk.Label(tab, text="等待操作")
        self.fw_status_label.pack(anchor="w", pady=(0, 8))

        self.fw_info_text = scrolledtext.ScrolledText(tab, wrap="word", height=10, font=("Consolas", 9))
        self.fw_info_text.pack(fill="both", expand=True)
        self._set_text(self.fw_info_text, "点击“扫描设备”读取块设备列表。\n")

    def _build_permission_tab(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="5. 权限管理")

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="5-1 查询磁盘读写权限", command=self.check_permissions).pack(side="left")
        ttk.Button(bar, text="5-2 ADB 可写提权", command=self.elevate_permissions).pack(side="left", padx=8)
        ttk.Button(bar, text="5-3 恢复原始读写权限", command=self.restore_permissions).pack(side="left")
        ttk.Button(bar, text="刷新状态", command=self.check_permissions).pack(side="left", padx=8)

        self.perm_text = scrolledtext.ScrolledText(tab, wrap="word", font=("Consolas", 10))
        self.perm_text.pack(fill="both", expand=True)
        self._set_text(self.perm_text, "点击“5-1 查询磁盘读写权限”查看当前状态。\n")

    def _build_file_tab(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="6. 文件管理")

        path_bar = ttk.Frame(tab)
        path_bar.pack(fill="x", pady=(0, 6))
        ttk.Label(path_bar, text="设备路径:").pack(side="left")
        self.file_path_var = tk.StringVar(value="/sdcard")
        self.file_path_combo = ttk.Combobox(
            path_bar,
            textvariable=self.file_path_var,
            values=["/sdcard", "/data/local/tmp", "/data", "/system", "/vendor", "/"],
            width=52,
        )
        self.file_path_combo.pack(side="left", padx=4)
        self.file_path_combo.bind("<Return>", lambda e: self.refresh_file_list())
        ttk.Button(path_bar, text="转到", command=self.refresh_file_list).pack(side="left")
        ttk.Button(path_bar, text="上一级", command=self.file_up).pack(side="left", padx=4)
        ttk.Button(path_bar, text="刷新", command=self.refresh_file_list).pack(side="left")

        act_bar = ttk.Frame(tab)
        act_bar.pack(fill="x", pady=(0, 6))
        ttk.Button(act_bar, text="下载到本地", command=self.download_selected_file).pack(side="left")
        ttk.Button(act_bar, text="上传文件", command=self.upload_file).pack(side="left", padx=6)
        ttk.Button(act_bar, text="查看 / 编辑", command=self.edit_selected_file).pack(side="left")
        ttk.Button(act_bar, text="新建文件", command=self.new_remote_file).pack(side="left", padx=6)
        self.file_status_label = ttk.Label(act_bar, text="")
        self.file_status_label.pack(side="left", padx=10)

        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True)
        columns = ("name", "kind", "size", "perm", "date")
        self.file_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "name": ("名称", 330),
            "kind": ("类型", 80),
            "size": ("大小", 100),
            "perm": ("权限", 120),
            "date": ("日期", 160),
        }
        for col in columns:
            text, width = headings[col]
            self.file_tree.heading(col, text=text)
            self.file_tree.column(col, width=width, anchor="w")
        vs = ttk.Scrollbar(tree_frame, orient="vertical", command=self.file_tree.yview)
        hs = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.file_tree.bind("<Double-1>", lambda e: self.file_activate())

    # ------------------------------------------------------------------
    # 7. 网络传输（Netcat）
    # ------------------------------------------------------------------
    def _build_network_tab(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="7. 网络传输")

        nc_frame = ttk.LabelFrame(tab, text="7-1 Netcat 扫描与配置", padding=6)
        nc_frame.pack(fill="x", pady=(0, 6))
        nc_bar = ttk.Frame(nc_frame)
        nc_bar.pack(fill="x")
        ttk.Button(nc_bar, text="扫描 nc 命令", command=self.scan_netcat).pack(side="left")
        ttk.Button(nc_bar, text="一键下载安装 Netcat", command=self.download_netcat).pack(side="left", padx=6)
        ttk.Button(nc_bar, text="打开下载页面", command=self.open_netcat_page).pack(side="left")
        ttk.Button(nc_bar, text="选择 nc.exe 并配置 PATH", command=self.select_netcat).pack(side="left", padx=6)
        ttk.Button(nc_bar, text="一键配置 PATH", command=self.configure_netcat_path).pack(side="left")
        self.nc_status_label = ttk.Label(nc_frame, text="Netcat：未检测（点击“扫描 nc 命令”）")
        self.nc_status_label.pack(anchor="w", pady=(4, 0))

        net_frame = ttk.LabelFrame(tab, text="7-2 分区表自动识别与 Netcat 传输", padding=6)
        net_frame.pack(fill="both", expand=True)

        opt = ttk.Frame(net_frame)
        opt.pack(fill="x", pady=(0, 4))
        ttk.Label(opt, text="传输方式:").pack(side="left")
        self.net_mode_var = tk.StringVar(value="adb reverse（USB 推荐）")
        ttk.Combobox(
            opt, textvariable=self.net_mode_var, state="readonly", width=20,
            values=["adb reverse（USB 推荐）", "局域网 IP（设备直连 PC）"],
        ).pack(side="left", padx=4)
        ttk.Label(opt, text="PC IP:").pack(side="left", padx=(8, 0))
        self.net_ip_var = tk.StringVar(value=local_ipv4())
        ttk.Entry(opt, textvariable=self.net_ip_var, width=16).pack(side="left", padx=4)
        ttk.Button(opt, text="自动获取", width=8, command=self._auto_fill_ip).pack(side="left")
        ttk.Label(opt, text="端口:").pack(side="left", padx=(8, 0))
        self.net_port_var = tk.StringVar(value="8888")
        ttk.Entry(opt, textvariable=self.net_port_var, width=7).pack(side="left", padx=4)
        ttk.Label(opt, text="（被占用自动改用 9999）").pack(side="left")

        out = ttk.Frame(net_frame)
        out.pack(fill="x", pady=(0, 4))
        ttk.Label(out, text="输出目录:").pack(side="left")
        self.net_dir_var = tk.StringVar(value="")
        ttk.Entry(out, textvariable=self.net_dir_var).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(out, text="浏览…", width=7, command=self._browse_net_dir).pack(side="left")
        ttk.Button(out, text="打开目录", width=8, command=self._open_net_dir).pack(side="left", padx=4)

        bar = ttk.Frame(net_frame)
        bar.pack(fill="x", pady=(0, 4))
        ttk.Button(bar, text="自动识别分区表", command=self.net_scan_partitions).pack(side="left")
        ttk.Button(bar, text="全选", command=self._net_select_all).pack(side="left", padx=6)
        ttk.Button(bar, text="取消选择", command=self._net_clear_selection).pack(side="left")
        self.net_start_btn = ttk.Button(bar, text="开始 Netcat 备份", command=self.start_net_backup)
        self.net_start_btn.pack(side="left", padx=10)
        self.net_stop_btn = ttk.Button(bar, text="停止", command=self.stop_net_backup, state="disabled")
        self.net_stop_btn.pack(side="left")
        ttk.Button(bar, text="复制发送命令", command=self.copy_net_commands).pack(side="left", padx=10)
        self.net_selection_label = ttk.Label(bar, text="已选：0")
        self.net_selection_label.pack(side="left", padx=8)

        tree_frame = ttk.Frame(net_frame)
        tree_frame.pack(fill="both", expand=True)
        columns = ("name", "type", "size", "path", "status")
        self.net_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
        headings = {
            "name": ("分区名", 180),
            "type": ("类型", 70),
            "size": ("大小", 100),
            "path": ("设备路径", 330),
            "status": ("状态", 160),
        }
        for col in columns:
            text, width = headings[col]
            self.net_tree.heading(col, text=text)
            self.net_tree.column(col, width=width, anchor="w")
        vs = ttk.Scrollbar(tree_frame, orient="vertical", command=self.net_tree.yview)
        hs = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.net_tree.xview)
        self.net_tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.net_tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.net_tree.bind("<<TreeviewSelect>>", lambda e: self._update_net_selection())

        bottom = ttk.Frame(net_frame)
        bottom.pack(fill="x", pady=(6, 0))
        self.net_progress = ttk.Progressbar(bottom, mode="indeterminate")
        self.net_progress.pack(fill="x")
        self.net_status_label = ttk.Label(
            bottom,
            text="PC 监听：nc -l -p 8888 > E:\\1\\backup_mtd27.bin.gz    "
                 "设备发送：dd if=/dev/mtd27 | gzip | nc <PC_IP> 8888",
        )
        self.net_status_label.pack(anchor="w", pady=(2, 0))

    def _auto_fill_ip(self):
        ip = local_ipv4()
        self.net_ip_var.set(ip)
        self.log("本机 IP：%s" % ip)

    def _net_dir(self):
        value = self.net_dir_var.get().strip()
        if value:
            return value
        root = self.pick_output_root()
        if not root:
            return None
        return os.path.join(root, self._device_folder_name(), "网络备份")

    def _browse_net_dir(self):
        initial = self._net_dir()
        path = filedialog.askdirectory(title="选择网络备份输出目录", initialdir=initial if initial and os.path.isdir(initial) else None)
        if path:
            self.net_dir_var.set(path)

    def _open_net_dir(self):
        path = self._net_dir()
        if not path:
            messagebox.showerror("无可用磁盘", "未检测到可写的 F/E/D 盘，请手动选择输出目录。")
            return
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("创建目录失败", str(exc))
            return
        self._open_folder(path)

    def scan_netcat(self, quiet=False):
        found = find_netcat()
        if found:
            self.nc_path = found[0]
            self.nc_status_label.config(text="Netcat：%s" % found[0])
            if not quiet:
                self.log("检测到 %d 个 Netcat：%s" % (len(found), "；".join(found)), "ok")
        else:
            self.nc_path = ""
            self.nc_status_label.config(text="Netcat：未检测到（可一键下载或打开下载页面）")
            if not quiet:
                self.log("未检测到 nc/netcat/ncat。可点击“一键下载安装 Netcat”，或打开下载页面手动安装。", "warn")

    def open_netcat_page(self):
        webbrowser.open(NETCAT_PAGE)
        self.log("已打开 Netcat 下载页面：%s" % NETCAT_PAGE)

    def configure_netcat_path(self):
        exe = self.nc_path
        if not exe:
            found = find_netcat()
            exe = found[0] if found else ""
        if not exe:
            if messagebox.askyesno("未找到 Netcat", "未检测到 nc，是否打开下载页面手动下载？"):
                self.open_netcat_page()
            return
        ok, msg = add_to_user_path(os.path.dirname(exe))
        self.log(msg, "ok" if ok else "error")
        if ok:
            messagebox.showinfo("PATH 已配置", msg)
        else:
            messagebox.showerror("PATH 配置失败", msg)

    def select_netcat(self):
        path = filedialog.askopenfilename(
            title="选择 nc.exe", filetypes=[("可执行文件", "*.exe"), ("所有文件", "*.*")])
        if not path:
            return
        self.nc_path = path
        self.nc_status_label.config(text="Netcat：%s" % path)
        ok, msg = add_to_user_path(os.path.dirname(path))
        self.log("已选择 Netcat：%s" % path, "ok")
        self.log(msg, "ok" if ok else "error")
        if ok:
            messagebox.showinfo("Netcat 配置完成", "已选择：\n%s\n\n%s" % (path, msg))
        else:
            messagebox.showwarning("PATH 配置失败", msg)

    def download_netcat(self):
        if os.name != "nt":
            messagebox.showinfo("提示", "自动安装仅支持 Windows，请在浏览器中手动下载。")
            self.open_netcat_page()
            return
        if not messagebox.askyesno(
                "下载 Netcat",
                "将从 eternallybored.org 下载官方 Windows Netcat 压缩包，\n"
                "解压后放到：%s\n并自动添加到用户 PATH。\n\n是否继续？" % netcat_tools_dir()):
            return
        threading.Thread(target=self._download_netcat_worker, daemon=True).start()

    def _download_netcat_worker(self):
        tools = netcat_tools_dir()
        try:
            os.makedirs(tools, exist_ok=True)
        except OSError as exc:
            self._post(self.log, "创建目录失败：%s" % exc, "error")
            return
        fd, zip_path = tempfile.mkstemp(prefix="netcat_", suffix=".zip")
        os.close(fd)
        try:
            last_error = None
            for url in NETCAT_ZIP_URLS:
                self._post(self.log, "正在下载：%s" % url)
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=60) as resp, open(zip_path, "wb") as f:
                        shutil.copyfileobj(resp, f)
                    if os.path.getsize(zip_path) < 10000:
                        raise RuntimeError("下载文件过小，可能不是有效压缩包")
                    break
                except Exception as exc:
                    last_error = exc
                    self._post(self.log, "下载失败：%s" % exc, "warn")
            else:
                raise RuntimeError("所有下载地址均失败：%s" % last_error)

            with zipfile.ZipFile(zip_path) as zf:
                names = [n for n in zf.namelist()
                         if posixpath.basename(n).lower() in ("nc.exe", "nc64.exe")]
                if not names:
                    raise RuntimeError("压缩包内未找到 nc.exe")
                preferred = ("nc64.exe", "nc.exe") if sys.maxsize > 2 ** 32 else ("nc.exe", "nc64.exe")
                chosen = None
                for want in preferred:
                    for name in names:
                        if posixpath.basename(name).lower() == want:
                            chosen = name
                            break
                    if chosen:
                        break
                data = zf.read(chosen)

            dest = os.path.join(tools, "nc.exe")
            with open(dest, "wb") as f:
                f.write(data)
        except Exception as exc:
            self._post(self.log, "Netcat 下载安装失败：%s" % exc, "error")
            self._post(messagebox.showerror, "下载失败",
                       "自动下载失败：%s\n\n请点击“打开下载页面”手动下载，安装后点击“选择 nc.exe 并配置 PATH”。" % exc)
            return
        finally:
            self._remove_file(zip_path)

        ok, path_msg = add_to_user_path(tools)
        self._post(self._apply_downloaded_netcat, dest, ok, path_msg)

    def _apply_downloaded_netcat(self, dest, path_ok, path_msg):
        self.nc_path = dest
        self.nc_status_label.config(text="Netcat：%s" % dest)
        self.log("Netcat 已安装：%s" % dest, "ok")
        self.log(path_msg, "ok" if path_ok else "warn")
        messagebox.showinfo("Netcat 安装完成",
                            "已安装到：\n%s\n\n%s\n\n可直接使用 7-2 进行网络备份。" % (dest, path_msg))

    def net_scan_partitions(self):
        if self.partitions:
            self._fill_net_tree(self.partitions)
            self.log("已载入现有分区表：%d 个分区" % len(self.partitions), "ok")
            return
        self.query_partitions()

    def _fill_net_tree(self, entries):
        self.net_tree.delete(*self.net_tree.get_children())
        self.net_items.clear()
        for idx, entry in enumerate(entries):
            iid = "n%d" % idx
            self.net_items[iid] = entry
            self.net_tree.insert("", "end", iid=iid, values=(
                entry["name"], entry["type"], human_size(entry["size"]), entry["path"], "待传输"
            ))
        self._update_net_selection()

    def _net_select_all(self):
        self.net_tree.selection_set(self.net_tree.get_children())
        self._update_net_selection()

    def _net_clear_selection(self):
        self.net_tree.selection_remove(self.net_tree.get_children())
        self._update_net_selection()

    def _update_net_selection(self):
        self.net_selection_label.config(text="已选：%d" % len(self.net_tree.selection()))

    def _set_net_tree_status(self, iid, text):
        try:
            self.net_tree.set(iid, "status", text)
        except tk.TclError:
            pass

    def _selected_net_entries(self):
        selection = self.net_tree.selection()
        items = [(iid, self.net_items[iid]) for iid in selection if iid in self.net_items]
        return items

    def copy_net_commands(self):
        items = self._selected_net_entries()
        if not items:
            items = list(self.net_items.items())
        if not items:
            messagebox.showinfo("无分区", "请先点击“自动识别分区表”。")
            return
        try:
            port = int(self.net_port_var.get().strip() or 8888)
        except ValueError:
            port = 8888
        outdir = self._net_dir() or (
            r"E:\1" if os.name == "nt" else os.path.join(os.path.expanduser("~"), "ADB备份"))
        device_ip = "127.0.0.1" if "reverse" in self.net_mode_var.get() else (self.net_ip_var.get().strip() or "<PC_IP>")
        lines = ["# 每个分区执行一次；传输完成后 PC 端监听会自行结束"]
        for _, entry in items:
            name = sanitize_name(entry["name"])
            target = os.path.join(outdir, "backup_%s.bin.gz" % name)
            lines.append('nc -l -p %d > "%s"' % (port, target))
            lines.append('adb shell "dd if=%s | gzip | nc %s %d"' % (entry["path"], device_ip, port))
            lines.append("# SSH 方式：ssh user@设备IP \"dd if=%s | gzip | nc %s %d\"" % (entry["path"], device_ip, port))
            lines.append("")
        lines.append("# 端口 %d 被占用时改用 9999" % port)
        text = "\n".join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status("发送命令已复制到剪贴板")
        self.log("已复制 %d 个分区的 Netcat 发送命令" % len(items), "ok")

    def _resolve_net_port(self):
        try:
            requested = int(self.net_port_var.get().strip() or 8888)
        except ValueError:
            requested = 8888
        if not 1 <= requested <= 65535:
            requested = 8888
        if port_is_free(requested):
            self.log("使用端口 %d" % requested)
            return requested
        port = 9999 if requested != 9999 else 10000
        while port <= 65535 and not port_is_free(port):
            port += 1
        if port > 65535:
            port = requested
        self.log("端口 %d 已被占用，自动改用 %d" % (requested, port), "warn")
        return port

    def start_net_backup(self):
        if self._net_running:
            messagebox.showinfo("正在传输", "当前已有网络传输任务在运行。")
            return
        if not self._check_device():
            return
        items = self._selected_net_entries()
        if not items:
            if not self.net_items:
                messagebox.showinfo("无分区", "请先点击“自动识别分区表”。")
                return
            if not messagebox.askyesno("未选择分区", "当前未选择任何分区，是否传输全部分区？"):
                return
            items = list(self.net_items.items())

        if not self.nc_path:
            self.scan_netcat(quiet=True)
        if not self.nc_path or not os.path.isfile(self.nc_path):
            if messagebox.askyesno("未找到 Netcat", "未检测到可用的 nc 程序。\n是否打开下载页面？"):
                self.open_netcat_page()
            return

        outdir = self._net_dir()
        if not outdir:
            messagebox.showerror("无可用磁盘", "未检测到可写的 F/E/D 盘，请手动选择输出目录。")
            return
        try:
            os.makedirs(outdir, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("创建目录失败", str(exc))
            return

        mode = "reverse" if "reverse" in self.net_mode_var.get() else "lan"
        pc_ip = self.net_ip_var.get().strip()
        if mode == "lan" and not pc_ip:
            messagebox.showwarning("缺少 PC IP", "局域网模式需要填写 PC 的 IP 地址。")
            return

        port = self._resolve_net_port()
        self._net_stop = False
        self._net_running = True
        self.net_start_btn.config(state="disabled")
        self.net_stop_btn.config(state="normal")
        self.net_progress.start(12)
        for iid, _ in items:
            self._set_net_tree_status(iid, "等待")
        self._net_set_status("准备传输 %d 个分区，端口 %d" % (len(items), port))
        self.log("开始 Netcat 传输：%d 个分区，端口 %d，方式 %s，目录 %s" % (
            len(items), port, "adb reverse" if mode == "reverse" else "局域网", outdir), "ok")
        threading.Thread(target=self._net_worker, args=(items, outdir, port, mode, pc_ip), daemon=True).start()

    def stop_net_backup(self):
        self._net_stop = True
        self.log("正在停止网络传输…", "warn")
        for proc in (self._net_listener, self._net_sender):
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
        self._net_set_status("正在停止…")

    def _net_set_status(self, text):
        try:
            self.net_status_label.config(text=text)
        except tk.TclError:
            pass

    def _net_worker(self, items, outdir, port, mode, pc_ip):
        reverse_added = False
        success = 0
        failed = 0
        self.detect_root()
        self.log("网络传输权限模式：%s" % self.root_mode, "warn" if self.root_mode == "none" else "info")
        try:
            if mode == "reverse":
                rc, out, err = self.adb(["reverse", "tcp:%d" % port, "tcp:%d" % port], timeout=20)
                if rc == 0:
                    reverse_added = True
                    self.log("adb reverse 已建立：tcp:%d" % port, "ok")
                else:
                    self.log("adb reverse 建立失败：%s，改用局域网模式" % (err or out).strip()[:200], "warn")
                    mode = "lan"
            if mode == "lan":
                self.log("局域网模式：设备需能访问 %s:%d；若无数据，请允许 nc 通过防火墙或改用 adb reverse。"
                         % (pc_ip, port), "warn")

            for iid, entry in items:
                if self._net_stop:
                    break
                self._set_net_tree_status(iid, "传输中")
                self._post(self._net_set_status, "正在传输：%s" % entry["name"])
                try:
                    ok, msg = self._net_transfer(entry, outdir, port, mode, pc_ip)
                except Exception as exc:
                    ok, msg = False, "异常：%s" % exc
                if ok:
                    success += 1
                    self._set_net_tree_status(iid, "完成")
                    self.log("  %s 传输完成：%s" % (entry["name"], msg), "ok")
                else:
                    failed += 1
                    self._set_net_tree_status(iid, "失败")
                    self.log("  %s 传输失败：%s" % (entry["name"], msg), "error")
        finally:
            if reverse_added:
                self.adb(["reverse", "--remove", "tcp:%d" % port], timeout=15)
                self.log("已移除 adb reverse tcp:%d" % port)
            self._net_listener = None
            self._net_sender = None
            self._post(self._net_finish_ui, success, failed, len(items))

    def _net_finish_ui(self, success, failed, total):
        self._net_running = False
        self.net_progress.stop()
        self.net_start_btn.config(state="normal")
        self.net_stop_btn.config(state="disabled")
        self._net_set_status("网络传输结束：成功 %d，失败 %d，共 %d" % (success, failed, total))
        self.set_status("Netcat 传输结束：成功 %d，失败 %d" % (success, failed))
        self.log("Netcat 传输结束：成功 %d，失败 %d，共 %d。" % (success, failed, total), "ok" if failed == 0 else "warn")
        if failed:
            messagebox.showwarning("传输完成（有失败）", "成功 %d 个，失败 %d 个。\n请查看日志与分区状态。" % (success, failed))
        else:
            messagebox.showinfo("传输完成", "全部 %d 个分区传输成功。\n目录：%s" % (success, self._net_dir()))

    def _net_transfer(self, entry, outdir, port, mode, pc_ip):
        name = sanitize_name(entry["name"])
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(outdir, "backup_%s_%s" % (name, stamp))
        counter = 1
        while os.path.exists(base + ".bin") or os.path.exists(base + ".bin.gz"):
            base = os.path.join(outdir, "backup_%s_%s_%d" % (name, stamp, counter))
            counter += 1
        part_path = base + ".bin.gz.part"
        address = "127.0.0.1" if mode == "reverse" else pc_ip

        last_error = "未知错误"
        for use_gzip in (True, False):
            if self._net_stop:
                return False, "已取消"
            if not use_gzip:
                self.log("  改用不压缩直传重试…", "warn")
            ok, msg, size = self._net_once(entry["path"], part_path, port, address, use_gzip)
            if ok and size > 0:
                if is_gzip_file(part_path):
                    final = base + ".bin.gz"
                else:
                    final = base + ".bin"
                try:
                    os.replace(part_path, final)
                except OSError as exc:
                    self._remove_file(part_path)
                    return False, "重命名失败：%s" % exc
                if use_gzip and not final.endswith(".gz"):
                    self.log("  设备未产生 gzip 数据，已按未压缩镜像保存。", "warn")
                return True, "接收 %s -> %s" % (human_size(size), final)
            last_error = msg
            self._remove_file(part_path)
            if self._net_stop:
                return False, "已取消"
        return False, last_error

    @staticmethod
    def _netcat_listen_patterns(exe, port):
        base = os.path.basename(exe).lower()
        if base.startswith("ncat"):
            return [["-l", str(port)]]
        return [["-l", "-p", str(port)], ["-l", str(port)], ["-lp", str(port)]]

    def _net_once(self, remote_path, part_path, port, address, use_gzip):
        exe = self.nc_path
        if not exe or not os.path.isfile(exe):
            return False, "未找到 nc 可执行文件", 0

        listener = None
        out_handle = None
        err_handle = None
        listener_log_fd, listener_log = tempfile.mkstemp(prefix="adbtool_nc_")
        os.close(listener_log_fd)
        listener_error = ""
        for pattern in self._netcat_listen_patterns(exe, port):
            if self._net_stop:
                self._remove_file(listener_log)
                return False, "已取消", 0
            self._remove_file(part_path)
            try:
                out_handle = open(part_path, "wb")
                err_handle = open(listener_log, "wb")
                listener = subprocess.Popen(
                    [exe] + pattern, stdout=out_handle, stderr=err_handle,
                    stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
            except OSError as exc:
                for handle in (out_handle, err_handle):
                    if handle:
                        handle.close()
                self._remove_file(listener_log)
                return False, "启动 nc 监听失败：%s" % exc, 0
            self._net_listener = listener
            time.sleep(0.6)
            if listener.poll() is None:
                break
            listener_error = self._read_text_tail(listener_log)
            for handle in (out_handle, err_handle):
                if handle:
                    handle.close()
            out_handle = err_handle = None
            listener = None
            self._net_listener = None
            self._remove_file(listener_log)

        if listener is None or listener.poll() is not None:
            self._remove_file(part_path)
            return False, "nc 监听启动失败：%s" % (listener_error or "端口被占用或参数不兼容"), 0

        if self._net_stop:
            if listener.poll() is None:
                listener.terminate()
            for handle in (out_handle, err_handle):
                if handle:
                    handle.close()
            self._net_listener = None
            self._remove_file(part_path)
            self._remove_file(listener_log)
            return False, "已取消", 0

        send_log_fd, send_log = tempfile.mkstemp(prefix="adbtool_send_")
        os.close(send_log_fd)
        send_handle = None
        sender = None
        command = self._net_remote_command(remote_path, address, port, use_gzip)
        self.log("  设备命令：adb shell %s" % command)
        try:
            send_handle = open(send_log, "wb")
            sender = subprocess.Popen(
                self._adb_cmd(["shell", command]), stdout=send_handle, stderr=send_handle,
                stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
            self._net_sender = sender
        except OSError as exc:
            if send_handle:
                send_handle.close()
            self._remove_file(send_log)
            if listener.poll() is None:
                listener.terminate()
            for handle in (out_handle, err_handle):
                if handle:
                    handle.close()
            self._remove_file(listener_log)
            return False, "启动设备发送命令失败：%s" % exc, 0

        last_size = -1
        last_change = time.time()
        while sender.poll() is None:
            if self._net_stop:
                try:
                    sender.terminate()
                except OSError:
                    pass
                break
            try:
                size = os.path.getsize(part_path)
            except OSError:
                size = 0
            if size != last_size:
                last_size = size
                last_change = time.time()
            elif time.time() - last_change > 1800:
                try:
                    sender.terminate()
                except OSError:
                    pass
                break
            if size > 0:
                self._post(self._net_set_status, "正在接收：%s（已接收 %s）"
                           % (os.path.basename(part_path), human_size(size)))
            time.sleep(0.3)

        try:
            sender.wait(timeout=15)
        except subprocess.TimeoutExpired:
            sender.kill()
            sender.wait(timeout=5)

        deadline = time.time() + 30
        while listener.poll() is None and time.time() < deadline:
            if self._net_stop:
                break
            time.sleep(0.2)
        if listener.poll() is None:
            try:
                listener.terminate()
            except OSError:
                pass
            try:
                listener.wait(timeout=5)
            except subprocess.TimeoutExpired:
                listener.kill()

        for handle in (out_handle, err_handle, send_handle):
            if handle:
                handle.close()
        self._net_listener = None
        self._net_sender = None

        try:
            size = os.path.getsize(part_path)
        except OSError:
            size = 0
        send_error = self._read_text_tail(send_log)
        nc_error = self._read_text_tail(listener_log)
        self._remove_file(send_log)
        self._remove_file(listener_log)

        if self._net_stop:
            return False, "已取消", size
        if size == 0:
            detail = (send_error + " " + nc_error).strip()
            return False, "未收到数据：%s" % (detail[:400] or "设备端 nc/gzip 不可用或无法连接 PC"), 0
        return True, "收到 %s" % human_size(size), size

    def _net_remote_command(self, remote_path, address, port, use_gzip):
        dd = "dd if=%s bs=1M 2>/dev/null" % shlex.quote(remote_path)
        if use_gzip:
            inner = "%s | gzip -1 | nc %s %d" % (dd, address, port)
        else:
            inner = "%s | nc %s %d" % (dd, address, port)
        if self.root_mode == "su":
            inner = "su -c " + shlex.quote(inner)
        return inner

    def _read_text_tail(self, path, limit=800):
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                if size > limit:
                    f.seek(size - limit)
                return f.read().decode("utf-8", "replace").strip()
        except OSError:
            return ""

    # ------------------------------------------------------------------
    # 8. ADB 环境检测与安装
    # ------------------------------------------------------------------
    def _build_adb_env_tab(self):
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="8. ADB 环境")

        det = ttk.LabelFrame(tab, text="8-1 ADB 环境检测", padding=6)
        det.pack(fill="both", expand=True, pady=(0, 6))
        bar = ttk.Frame(det)
        bar.pack(fill="x")
        ttk.Button(bar, text="扫描 ADB 环境", command=self.scan_adb_env).pack(side="left")
        ttk.Button(bar, text="复制信息", command=lambda: self.copy_widget(self.adb_env_text)).pack(side="left", padx=6)
        self.adb_env_status = ttk.Label(bar, text="点击“扫描 ADB 环境”查看 adb / platform-tools / PATH 状态")
        self.adb_env_status.pack(side="left", padx=8)
        self.adb_env_text = scrolledtext.ScrolledText(det, wrap="none", height=12, font=("Consolas", 9))
        self.adb_env_text.pack(fill="both", expand=True, pady=(4, 0))
        self.adb_env_text.insert("1.0", "尚未检测。\n")
        self.adb_env_text.config(state="disabled")

        inst = ttk.LabelFrame(tab, text="8-2 ADB 环境下载与安装", padding=6)
        inst.pack(fill="x")
        row1 = ttk.Frame(inst)
        row1.pack(fill="x")
        self.adb_dl_btn = ttk.Button(row1, text="一键下载安装 platform-tools", command=self.download_platform_tools)
        self.adb_dl_btn.pack(side="left")
        ttk.Button(row1, text="打开 android-docs 下载页", command=self.open_adb_docs_page).pack(side="left", padx=6)
        ttk.Button(row1, text="打开 123 网盘下载页", command=self.open_123pan_page).pack(side="left")
        row2 = ttk.Frame(inst)
        row2.pack(fill="x", pady=(4, 0))
        ttk.Button(row2, text="选择 platform-tools 并配置 PATH", command=self.select_platform_tools).pack(side="left")
        ttk.Button(row2, text="一键配置 PATH", command=self.configure_adb_path).pack(side="left", padx=6)
        ttk.Label(
            inst,
            text=("自动下载优先解析 android-docs 页面中的 Windows 压缩包，失败时回退 Google 官方地址；"
                  "123 网盘分享页提取码：%s（通常需在浏览器中手动下载）。" % ADB_123PAN_PWD),
            wraplength=900, justify="left",
        ).pack(anchor="w", pady=(6, 0))

    def scan_adb_env(self):
        self.adb_env_status.config(text="正在检测 ADB 环境…")
        threading.Thread(target=self._scan_adb_env_worker, daemon=True).start()

    def _scan_adb_env_worker(self):
        try:
            lines = [
                "================ ADB 环境检测 ================",
                "检测时间 : %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "",
            ]
            exe = self._adb_executable()
            exists = bool(exe and os.path.isfile(exe))
            lines.append("当前 ADB 路径 : %s" % (exe or "未找到"))
            lines.append("可执行状态    : %s" % ("正常" if exists else "不存在或不可用"))
            if exists:
                folder = os.path.dirname(exe)
                lines.append("所在目录      : %s" % folder)
                lines.append("PATH 环境变量 : %s" % ("已包含该目录" if path_has_folder(folder) else "未包含该目录"))
                rc, out, err = self.adb(["version"], timeout=15, use_serial=False)
                version = (out or err).strip()
                lines.append("ADB 版本      : %s" % (version.splitlines()[0] if version else "读取失败"))
            else:
                lines.append("ADB 版本      : 未安装或无法执行")
            which = shutil.which("adb")
            lines.append("PATH 中的 adb : %s" % (which or "未找到"))
            lines.append("")
            lines.append("---------------- 候选安装位置 ----------------")
            localapp = os.environ.get("LOCALAPPDATA", "")
            candidates = [
                os.path.join(platform_tools_dir(), "adb.exe"),
                os.path.join(localapp, "Android", "Sdk", "platform-tools", "adb.exe") if localapp else "",
                "C:\\platform-tools\\adb.exe",
                "C:\\adb\\adb.exe",
                os.path.join(os.path.dirname(os.path.abspath(
                    sys.executable if getattr(sys, "frozen", False) else __file__)), "adb.exe"),
                find_adb(),
            ]
            for path in candidates:
                if not path:
                    continue
                lines.append("[%s] %s" % ("存在" if os.path.isfile(path) else "缺失", path))
            lines.append("")
            lines.append("---------------- PATH 中相关目录 ----------------")
            related = [p for p in os.environ.get("PATH", "").split(os.pathsep)
                       if p and ("platform-tools" in p.lower() or p.lower().endswith("\\adb"))]
            lines.append("；".join(related) if related else "（无）")
            lines.append("")
            lines.append("---------------- 设备连接 ----------------")
            if exists:
                rc, out, err = self.adb(["devices", "-l"], timeout=25, use_serial=False)
                lines.append((out or err).strip() or "（无输出）")
            else:
                lines.append("（ADB 不可用，跳过设备检测）")
            lines.append("")
            lines.append("提示：安装或修改 PATH 后，建议重启本工具或重新打开 CMD 使环境变量生效。")
            text = "\n".join(lines)
        except Exception as exc:
            text = "ADB 环境检测失败：%s" % exc
        self._post(self._apply_adb_env, text)

    def _apply_adb_env(self, text):
        self._set_text(self.adb_env_text, text)
        self.adb_env_status.config(text="ADB 环境检测完成")
        self.log("ADB 环境检测完成", "ok")

    def open_adb_docs_page(self):
        webbrowser.open(ADB_DOCS_PAGE)
        self.log("已打开 platform-tools 下载页：%s" % ADB_DOCS_PAGE)

    def open_123pan_page(self):
        webbrowser.open(ADB_123PAN_PAGE)
        self.log("已打开 123 网盘分享页，提取码：%s" % ADB_123PAN_PWD)

    def configure_adb_path(self):
        exe = self._adb_executable()
        if not exe or not os.path.isfile(exe):
            exe = find_adb()
        if not exe or not os.path.isfile(exe):
            if messagebox.askyesno("未找到 ADB", "未检测到 adb.exe，是否打开下载页面？"):
                self.open_adb_docs_page()
            return
        folder = os.path.dirname(exe)
        ok, msg = add_to_user_path(folder)
        self.adb_path_var.set(exe)
        self.adb_exe = exe
        self.exec_out_ok = None
        self.log(msg, "ok" if ok else "error")
        if ok:
            messagebox.showinfo("PATH 已配置", "ADB 目录已加入用户 PATH：\n%s\n\n%s" % (folder, msg))
        else:
            messagebox.showerror("PATH 配置失败", msg)
        self.refresh_devices()

    def select_platform_tools(self):
        folder = filedialog.askdirectory(title="选择 platform-tools 目录")
        if not folder:
            return
        exe_name = "adb.exe" if os.name == "nt" else "adb"
        exe = os.path.join(folder, exe_name)
        if not os.path.isfile(exe):
            inner = os.path.join(folder, "platform-tools", exe_name)
            if os.path.isfile(inner):
                folder, exe = os.path.dirname(inner), inner
        if not os.path.isfile(exe):
            messagebox.showerror("未找到 adb", "所选目录中没有 %s：\n%s" % (exe_name, folder))
            return
        self.adb_path_var.set(exe)
        self.adb_exe = exe
        self.exec_out_ok = None
        ok, msg = add_to_user_path(os.path.dirname(exe))
        self.log("已选择 ADB：%s" % exe, "ok")
        self.log(msg, "ok" if ok else "warn")
        self.adb_env_status.config(text="已选择 ADB：%s" % exe)
        self.scan_adb_env()
        self.refresh_devices()

    def download_platform_tools(self):
        if os.name != "nt":
            messagebox.showinfo("提示", "自动安装仅支持 Windows，请在浏览器中手动下载。")
            self.open_adb_docs_page()
            return
        if self._adb_downloading:
            return
        if not messagebox.askyesno(
                "下载 platform-tools",
                "将下载 Android platform-tools（Windows 压缩包），解压安装到：\n%s\n"
                "并自动写入用户 PATH。\n\n是否继续？" % platform_tools_dir()):
            return
        self._adb_downloading = True
        self.adb_dl_btn.config(state="disabled")
        self.adb_env_status.config(text="正在下载 platform-tools…")
        threading.Thread(target=self._download_platform_tools_worker, daemon=True).start()

    def _resolve_platform_tools_urls(self):
        urls = []
        try:
            req = urllib.request.Request(ADB_DOCS_PAGE, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                html = resp.read().decode("utf-8", "replace")
            for match in re.finditer(r'''href\s*=\s*["']([^"']+\.zip[^"']*)["']''', html, re.I):
                url = match.group(1)
                if "platform-tools" in url.lower() and "windows" in url.lower():
                    urls.append(urljoin(ADB_DOCS_PAGE, url))
        except Exception as exc:
            self._post(self.log, "读取 android-docs 页面失败：%s" % exc, "warn")
        urls.extend([
            "https://android-docs.cn/tools/releases/platform-tools/platform-tools-latest-windows.zip",
            "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
        ])
        unique = []
        for url in urls:
            if url not in unique:
                unique.append(url)
        return unique

    def _download_platform_tools_worker(self):
        temp_dir = tempfile.mkdtemp(prefix="adbtool_platform_tools_")
        try:
            urls = self._resolve_platform_tools_urls()
            zip_path = os.path.join(temp_dir, "platform-tools.zip")
            last_error = None
            downloaded = False
            for url in urls:
                self._post(self.log, "正在下载 platform-tools：%s" % url)
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=120) as resp, open(zip_path, "wb") as f:
                        shutil.copyfileobj(resp, f)
                    if os.path.getsize(zip_path) < 1024 * 1024:
                        raise RuntimeError("下载文件过小，可能不是有效压缩包")
                    downloaded = True
                    break
                except Exception as exc:
                    last_error = exc
                    self._post(self.log, "下载失败：%s" % exc, "warn")
            if not downloaded:
                raise RuntimeError("所有下载地址均失败：%s" % last_error)

            extract_dir = os.path.join(temp_dir, "extract")
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                if not any(n.lower().endswith("adb.exe") for n in names):
                    raise RuntimeError("压缩包中未找到 adb.exe")
                zf.extractall(extract_dir)

            source_dir = None
            for root, dirs, files in os.walk(extract_dir):
                if "adb.exe" in files:
                    source_dir = root
                    break
            if not source_dir:
                raise RuntimeError("解压后未找到 adb.exe")

            dest_dir = platform_tools_dir()
            os.makedirs(dest_dir, exist_ok=True)
            shutil.copytree(source_dir, dest_dir, dirs_exist_ok=True)
            exe = os.path.join(dest_dir, "adb.exe")
            if not os.path.isfile(exe):
                raise RuntimeError("安装后未找到 %s" % exe)
        except Exception as exc:
            self._post(self.log, "platform-tools 安装失败：%s" % exc, "error")
            self._post(messagebox.showerror, "安装失败",
                       "自动下载安装失败：%s\n\n请点击“打开 android-docs 下载页”或“打开 123 网盘下载页”手动下载，"
                       "再点击“选择 platform-tools 并配置 PATH”。" % exc)
            self._post(self._set_adb_dl_state, False)
            return
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        ok, path_msg = add_to_user_path(dest_dir)
        self._post(self._apply_platform_tools_installed, exe, ok, path_msg)

    def _set_adb_dl_state(self, running):
        self._adb_downloading = running
        self.adb_dl_btn.config(state="disabled" if running else "normal")

    def _apply_platform_tools_installed(self, exe, path_ok, path_msg):
        self._set_adb_dl_state(False)
        self.adb_path_var.set(exe)
        self.adb_exe = exe
        self.exec_out_ok = None
        self.adb_env_status.config(text="platform-tools 已安装：%s" % exe)
        self.log("platform-tools 已安装：%s" % exe, "ok")
        self.log(path_msg, "ok" if path_ok else "warn")
        messagebox.showinfo("安装完成",
                            "platform-tools 已安装到：\n%s\n\n%s\n\nADB 路径已切换到该版本。"
                            % (exe, path_msg))
        self.scan_adb_env()
        self.refresh_devices()

    # ------------------------------------------------------------------
    # 基础 UI 操作
    # ------------------------------------------------------------------
    def _set_text(self, widget, content):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content or "")
        widget.config(state="disabled")

    def copy_widget(self, widget):
        try:
            content = widget.get("1.0", "end-1c")
        except tk.TclError:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.set_status("已复制到剪贴板（%d 字符）" % len(content))

    def _clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def copy_log(self):
        content = self.log_text.get("1.0", "end-1c")
        if not content.strip():
            self.set_status("日志为空，无需复制")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.set_status("日志已复制到剪贴板（%d 字符）" % len(content))
        self.log("日志已复制到剪贴板")

    def export_log(self):
        content = self.log_text.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showinfo("日志为空", "当前没有可导出的日志。")
            return
        default = "adb_backup_log_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="导出日志", defaultextension=".txt", initialfile=default,
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig") as f:
                f.write(content)
            self.log("日志已导出：%s" % path, "ok")
            self.set_status("日志已导出")
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))

    def _poll_log(self):
        try:
            while True:
                msg, level = self.log_queue.get_nowait()
                self.log_text.config(state="normal")
                self.log_text.insert("end", msg + "\n", level if level != "info" else ())
                self.log_text.see("end")
                self.log_text.config(state="disabled")
        except queue.Empty:
            pass
        try:
            self.root.after(120, self._poll_log)
        except tk.TclError:
            pass

    def log(self, msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put(("[%s] %s" % (ts, msg), level))

    def set_status(self, text):
        try:
            self.status_label.config(text=text)
        except tk.TclError:
            pass

    def _post(self, func, *args, **kwargs):
        try:
            self.root.after(0, lambda: func(*args, **kwargs))
        except tk.TclError:
            pass

    def _browse_adb(self):
        path = filedialog.askopenfilename(title="选择 adb.exe", filetypes=[("adb", "adb.exe"), ("所有文件", "*.*")])
        if path:
            self.adb_path_var.set(path)
            self.adb_exe = path
            self.exec_out_ok = None
            self.log("ADB 路径已切换为：%s" % path)
            self.refresh_devices()

    # ------------------------------------------------------------------
    # ADB 基础调用
    # ------------------------------------------------------------------
    def _adb_executable(self):
        return self.adb_path_var.get().strip() or self.adb_exe

    def _adb_cmd(self, args, use_serial=True):
        cmd = [self._adb_executable()]
        serial = self.serial_var.get().strip()
        if use_serial and serial:
            cmd += ["-s", serial]
        cmd += args
        return cmd

    def adb(self, args, timeout=60, use_serial=True, binary=False):
        if not self._adb_executable():
            return 1, (b"" if binary else ""), "未找到 adb，可执行文件不存在"
        cmd = self._adb_cmd(args, use_serial=use_serial)
        try:
            p = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                creationflags=CREATE_NO_WINDOW,
            )
        except subprocess.TimeoutExpired:
            return 124, (b"" if binary else ""), "命令超时（%s 秒）" % timeout
        except OSError as exc:
            return 1, (b"" if binary else ""), str(exc)
        out = p.stdout if binary else p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        return p.returncode, out, err

    def _shell(self, command, timeout=60):
        return self.adb(["shell", command], timeout=timeout)

    def _check_adb(self):
        exe = self._adb_executable()
        if not exe or not os.path.isfile(exe):
            messagebox.showerror("未找到 adb", "请点击“浏览…”选择 adb.exe 的路径。")
            return False
        self.adb_exe = exe
        return True

    def _check_device(self):
        if not self._check_adb():
            return False
        if not self.serial_var.get().strip():
            messagebox.showwarning("未选择设备", "请先刷新设备并选择一个已连接设备。")
            return False
        return True

    def detect_root(self):
        rc, out, _ = self._shell("id", timeout=12)
        if "uid=0" in out:
            self.root_mode = "adbd"
            return "adbd"
        rc, out, _ = self._shell("su -c id", timeout=12)
        if "uid=0" in out:
            self.root_mode = "su"
            return "su"
        self.root_mode = "none"
        return "none"

    def _detect_capabilities(self):
        rc, out, err = self.adb(["exec-out", "echo", "ok"], timeout=10)
        self.exec_out_ok = (rc == 0 and "ok" in out and "Android Debug Bridge" not in out)
        if self.exec_out_ok:
            self.log("ADB 支持 exec-out，可作为 adb pull 失败后的直读兜底。", "ok")
        else:
            self.log("当前 ADB 不支持 exec-out（版本较旧），备份将以 adb pull 直出为主，失败时使用 PTY raw 直读。", "warn")
            self.log("建议换用新版 platform-tools 的 adb，可显著提升大分区备份稳定性。", "warn")
        return self.exec_out_ok

    # ------------------------------------------------------------------
    # 设备识别
    # ------------------------------------------------------------------
    def refresh_devices(self):
        if not self._check_adb():
            return
        self.exec_out_ok = None
        self.set_status("正在刷新设备列表…")
        threading.Thread(target=self._refresh_devices_worker, daemon=True).start()

    def _refresh_devices_worker(self):
        rc, out, err = self.adb(["devices", "-l"], timeout=25, use_serial=False)
        if rc != 0:
            self.log("adb devices 执行失败：%s" % (err or out).strip(), "error")
            self._post(self.set_status, "刷新设备失败")
            return
        devices = []
        lines = out.splitlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            model = ""
            for token in parts[2:]:
                if token.startswith("model:"):
                    model = token[6:].replace("_", " ")
            devices.append({"serial": serial, "state": state, "model": model})
        self._post(self._apply_devices, devices, out)

    def _apply_devices(self, devices, raw):
        self.device_map = {}
        values = []
        for dev in devices:
            display = "%s  [%s]  %s" % (dev["serial"], dev["state"], dev["model"] or "未知型号")
            values.append(display)
            self.device_map[display] = dev["serial"]
        self.device_combo["values"] = values
        self.log("检测到 %d 个设备。%s" % (len(devices), "有设备处于未授权/离线状态。" if any(d["state"] != "device" for d in devices) else ""))

        current_serial = self.serial_var.get().strip()
        selected = ""
        for display in values:
            if self.device_map.get(display) == current_serial:
                selected = display
                break
        if not selected and values:
            for display in values:
                if "[device]" in display:
                    selected = display
                    break
            if not selected:
                selected = values[0]
        if selected:
            self.device_combo.set(selected)
            self.serial_var.set(self.device_map.get(selected, ""))
            self.conn_label.config(text="已连接：%s" % self.serial_var.get(), foreground="#2e7d32")
            self.set_status("设备已就绪：%s" % self.serial_var.get())
            self.query_device_info()
        else:
            self.device_combo.set("")
            self.serial_var.set("")
            self.conn_label.config(text="未连接", foreground="#b71c1c")
            self.set_status("未检测到设备")

    def _on_device_selected(self, event=None):
        display = self.device_combo.get()
        serial = self.device_map.get(display, "")
        if serial == self.serial_var.get():
            return
        self.serial_var.set(serial)
        self.device_folder = ""
        self.device_model = ""
        self.partitions = []
        self.block_devices = []
        self.partition_tree.delete(*self.partition_tree.get_children())
        self.backup_tree.delete(*self.backup_tree.get_children())
        self.backup_items.clear()
        self.fw_combo["values"] = []
        self.fw_map.clear()
        self.net_tree.delete(*self.net_tree.get_children())
        self.net_items.clear()
        self.net_selection_label.config(text="已选：0")
        self.partition_status_label.config(text="分区数：0")
        self.backup_selection_label.config(text="已选：0")
        self.conn_label.config(text="已连接：%s" % serial if serial else "未连接", foreground="#2e7d32" if serial else "#b71c1c")
        self.log("已选择设备：%s" % serial)
        if serial:
            self.query_device_info()

    def query_device_info(self):
        if not self._check_device():
            return
        threading.Thread(target=self._query_device_info_worker, daemon=True).start()

    def _query_device_info_worker(self):
        serial = self.serial_var.get().strip()
        self._post(self.set_status, "正在读取设备信息…")
        self._detect_capabilities()

        rc, dev_list, _ = self.adb(["devices", "-l"], timeout=20, use_serial=False)
        rc_ver, ver, _ = self.adb(["version"], timeout=10, use_serial=False)

        rc_prop, prop_out, prop_err = self._shell("getprop", timeout=30)
        props = {}
        for line in prop_out.splitlines():
            m = re.match(r"\[(.*?)\]: \[(.*?)\]", line)
            if m:
                props[m.group(1)] = m.group(2)

        keys = [
            ("ro.product.manufacturer", "品牌"),
            ("ro.product.model", "型号"),
            ("ro.product.device", "设备代号"),
            ("ro.serialno", "序列号"),
            ("ro.build.version.release", "Android 版本"),
            ("ro.build.version.sdk", "SDK 版本"),
            ("ro.build.type", "构建类型"),
            ("ro.build.tags", "构建标签"),
            ("ro.board.platform", "平台"),
            ("ro.product.cpu.abi", "CPU 架构"),
            ("ro.build.fingerprint", "系统指纹"),
        ]
        model = props.get("ro.product.model") or props.get("ro.product.device") or ""
        folder = sanitize_name(model or serial)

        lines = []
        lines.append("================ ADB 硬件识别 ================")
        lines.append("ADB 路径       : %s" % self.adb_exe)
        lines.append("ADB 版本       : %s" % (ver.strip().splitlines()[0] if ver.strip() else "未知"))
        lines.append("当前设备序列号 : %s" % serial)
        lines.append("备份传输方式   : adb pull 直出到 PC（失败时回退 %s）" % ("exec-out" if self.exec_out_ok else "PTY raw 直读"))
        lines.append("")
        lines.append("---------------- adb devices -l ----------------")
        lines.append(dev_list.strip() or "（无输出）")
        lines.append("")
        lines.append("---------------- 设备属性 ----------------")
        for key, title in keys:
            lines.append("%-10s: %s" % (title, props.get(key, "未知")))
        lines.append("")
        lines.append("---------------- 内核信息 ----------------")
        rc_uname, uname, _ = self._shell("uname -a", timeout=15)
        lines.append(uname.strip() or "（读取失败）")
        lines.append("")
        lines.append("---------------- 存储空间 ----------------")
        rc_df, df_out, _ = self._shell("df -h", timeout=20)
        lines.append(df_out.strip() or (prop_err.strip() if prop_err.strip() else "（读取失败）"))
        if rc_prop != 0:
            lines.append("getprop 错误：%s" % prop_err.strip())

        self._post(self._apply_device_info, "\n".join(lines), model, folder, props)

    def _apply_device_info(self, text, model, folder, props):
        self._set_text(self.device_info_text, text)
        self.device_model = model
        self.device_folder = folder
        self.refresh_dest_labels()
        self.set_status("设备信息读取完成：%s" % (model or self.serial_var.get()))
        self.log("设备信息读取完成，设备名：%s" % folder, "ok")
        build_type = props.get("ro.build.type", "")
        if build_type:
            self.log("构建类型：%s（user 版本通常无法直接用 adb root，可尝试 su）" % build_type)

    def export_device_info(self):
        content = self.device_info_text.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showinfo("无内容", "请先查询设备信息。")
            return
        default = "device_info_%s_%s.txt" % (self.serial_var.get() or "device", datetime.now().strftime("%Y%m%d_%H%M%S"))
        path = filedialog.asksaveasfilename(title="导出设备信息", defaultextension=".txt", initialfile=default,
                                            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.log("设备信息已导出：%s" % path, "ok")
            self.set_status("已导出设备信息")
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))

    # ------------------------------------------------------------------
    # 分区查询
    # ------------------------------------------------------------------
    def query_partitions(self):
        if not self._check_device():
            return
        self.set_status("正在查询分区信息…")
        self.log("开始查询分区信息…")
        threading.Thread(target=self._query_partitions_worker, daemon=True).start()

    def _query_partitions_worker(self):
        rc_mtd, mtd_out, mtd_err = self._shell("cat /proc/mtd", timeout=20)
        if rc_mtd != 0 and not mtd_out.strip():
            mtd_out = "（该设备没有 /proc/mtd 或读取失败）\n%s" % mtd_err.strip()

        rc_dev, dev_out, dev_err = self._shell("ls -la /dev", timeout=25)
        if rc_dev != 0 and not dev_out.strip():
            dev_out = "（ls /dev 失败）\n%s" % dev_err.strip()

        block_script = (
            "ls -l /dev/block/by-name 2>/dev/null; "
            "ls -l /dev/block/platform/*/by-name 2>/dev/null; "
            "ls -l /dev/block 2>/dev/null"
        )
        rc_block, block_out, _ = self._shell(block_script, timeout=25)

        rc_parts, parts_out, _ = self._shell("cat /proc/partitions", timeout=20)
        if rc_parts != 0 and not parts_out.strip():
            parts_out = "（读取失败）"

        rc_df, df_out, _ = self._shell("df -h", timeout=20)
        if rc_df != 0 and not df_out.strip():
            df_out = "（df 执行失败）"

        rc_mtddir, mtddir_out, _ = self._shell("ls /dev/mtd", timeout=15)
        mtd_dir_exists = rc_mtddir == 0 and "mtd" in mtddir_out

        entries, parts_map, block_devices = parse_partition_table(mtd_out, parts_out, block_out, mtd_dir_exists)

        self._post(self._apply_partitions, entries, parts_map, block_devices, mtd_out, dev_out, parts_out, df_out, block_out)

    def _apply_partitions(self, entries, parts_map, block_devices, mtd_out, dev_out, parts_out, df_out, block_out):
        self.partitions = entries
        self.parts_map = parts_map
        self.block_devices = block_devices

        self._set_text(self.raw_texts["mtd"], mtd_out)
        self._set_text(self.raw_texts["dev"], dev_out)
        self._set_text(self.raw_texts["parts"], parts_out)
        self._set_text(self.raw_texts["df"], df_out)

        self.partition_tree.delete(*self.partition_tree.get_children())
        for entry in entries:
            self.partition_tree.insert("", "end", values=(
                entry["name"], entry["type"], human_size(entry["size"]), entry["path"]
            ))
        self.partition_status_label.config(text="分区数：%d" % len(entries))

        self.backup_tree.delete(*self.backup_tree.get_children())
        self.backup_items.clear()
        for idx, entry in enumerate(entries):
            iid = "p%d" % idx
            self.backup_items[iid] = entry
            self.backup_tree.insert("", "end", iid=iid, values=(
                entry["name"], entry["type"], human_size(entry["size"]), entry["path"], "待备份"
            ))

        self._apply_firmware_devices(block_devices, parts_out)
        self._fill_net_tree(entries)
        self.set_status("分区查询完成，共 %d 个分区" % len(entries))
        self.log("分区查询完成：%d 个分区，%d 个整盘设备。" % (len(entries), len(block_devices)), "ok")

    def copy_partition_table(self):
        if not self.partitions:
            messagebox.showinfo("无数据", "请先查询分区信息。")
            return
        text = self._partition_table_text()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status("分区表已复制到剪贴板")

    def _partition_table_text(self):
        lines = []
        lines.append("ADB 分区表")
        lines.append("生成时间：%s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        lines.append("设备序列号：%s" % self.serial_var.get())
        lines.append("设备名称：%s" % (self.device_model or self.serial_var.get()))
        lines.append("")
        lines.append("%-28s %-6s %-12s %-10s %s" % ("分区名", "类型", "大小", "字节", "设备路径"))
        for entry in self.partitions:
            lines.append("%-28s %-6s %-12s %-10s %s" % (
                entry["name"], entry["type"], human_size(entry["size"]),
                entry["size"] if entry["size"] is not None else "-", entry["path"]
            ))
        lines.append("")
        lines.append("================ 原始信息 ================")
        for key, title in [("mtd", "/proc/mtd"), ("dev", "ls /dev"), ("parts", "/proc/partitions"), ("df", "df -h")]:
            lines.append("")
            lines.append("-------- %s --------" % title)
            widget = self.raw_texts.get(key)
            lines.append(widget.get("1.0", "end-1c") if widget else "")
        return "\n".join(lines)

    def export_partition_table(self, fmt):
        if not self.partitions:
            messagebox.showinfo("无数据", "请先查询分区信息。")
            return
        default = "partition_table_%s_%s.%s" % (
            sanitize_name(self.serial_var.get() or "device"),
            datetime.now().strftime("%Y%m%d_%H%M%S"), fmt
        )
        filetypes = [("文本文件", "*.txt")] if fmt == "txt" else [("CSV 文件", "*.csv")]
        path = filedialog.asksaveasfilename(title="导出分区表", defaultextension="." + fmt,
                                            initialfile=default, filetypes=filetypes + [("所有文件", "*.*")])
        if not path:
            return
        try:
            if fmt == "csv":
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["分区名", "类型", "大小", "字节", "设备路径"])
                    for entry in self.partitions:
                        writer.writerow([entry["name"], entry["type"], human_size(entry["size"]),
                                         entry["size"] if entry["size"] is not None else "", entry["path"]])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._partition_table_text())
            self.log("分区表已导出：%s" % path, "ok")
            self.set_status("分区表已导出")
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))

    def _write_partition_table_to_dir(self, target_dir):
        try:
            os.makedirs(target_dir, exist_ok=True)
            path = os.path.join(target_dir, "分区表.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._partition_table_text())
            self.log("分区表已随备份保存：%s" % path)
        except OSError as exc:
            self.log("保存分区表失败：%s" % exc, "warn")

    # ------------------------------------------------------------------
    # 磁盘与目录
    # ------------------------------------------------------------------
    def pick_output_root(self):
        if os.name == "nt":
            for letter in ("F", "E", "D"):
                root = "%s:\\" % letter
                if not os.path.exists(root):
                    continue
                if self._is_writable_root(root):
                    return root
            return None

        candidates = [os.path.join(os.path.expanduser("~"), "ADB备份")]
        user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
        bases = ["/mnt"]
        if user:
            bases.insert(0, "/run/media/%s" % user)
            bases.insert(0, "/media/%s" % user)
        for base in bases:
            try:
                for name in sorted(os.listdir(base)):
                    path = os.path.join(base, name)
                    if os.path.isdir(path) and os.access(path, os.W_OK):
                        candidates.append(path)
            except OSError:
                pass
        for root in candidates:
            if self._is_writable_root(root):
                return root
        return None

    @staticmethod
    def _is_writable_root(root):
        test_dir = os.path.join(root, ".adbtool_write_test_%d" % os.getpid())
        try:
            os.makedirs(test_dir, exist_ok=True)
            os.rmdir(test_dir)
            return True
        except OSError:
            return False

    def _device_folder_name(self):
        if not self.device_folder:
            self.device_folder = sanitize_name(self.device_model or self.serial_var.get() or "unknown_device")
        return self.device_folder

    def _backup_dir(self):
        root = self.pick_output_root()
        if not root:
            return None
        return os.path.join(root, self._device_folder_name(), "分区备份")

    def _firmware_dir(self):
        root = self.pick_output_root()
        if not root:
            return None
        return os.path.join(root, self._device_folder_name(), "编程器固件")

    def refresh_dest_labels(self):
        root = self.pick_output_root()
        folder = self._device_folder_name()
        if root:
            self.backup_drive_label.config(text="输出磁盘：%s    设备文件夹：%s    分区目录：%s" % (
                root, folder, os.path.join(root, folder, "分区备份")))
        else:
            self.backup_drive_label.config(text="未检测到可写的 D/E/F 盘，请插入存储卡或检查盘符。")

        if root:
            fw_dev = self.fw_combo.get().split(" ")[0].strip() if self.fw_combo.get() else "flash"
            self.fw_dir_label.config(text="固件目录：%s    文件名前缀：firmware_%s" % (
                os.path.join(root, folder, "编程器固件"), fw_dev))
        else:
            self.fw_dir_label.config(text="未检测到可写的 D/E/F 盘。")

    def _open_folder(self, path):
        if not path or not os.path.isdir(path):
            messagebox.showinfo("目录不存在", "备份目录尚未创建：%s" % path)
            return
        try:
            if os.name == "nt":
                os.startfile(path)
            else:
                subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        except Exception as exc:
            messagebox.showerror("打开失败", str(exc))

    def open_backup_dir(self):
        path = self._backup_dir()
        self._open_folder(path)

    def open_firmware_dir(self):
        path = self._firmware_dir()
        self._open_folder(path)

    # ------------------------------------------------------------------
    # 备份
    # ------------------------------------------------------------------
    def select_all_partitions(self):
        self.backup_tree.selection_set(self.backup_tree.get_children())
        self._update_backup_selection()

    def clear_partition_selection(self):
        self.backup_tree.selection_remove(self.backup_tree.get_children())
        self._update_backup_selection()

    def _update_backup_selection(self):
        count = len(self.backup_tree.selection())
        self.backup_selection_label.config(text="已选：%d" % count)

    def start_backup(self):
        if not self._check_device():
            return
        if self._backup_running:
            messagebox.showinfo("正在备份", "当前已有备份任务在运行。")
            return
        if not self.partitions:
            messagebox.showinfo("无分区", "请先在“2. 分区查询”中查询分区信息。")
            return
        selection = self.backup_tree.selection()
        if not selection:
            if not messagebox.askyesno("未选择分区", "当前未选择任何分区，是否备份全部分区？"):
                return
            selection = self.backup_tree.get_children()

        mode = self.detect_root()
        if mode == "none":
            if not messagebox.askyesno(
                "权限不足",
                "未检测到 root / su 权限，读取分区数据很可能失败。\n\n"
                "是否仍要继续备份？\n"
                "选择“否”将切换到“5. 权限管理”页，可先执行 5-2 提权。",
            ):
                self.notebook.select(4)
                return

        entries = [(iid, self.backup_items[iid]) for iid in selection if iid in self.backup_items]
        if not entries:
            return

        dest = self._backup_dir()
        if not dest:
            messagebox.showerror("无可用磁盘", "未检测到可写的 F/E/D 盘。请插入存储卡后重试。")
            return
        try:
            os.makedirs(dest, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("创建目录失败", str(exc))
            return

        total_bytes = sum(item[1]["size"] for item in entries if item[1]["size"])
        if total_bytes:
            try:
                free = shutil.disk_usage(os.path.splitdrive(dest)[0] + "\\").free
                if free < total_bytes * 1.05:
                    if not messagebox.askyesno("磁盘空间不足",
                                               "预计需要 %s，目标磁盘可用 %s。\n是否继续？" % (
                                                   human_size(total_bytes), human_size(free))):
                        return
            except OSError:
                pass

        self._write_partition_table_to_dir(os.path.dirname(dest))
        self._backup_running = True
        self._stop_backup = False
        self.backup_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.backup_progress.config(value=0)
        for iid in selection:
            self.backup_tree.set(iid, "status", "等待")
        self.log("开始备份 %d 个分区到：%s" % (len(entries), dest), "ok")
        threading.Thread(target=self._backup_worker, args=(entries, dest), daemon=True).start()

    def stop_backup(self):
        self._stop_backup = True
        self.log("正在停止备份…", "warn")
        for proc in (self._dump_proc,):
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
        self.set_status("正在停止备份…")

    def _set_tree_status(self, iid, text):
        try:
            self.backup_tree.set(iid, "status", text)
        except tk.TclError:
            pass

    def _set_progress(self, bar, value):
        try:
            bar.config(value=value)
        except tk.TclError:
            pass

    def _backup_worker(self, items, dest):
        if self.exec_out_ok is None:
            self._detect_capabilities()
        mode = self.detect_root()
        self.log("当前权限模式：%s" % {"adbd": "adbd 已 root", "su": "su 可用", "none": "普通 shell（无 root）"}[mode],
                 "warn" if mode == "none" else "info")
        if mode == "none":
            self.log("当前没有 root 权限，建议先在“5. 权限管理”执行 5-2 提权，否则多数分区会读取失败。", "error")
        total = len(items)
        success = 0
        failed = 0

        for idx, (iid, entry) in enumerate(items):
            if self._stop_backup:
                break
            display_name = sanitize_name(entry["name"])
            filename = display_name + ".img"
            local_path = os.path.join(dest, filename)
            if os.path.exists(local_path):
                base, ext = os.path.splitext(local_path)
                local_path = "%s_%s%s" % (base, datetime.now().strftime("%H%M%S"), ext)

            self._post(self._set_tree_status, iid, "备份中")
            self._post(self.set_status, "正在备份 %d/%d：%s" % (idx + 1, total, entry["name"]))
            self.log("(%d/%d) 备份 %s -> %s" % (idx + 1, total, entry["name"], local_path))

            def progress_cb(fraction, item_iid=iid, index=idx, t=total):
                if fraction is None:
                    self._post(self._set_tree_status, item_iid, "备份中")
                else:
                    self._post(self._set_tree_status, item_iid, "备份中 %d%%" % int(fraction * 100))
                    self._post(self._set_progress, self.backup_progress, (index + fraction) / t * 100)

            ok, msg = self._dump_partition(entry["path"], local_path, entry["size"], progress_cb)
            if self._stop_backup:
                break
            if ok:
                success += 1
                try:
                    real_size = os.path.getsize(local_path)
                except OSError:
                    real_size = 0
                self._post(self._set_tree_status, iid, "完成 " + human_size(real_size))
                self.log("  成功：%s（%s）" % (filename, msg), "ok")
            else:
                failed += 1
                self._post(self._set_tree_status, iid, "失败")
                self.log("  失败：%s -> %s" % (entry["name"], msg), "error")
            self._post(self._set_progress, self.backup_progress, (idx + 1) / total * 100)

        stopped = self._stop_backup
        self._backup_running = False
        self._stop_backup = False
        self._post(self._finish_backup_ui, success, failed, total, stopped)

    def _finish_backup_ui(self, success, failed, total, stopped):
        self.backup_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if stopped:
            self.backup_progress_label.config(text="已停止：成功 %d / 失败 %d / 共 %d" % (success, failed, total))
            self.set_status("备份已停止")
            self.log("备份已停止：成功 %d，失败 %d。" % (success, failed), "warn")
        else:
            self.backup_progress_label.config(text="完成：成功 %d / 失败 %d / 共 %d" % (success, failed, total))
            self.set_status("分区备份完成")
            self.log("分区备份完成：成功 %d，失败 %d，共 %d。" % (success, failed, total), "ok")
            if failed == 0:
                messagebox.showinfo("备份完成", "全部 %d 个分区备份成功。\n目录：%s" % (success, self._backup_dir()))
            else:
                messagebox.showwarning("备份完成（有失败）", "成功 %d 个，失败 %d 个。\n请查看日志了解失败原因。" % (success, failed))

    # ------------------------------------------------------------------
    # 二进制备份核心
    # ------------------------------------------------------------------
    def _dump_partition(self, remote_path, local_path, expected_size, progress_cb=None):
        part_path = local_path + ".part"
        try:
            if os.path.exists(part_path):
                os.remove(part_path)
        except OSError:
            pass

        attempts = [("adb pull", self._dump_pull)]
        if self.exec_out_ok:
            attempts.append(("exec-out", self._dump_exec_out))
        attempts.append(("PTY raw", self._dump_pty))

        last_error = "未知错误"
        for mode, func in attempts:
            if self._stop_backup:
                break
            self.log("  尝试模式：%s" % mode)
            try:
                ok, msg = func(remote_path, part_path, expected_size, progress_cb)
            except Exception as exc:
                ok, msg = False, "异常：%s" % exc
            if ok:
                try:
                    size = os.path.getsize(part_path)
                except OSError:
                    size = 0
                if not self._size_matches(size, expected_size, mode):
                    last_error = "%s 输出大小异常：%s，预期 %s" % (mode, human_size(size), human_size(expected_size))
                    self.log("  " + last_error, "warn")
                    self._remove_file(part_path)
                    continue
                try:
                    os.replace(part_path, local_path)
                except OSError as exc:
                    return False, "重命名失败：%s" % exc
                return True, "%s 完成，%s" % (mode, human_size(size))
            last_error = msg
            self.log("  模式 %s 失败：%s" % (mode, msg), "warn")
            self._remove_file(part_path)
            if self._stop_backup:
                break

        self._remove_file(part_path)
        if self._stop_backup:
            return False, "已取消"
        return False, last_error

    @staticmethod
    def _size_matches(size, expected, mode):
        if not expected:
            return size > 0
        if mode == "PTY raw":
            return size == expected
        return abs(size - expected) <= 4096

    @staticmethod
    def _remove_file(path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    def _dump_exec_out(self, remote_path, part_path, expected, progress_cb):
        inner = "dd if=%s bs=1048576 2>/dev/null" % shlex.quote(remote_path)
        if self.root_mode == "su":
            inner = "su -c " + shlex.quote(inner)
        return self._dump_stream(["exec-out", inner], part_path, expected, progress_cb, "exec-out")

    def _dump_pty(self, remote_path, part_path, expected, progress_cb):
        inner = "dd if=%s bs=1048576 2>/dev/null" % shlex.quote(remote_path)
        if self.root_mode == "su":
            inner = "su -c " + shlex.quote(inner)
        command = "stty raw -echo 2>/dev/null; " + inner
        return self._dump_stream(["shell", command], part_path, expected, progress_cb, "PTY raw")

    def _dump_stream(self, args, part_path, expected, progress_cb, mode):
        err_fd, err_path = tempfile.mkstemp(prefix="adbtool_err_")
        os.close(err_fd)
        try:
            out_f = open(part_path, "wb")
            err_f = open(err_path, "wb")
        except OSError as exc:
            os.unlink(err_path)
            return False, "创建本地文件失败：%s" % exc

        proc = None
        try:
            proc = subprocess.Popen(
                self._adb_cmd(args),
                stdout=out_f,
                stderr=err_f,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
            self._dump_proc = proc
            last_size = -1
            last_change = time.time()
            while proc.poll() is None:
                if self._stop_backup:
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                    break
                try:
                    size = os.path.getsize(part_path)
                except OSError:
                    size = 0
                if size != last_size:
                    last_size = size
                    last_change = time.time()
                elif time.time() - last_change > 900:
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                    break
                if progress_cb:
                    if expected:
                        progress_cb(min(size / float(expected), 1.0))
                    else:
                        progress_cb(None)
                time.sleep(0.25)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        except OSError as exc:
            out_f.close()
            err_f.close()
            self._remove_file(err_path)
            return False, "启动 adb 失败：%s" % exc
        finally:
            out_f.close()
            err_f.close()
            if self._dump_proc is proc:
                self._dump_proc = None

        try:
            size = os.path.getsize(part_path)
        except OSError:
            size = 0
        try:
            with open(err_path, "rb") as f:
                err_text = f.read(1200).decode("utf-8", "replace").strip()
        except OSError:
            err_text = ""
        self._remove_file(err_path)

        if self._stop_backup:
            return False, "已取消"
        rc = proc.returncode
        if progress_cb and expected:
            progress_cb(min(size / float(expected), 1.0))
        if rc != 0 and size == 0:
            return False, "adb 返回码 %s：%s" % (rc, err_text[:300] or "无输出")
        if size == 0:
            return False, "未读取到数据：%s" % (err_text[:300] or "可能权限不足")
        if rc != 0 and err_text and "records" not in err_text.lower():
            self.log("  %s 返回码 %s，错误输出：%s" % (mode, rc, err_text[:200]), "warn")
        return True, "读取 %s" % human_size(size)

    def _dump_pull(self, remote_path, part_path, expected, progress_cb):
        """直接使用 adb pull 将设备节点输出到 PC，不在设备端产生临时文件。"""
        self._remove_file(part_path)
        fd, log_path = tempfile.mkstemp(prefix="adbtool_pull_")
        os.close(fd)
        log_handle = None
        proc = None
        try:
            log_handle = open(log_path, "wb")
            self.log("  adb pull %s %s" % (remote_path, part_path))
            proc = subprocess.Popen(
                self._adb_cmd(["pull", remote_path, part_path]),
                stdout=log_handle,
                stderr=log_handle,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
        except OSError as exc:
            if log_handle:
                log_handle.close()
            self._remove_file(log_path)
            return False, "启动 adb pull 失败：%s" % exc
        self._dump_proc = proc

        last_size = -1
        last_change = time.time()
        while proc.poll() is None:
            if self._stop_backup:
                try:
                    proc.terminate()
                except OSError:
                    pass
                break
            try:
                size = os.path.getsize(part_path)
            except OSError:
                size = 0
            if size != last_size:
                last_size = size
                last_change = time.time()
            elif time.time() - last_change > 600:
                try:
                    proc.terminate()
                except OSError:
                    pass
                break
            if progress_cb:
                if expected:
                    progress_cb(min(size / float(expected), 1.0))
                elif size > 0:
                    progress_cb(None)
            time.sleep(0.25)

        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        if log_handle:
            log_handle.close()
        self._dump_proc = None

        try:
            size = os.path.getsize(part_path)
        except OSError:
            size = 0
        log_text = ""
        try:
            with open(log_path, "rb") as f:
                try:
                    f.seek(max(0, os.path.getsize(log_path) - 2000))
                except OSError:
                    pass
                log_text = f.read().decode("utf-8", "replace").strip()
        except OSError:
            pass
        self._remove_file(log_path)

        if self._stop_backup:
            return False, "已取消"
        if progress_cb and expected:
            progress_cb(min(size / float(expected), 1.0))
        if size == 0:
            return False, "adb pull 未获取到数据（设备节点可能不支持 pull）：%s" % (log_text[-300:] or "无输出")
        if proc.returncode != 0:
            return False, "adb pull 返回码 %s：%s" % (proc.returncode, log_text[-300:])
        return True, "adb pull 完成，%s" % human_size(size)

    # ------------------------------------------------------------------
    # 编程器固件
    # ------------------------------------------------------------------
    def scan_firmware_devices(self):
        if not self._check_device():
            return
        threading.Thread(target=self._scan_firmware_worker, daemon=True).start()

    def _scan_firmware_worker(self):
        rc, out, _ = self._shell("cat /proc/partitions", timeout=20)
        _, _, block_devices = parse_partition_table("", out, "", False)
        self._post(self._apply_firmware_devices, block_devices, out)

    def _apply_firmware_devices(self, block_devices, raw=""):
        self.fw_map = {}
        values = []
        lines = []
        for dev in block_devices:
            display = "%s  (%s)" % (dev["name"], human_size(dev["size"]))
            values.append(display)
            self.fw_map[display] = dev
            lines.append("%-20s %-14s %s" % (dev["name"], human_size(dev["size"]), dev["path"]))
        self.fw_combo["values"] = values
        if values and not self.fw_combo.get():
            self.fw_combo.current(0)
        elif values and self.fw_combo.get() not in self.fw_map:
            self.fw_combo.current(0)
        content = "检测到的整盘设备：\n"
        content += "\n".join(lines) if lines else "（未发现整盘块设备，设备可能是 MTD/NAND）"
        content += "\n\n原始 /proc/partitions：\n" + (raw or "")
        self._set_text(self.fw_info_text, content)
        self.refresh_dest_labels()

    def start_firmware_backup(self):
        if not self._check_device():
            return
        display = self.fw_combo.get()
        dev = self.fw_map.get(display)
        if not dev:
            messagebox.showinfo("无设备", "请先点击“扫描设备”。")
            return
        dest_dir = self._firmware_dir()
        if not dest_dir:
            messagebox.showerror("无可用磁盘", "未检测到可写的 F/E/D 盘。")
            return
        try:
            os.makedirs(dest_dir, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("创建目录失败", str(exc))
            return

        size_text = human_size(dev["size"])
        if self.detect_root() == "none":
            if not messagebox.askyesno(
                "权限不足",
                "整盘固件读取通常需要 root 权限，当前未检测到 root / su。\n\n"
                "是否仍要继续？\n选择“否”将切换到权限管理页。",
            ):
                self.notebook.select(4)
                return
        if not messagebox.askyesno(
            "开始备份编程器固件",
            "即将读取整盘设备：\n\n%s\n%s\n\n文件大小约 %s，备份期间请勿断电或拔出设备。\n是否继续？" % (
                dev["path"], dev["name"], size_text
            ),
        ):
            return

        if dev["size"]:
            try:
                free = shutil.disk_usage(os.path.splitdrive(dest_dir)[0] + "\\").free
                if free < dev["size"] * 1.02:
                    if not messagebox.askyesno("空间不足", "可用空间 %s，小于固件大小 %s，是否继续？" % (
                        human_size(free), size_text)):
                        return
            except OSError:
                pass

        filename = "firmware_%s_%s.bin" % (sanitize_name(dev["name"]),
                                          datetime.now().strftime("%Y%m%d_%H%M%S"))
        target = os.path.join(dest_dir, filename)
        self.fw_btn.config(state="disabled")
        self.fw_progress.config(value=0)
        self.fw_status_label.config(text="准备备份…")
        self.log("开始备份编程器固件：%s -> %s" % (dev["path"], target), "ok")
        threading.Thread(target=self._firmware_worker, args=(dev, target), daemon=True).start()

    def _firmware_worker(self, dev, target):
        if self.exec_out_ok is None:
            self._detect_capabilities()
        mode = self.detect_root()
        self.log("固件备份权限模式：%s" % mode, "warn" if mode == "none" else "info")

        def progress_cb(fraction):
            if fraction is None:
                self._post(self.fw_status_label.config, {"text": "备份中…"})
            else:
                self._post(self.fw_progress.config, {"value": fraction * 100})
                self._post(self.fw_status_label.config, {"text": "备份中 %d%%" % int(fraction * 100)})

        ok, msg = self._dump_partition(dev["path"], target, dev["size"], progress_cb)
        self._post(self._finish_firmware_ui, ok, msg, target, dev["size"])

    def _finish_firmware_ui(self, ok, msg, target, expected):
        self.fw_btn.config(state="normal")
        if ok:
            self.fw_progress.config(value=100)
            try:
                size = os.path.getsize(target)
            except OSError:
                size = 0
            self.fw_status_label.config(text="完成：%s（%s）" % (os.path.basename(target), human_size(size)))
            self.set_status("编程器固件备份完成")
            self.log("编程器固件备份完成：%s（%s）" % (target, human_size(size)), "ok")
            messagebox.showinfo("固件备份完成", "已保存：\n%s\n\n大小：%s" % (target, human_size(size)))
        else:
            self.fw_status_label.config(text="失败：%s" % msg)
            self.set_status("固件备份失败")
            self.log("编程器固件备份失败：%s" % msg, "error")
            messagebox.showerror("固件备份失败", msg)

    # ------------------------------------------------------------------
    # 权限管理
    # ------------------------------------------------------------------
    def check_permissions(self):
        if not self._check_device():
            return
        threading.Thread(target=self._check_permissions_worker, daemon=True).start()

    def _collect_permission_report(self):
        lines = []
        mounts = {}
        rc, id_out, _ = self._shell("id", timeout=12)
        adbd_root = "uid=0" in id_out
        lines.append("adb shell id      : %s" % (id_out.strip() or "无输出"))
        lines.append("adbd 是否 root    : %s" % ("是" if adbd_root else "否"))

        rc_su, su_out, _ = self._shell("su -c id", timeout=12)
        su_ok = "uid=0" in su_out
        lines.append("su 是否可用       : %s%s" % ("是" if su_ok else "否",
                                                     "" if su_ok else "（%s）" % (su_out.strip()[:80] or "无 su")))
        if adbd_root:
            self.root_mode = "adbd"
        elif su_ok:
            self.root_mode = "su"
        else:
            self.root_mode = "none"

        rc_type, build_type, _ = self._shell("getprop ro.build.type", timeout=10)
        rc_tags, build_tags, _ = self._shell("getprop ro.build.tags", timeout=10)
        lines.append("构建类型          : %s" % (build_type.strip() or "未知"))
        lines.append("构建标签          : %s" % (build_tags.strip() or "未知"))

        rc_mount, mount_out, _ = self._shell("mount", timeout=20)
        for line in mount_out.splitlines():
            m = re.match(r"^\S+\s+on\s+(\S+)\s+type\s+(\S+)\s+\(([^)]*)\)", line)
            if m:
                mountpoint = m.group(1)
                opts = m.group(3)
                mounts[mountpoint] = opts
        lines.append("")
        lines.append("关键挂载点读写状态：")
        for key in MOUNT_KEYS:
            if key in mounts:
                rw = "rw" in mounts[key].split(",")
                lines.append("  %-10s : %s" % (key, "可写 rw" if rw else "只读 ro"))
        if not any(k in mounts for k in MOUNT_KEYS):
            lines.append("  （未解析到关键挂载点，原始 mount 输出如下）")
            lines.append(mount_out.strip())

        rc_w, w_out, w_err = self._shell(
            "echo ok > /data/local/tmp/adbtool_rwtest 2>/dev/null && "
            "rm -f /data/local/tmp/adbtool_rwtest && echo WRITE_OK", timeout=15)
        writable = "WRITE_OK" in w_out
        lines.append("")
        lines.append("/data/local/tmp 写入测试 : %s" % ("成功" if writable else "失败"))
        if not writable and (w_out.strip() or w_err.strip()):
            lines.append("  输出：%s" % (w_out.strip() or w_err.strip())[:200])
        return "\n".join(lines), mounts, adbd_root, su_ok

    def _check_permissions_worker(self):
        self._post(self.set_status, "正在检查磁盘读写权限…")
        text, mounts, adbd_root, su_ok = self._collect_permission_report()
        self._post(self._apply_permission_text, text)
        self._post(self.set_status, "权限检查完成")
        self.log("权限检查完成：adbd root=%s，su=%s" % (adbd_root, su_ok), "ok")

    def _apply_permission_text(self, text):
        self._set_text(self.perm_text, text)

    def elevate_permissions(self):
        if not self._check_device():
            return
        threading.Thread(target=self._elevate_worker, daemon=True).start()

    def _elevate_worker(self):
        self.log("开始执行 5-2 ADB 可写提权…", "warn")
        self._post(self.set_status, "正在提权…")

        text, mounts, adbd_root, su_ok = self._collect_permission_report()
        if self._perm_snapshot is None:
            self._perm_snapshot = {
                "adbd_root": adbd_root,
                "su_ok": su_ok,
                "mounts": {mp: ("rw" in opts.split(",")) for mp, opts in mounts.items()},
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.log("已记录原始权限状态（用于 5-3 恢复）。")

        rc, out, err = self.adb(["root"], timeout=60)
        msg = (out + "\n" + err).strip()
        self.log("adb root：%s" % (msg.splitlines()[0] if msg else "无输出"),
                 "ok" if rc == 0 else "warn")
        self.adb(["wait-for-device"], timeout=60)
        time.sleep(0.5)

        rc, out, err = self.adb(["remount"], timeout=60)
        msg = (out + "\n" + err).strip()
        if msg:
            self.log("adb remount：%s" % msg[:300])

        self.detect_root()
        if self.root_mode in ("adbd", "su"):
            for mp in ("/", "/system", "/vendor", "/product", "/odm", "/data"):
                if mp == "/data":
                    continue
                self._remount(mp, "rw")
        else:
            self.log("提权失败：设备既没有 adbd root，也没有可用的 su。", "error")

        text, mounts, adbd_root, su_ok = self._collect_permission_report()
        self._post(self._apply_permission_text, text)
        self._post(self.set_status, "提权操作完成，请查看权限状态")
        self.log("5-2 提权操作完成。", "ok")

    def _remount(self, mountpoint, mode):
        cmd = "mount -o %s,remount %s" % (mode, shlex.quote(mountpoint))
        if self.root_mode == "su":
            cmd = "su -c " + shlex.quote(cmd)
        rc, out, err = self._shell(cmd, timeout=30)
        if rc == 0 and not (err.strip() and "denied" in err.lower()):
            self.log("  %s 重新挂载为 %s：成功" % (mountpoint, mode), "ok")
            return True
        detail = (out.strip() or err.strip())[:160]
        self.log("  %s 重新挂载为 %s：失败%s" % (mountpoint, mode, ("（%s）" % detail) if detail else ""), "warn")
        return False

    def restore_permissions(self):
        if not self._check_device():
            return
        threading.Thread(target=self._restore_worker, daemon=True).start()

    def _restore_worker(self):
        self.log("开始执行 5-3 恢复原始读写权限…", "warn")
        self._post(self.set_status, "正在恢复权限…")
        snapshot = self._perm_snapshot
        self.detect_root()

        if snapshot:
            for mp, was_rw in snapshot.get("mounts", {}).items():
                if mp in MOUNT_KEYS and not was_rw:
                    self._remount(mp, "ro")
            if not snapshot.get("adbd_root"):
                self._unroot_adbd()
            self._perm_snapshot = None
            self.log("已按提权前记录恢复挂载状态与 adbd 权限。", "ok")
        else:
            self.log("没有提权前的状态记录，执行尽力恢复：将关键分区重新挂载为只读，并尝试取消 adb root。", "warn")
            for mp in ("/system", "/vendor", "/product", "/odm"):
                if mp in self._current_mounts():
                    self._remount(mp, "ro")
            rc, id_out, _ = self._shell("id", timeout=10)
            if "uid=0" in id_out:
                self._unroot_adbd()

        self.adb(["wait-for-device"], timeout=60)
        time.sleep(0.5)
        text, _, _, _ = self._collect_permission_report()
        self._post(self._apply_permission_text, text)
        self._post(self.set_status, "权限恢复操作完成")
        self.log("5-3 恢复操作完成。", "ok")

    def _current_mounts(self):
        mounts = {}
        rc, out, _ = self._shell("mount", timeout=15)
        for line in out.splitlines():
            m = re.match(r"^\S+\s+on\s+(\S+)\s+type\s+\S+", line)
            if m:
                mounts[m.group(1)] = True
        return mounts

    def _unroot_adbd(self):
        rc, out, err = self.adb(["unroot"], timeout=45)
        msg = (out + "\n" + err).strip()
        if rc == 0 and "unknown" not in msg.lower():
            self.log("adb unroot：%s" % (msg.splitlines()[0] if msg else "完成"), "ok")
        else:
            self.log("adb unroot 不可用，尝试通过属性重启 adbd…", "warn")
            cmd = "setprop service.adb.root 0; stop adbd; start adbd"
            if self.root_mode == "su":
                cmd = "su -c " + shlex.quote(cmd)
            self._shell(cmd, timeout=20)
        self.adb(["kill-server"], timeout=15, use_serial=False)
        self.adb(["start-server"], timeout=25, use_serial=False)
        self.adb(["wait-for-device"], timeout=60)
        self.root_mode = "none"

    # ------------------------------------------------------------------
    # 文件管理
    # ------------------------------------------------------------------
    def refresh_file_list(self):
        if not self._check_device():
            return
        path = self.file_path_var.get().strip() or "/"
        self.file_path_var.set(path)
        threading.Thread(target=self._list_files_worker, args=(path,), daemon=True).start()

    def _list_files_worker(self, path):
        rc, out, err = self._shell("ls -la %s" % shlex.quote(path), timeout=30)
        if rc != 0 and not out.strip():
            self._post(self.log, "读取目录失败：%s（%s）" % (path, err.strip()), "error")
            self._post(self.set_status, "读取目录失败")
            return
        entries = []
        for line in out.splitlines():
            line = line.rstrip()
            if not line or line.startswith("total "):
                continue
            parts = line.split(None, 7)
            if len(parts) < 8:
                continue
            perms, _, _, _, size, date, tm, name = parts
            if name in (".", ".."):
                continue
            is_link = perms.startswith("l")
            is_dir = perms.startswith("d")
            kind = "目录" if is_dir else ("链接" if is_link else "文件")
            size_text = size if not size.isdigit() else human_size(int(size))
            entries.append({
                "name": name.split(" -> ")[0],
                "full": name,
                "kind": kind,
                "size": size_text,
                "perm": perms,
                "date": "%s %s" % (date, tm),
                "is_dir": is_dir,
            })
        self._post(self._apply_file_listing, entries, path)

    def _apply_file_listing(self, entries, path):
        self.file_path_var.set(path)
        self.file_tree.delete(*self.file_tree.get_children())
        self.file_rows.clear()
        for idx, entry in enumerate(entries):
            iid = "f%d" % idx
            self.file_rows[iid] = entry
            self.file_tree.insert("", "end", iid=iid, values=(
                entry["name"], entry["kind"], entry["size"], entry["perm"], entry["date"]
            ))
        self.file_status_label.config(text="%d 项" % len(entries))
        self.set_status("已列出 %s（%d 项）" % (path, len(entries)))

    def file_up(self):
        current = self.file_path_var.get().strip() or "/"
        parent = posixpath.dirname(current.rstrip("/")) or "/"
        self.file_path_var.set(parent)
        self.refresh_file_list()

    def file_activate(self):
        iid = self.file_tree.focus()
        entry = self.file_rows.get(iid)
        if not entry:
            return
        current = self.file_path_var.get().strip() or "/"
        target = posixpath.join(current, entry["name"])
        if entry["is_dir"]:
            self.file_path_var.set(target)
            self.refresh_file_list()
        else:
            self._preview_remote_file(target)

    def edit_selected_file(self):
        iid = self.file_tree.focus()
        entry = self.file_rows.get(iid)
        if not entry:
            messagebox.showinfo("未选择", "请先选择一个文件。")
            return
        if entry["is_dir"]:
            messagebox.showinfo("提示", "目录不能作为文本编辑，请双击进入。")
            return
        current = self.file_path_var.get().strip() or "/"
        self._preview_remote_file(posixpath.join(current, entry["name"]))

    def _preview_remote_file(self, path):
        threading.Thread(target=self._preview_worker, args=(path,), daemon=True).start()

    def _preview_worker(self, path):
        self.detect_root()
        command = "dd if=%s bs=4096 count=256 2>/dev/null" % shlex.quote(path)
        if self.root_mode == "su":
            command = "su -c " + shlex.quote(command)
        rc, data, err = self.adb(["shell", command], timeout=45, binary=True)
        if rc != 0 and not data:
            self._post(self.log, "读取文件失败：%s（%s）" % (path, err.strip()), "error")
            return
        truncated = len(data) >= 1024 * 1024
        is_binary = b"\x00" in data
        if not is_binary:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("utf-8", "replace")
                replacement_ratio = text.count("\ufffd") / max(len(text), 1)
                is_binary = replacement_ratio > 0.02
            else:
                text = text.replace("\r\n", "\n")
        if is_binary:
            self._post(self.log, "文件为二进制内容，请使用“下载到本地”保存：%s" % path, "warn")
            self._post(messagebox.showinfo, "二进制文件",
                       "该文件包含二进制数据，无法在文本编辑器中打开。\n请使用“下载到本地”功能保存。")
            return
        self._post(self._open_editor_dialog, path, text, truncated)

    def _open_editor_dialog(self, path, content, truncated=False, is_new=False):
        win = tk.Toplevel(self.root)
        win.title(("新建文件 - " if is_new else "查看 / 编辑 - ") + path)
        win.geometry("920x680")
        win.transient(self.root)

        top = ttk.Frame(win, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text=path, font=("Consolas", 9)).pack(side="left")
        if truncated:
            ttk.Label(top, text="（仅显示前 1MB）", foreground="#e65100").pack(side="left", padx=8)

        text = scrolledtext.ScrolledText(win, wrap="none", font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=6, pady=6)
        text.insert("1.0", content)

        bar = ttk.Frame(win, padding=6)
        bar.pack(fill="x")
        status = ttk.Label(bar, text="")
        status.pack(side="left")

        def save_to_device():
            data = text.get("1.0", "end-1c")
            save_btn.config(state="disabled")
            status.config(text="正在保存…")

            def worker():
                fd, tmp = tempfile.mkstemp(prefix="adbtool_edit_", suffix=".txt")
                os.close(fd)
                try:
                    with open(tmp, "w", encoding="utf-8") as f:
                        f.write(data)
                    ok, msg = self._push_file(tmp, path)
                finally:
                    self._remove_file(tmp)
                if ok:
                    self._post(status.config, {"text": "已保存"})
                    self._post(self.log, "文件已保存：%s" % path, "ok")
                    self._post(self.refresh_file_list)
                    self._post(messagebox.showinfo, "保存成功", "文件已写入设备：\n%s" % path)
                    self._post(win.destroy)
                else:
                    self._post(status.config, {"text": "保存失败"})
                    self._post(self.log, "保存文件失败：%s" % msg, "error")
                    self._post(save_btn.config, {"state": "normal"})
                    self._post(messagebox.showerror, "保存失败", msg)

            threading.Thread(target=worker, daemon=True).start()

        def save_local():
            default = posixpath.basename(path) or "file.txt"
            local = filedialog.asksaveasfilename(title="保存到本地", initialfile=default,
                                                 filetypes=[("所有文件", "*.*")])
            if not local:
                return
            try:
                with open(local, "w", encoding="utf-8") as f:
                    f.write(text.get("1.0", "end-1c"))
                self.log("文本已另存到本地：%s" % local, "ok")
            except OSError as exc:
                messagebox.showerror("保存失败", str(exc))

        save_btn = ttk.Button(bar, text="保存到设备", command=save_to_device)
        save_btn.pack(side="right")
        ttk.Button(bar, text="关闭", command=win.destroy).pack(side="right", padx=8)
        ttk.Button(bar, text="另存到本地", command=save_local).pack(side="right")

    def new_remote_file(self):
        if not self._check_device():
            return
        current = self.file_path_var.get().strip() or "/"
        name = simpledialog.askstring("新建文件", "请输入文件名（保存到 %s）：" % current, parent=self.root)
        if not name:
            return
        if name.startswith("/"):
            path = name
        else:
            path = posixpath.join(current, name)
        self._open_editor_dialog(path, "", truncated=False, is_new=True)

    def download_selected_file(self):
        if not self._check_device():
            return
        iid = self.file_tree.focus()
        entry = self.file_rows.get(iid)
        if not entry:
            messagebox.showinfo("未选择", "请先选择一个文件。")
            return
        if entry["is_dir"]:
            messagebox.showinfo("提示", "暂不支持下载整个目录，请进入目录后选择文件。")
            return
        current = self.file_path_var.get().strip() or "/"
        remote = posixpath.join(current, entry["name"])
        local = filedialog.asksaveasfilename(title="下载到本地", initialfile=entry["name"],
                                             filetypes=[("所有文件", "*.*")])
        if not local:
            return
        threading.Thread(target=self._download_worker, args=(remote, local), daemon=True).start()

    def _download_worker(self, remote, local):
        self.set_status("正在下载：%s" % remote)
        self.log("下载文件：%s -> %s" % (remote, local))
        rc, out, err = self.adb(["pull", remote, local], timeout=3600)
        if rc == 0 and os.path.exists(local):
            size = os.path.getsize(local)
            self._post(self.log, "下载完成：%s（%s）" % (local, human_size(size)), "ok")
            self._post(self.set_status, "下载完成")
            self._post(messagebox.showinfo, "下载完成", "已保存到：\n%s\n\n大小：%s" % (local, human_size(size)))
        else:
            detail = (err or out).strip()[:400]
            self._post(self.log, "下载失败：%s" % detail, "error")
            self._post(self.set_status, "下载失败")
            self._post(messagebox.showerror, "下载失败", detail or "adb pull 执行失败")

    def upload_file(self):
        if not self._check_device():
            return
        local = filedialog.askopenfilename(title="选择要上传的文件", filetypes=[("所有文件", "*.*")])
        if not local:
            return
        current = self.file_path_var.get().strip() or "/"
        remote = posixpath.join(current, os.path.basename(local))
        threading.Thread(target=self._upload_worker, args=(local, remote), daemon=True).start()

    def _upload_worker(self, local, remote):
        self.set_status("正在上传：%s" % remote)
        self.log("上传文件：%s -> %s" % (local, remote))
        ok, msg = self._push_file(local, remote)
        if ok:
            self._post(self.log, "上传完成：%s" % remote, "ok")
            self._post(self.set_status, "上传完成")
            self._post(self.refresh_file_list)
            self._post(messagebox.showinfo, "上传完成", "已上传到设备：\n%s" % remote)
        else:
            self._post(self.log, "上传失败：%s" % msg, "error")
            self._post(self.set_status, "上传失败")
            self._post(messagebox.showerror, "上传失败", msg)

    def _push_file(self, local, remote):
        rc, out, err = self.adb(["push", local, remote], timeout=3600)
        if rc == 0:
            return True, "adb push 成功"
        self.detect_root()
        if self.root_mode in ("adbd", "su"):
            temp_remote = "/data/local/tmp/adbtool_upload_%s" % datetime.now().strftime("%H%M%S%f")
            rc2, out2, err2 = self.adb(["push", local, temp_remote], timeout=3600)
            if rc2 == 0:
                cmd = "cp %s %s && rm -f %s" % (
                    shlex.quote(temp_remote), shlex.quote(remote), shlex.quote(temp_remote)
                )
                if self.root_mode == "su":
                    cmd = "su -c " + shlex.quote(cmd)
                rc3, out3, err3 = self._shell(cmd, timeout=120)
                if rc3 == 0:
                    return True, "通过 root 中转写入成功"
                return False, "root 写入失败：%s" % ((err3 or out3).strip()[:300] or "未知错误")
            return False, "中转 push 失败：%s" % (err2 or out2).strip()[:300]
        return False, (err or out).strip()[:400] or "adb push 执行失败（目标可能为只读文件系统）"


# ----------------------------------------------------------------------------
def main():
    if os.name == "nt":
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    AdbBackupApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

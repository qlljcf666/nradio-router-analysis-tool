#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NV文件读取工具 - GUI版本
基于 read_nvitem.py (udx710刷机程序源码分析) 编写
使用 tkinter 实现图形界面, 仅依赖 Python 标准库

功能:
    - 打开并解析 NV 文件 (INDX 标准格式 / UBI 格式)
    - 树形列表展示所有核心的 NV items (ID/名称/大小/偏移)
    - 加载 XML 配置文件显示 item 名称
    - 十六进制查看选中 item 内容
    - 导出选中 item / 导出全部 items
    - 按 ID / 名称过滤查找

文件格式:
    1. MULTI_CORE_NV_HEADER_T - 文件头部 (magic: 0x58444E49 "INDX")
    2. NV_CORE_INFO_T 数组 - 每个核心的名称/数据偏移/数据大小
    3. NVItem 数据 - 每个 item 包含 ID(WORD) + Length(WORD) + Data
"""

import os
import struct
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import font as tkfont
import xml.etree.ElementTree as ET
from collections import OrderedDict

# ---------------------------------------------------------------------------
# 常量定义 (与原脚本一致)
# ---------------------------------------------------------------------------
INDEX_MAGIC = 0x58444E49      # "INDX"
UBI_NV_MAGIC = 0x00004E56     # "VN" (UBI格式)
PADDING_NV_ID = 0xFFFE
MAX_NV_CORE_NAME = 16
UBI_HEADER_SIZE = 0x200       # UBI格式头部大小

APP_TITLE = "NV文件读取工具 (GUI版)"
APP_VERSION = "1.0"


# ---------------------------------------------------------------------------
# NV 解析核心逻辑 (源自 read_nvitem.py, print 改为 log 回调)
# ---------------------------------------------------------------------------
class NVHeader:
    """NV文件头部结构"""
    SIZE = 8  # DWORD + WORD + WORD

    def __init__(self, data):
        self.magic, self.version, self.count_core = struct.unpack('<IHH', data[:self.SIZE])

    def is_valid(self):
        return self.magic == INDEX_MAGIC

    def __repr__(self):
        return f"NVHeader(magic=0x{self.magic:08X}, version={self.version}, cores={self.count_core})"


class NVCoreInfo:
    """NV核心信息结构"""
    SIZE = 16 + 4 + 4  # char[16] + DWORD + DWORD

    def __init__(self, data):
        name_bytes = data[:16]
        self.core_name = name_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
        self.data_offset, self.data_size = struct.unpack('<II', data[16:24])

    def __repr__(self):
        return f"NVCore(name='{self.core_name}', offset=0x{self.data_offset:08X}, size=0x{self.data_size:08X})"


class NVItem:
    """NV Item结构"""

    def __init__(self, item_id, data, offset=0):
        self.id = item_id
        self.data = data
        self.size = len(data)
        self.offset = offset  # 该item在文件中的偏移位置

    def __repr__(self):
        return f"NVItem(id=0x{self.id:04X}, size={self.size} bytes, offset=0x{self.offset:08X})"


class NVFile:
    """NV文件解析器"""

    def __init__(self, filepath, log=print):
        self.filepath = filepath
        self.log = log
        self.header = None
        self.cores = []
        self.items = OrderedDict()  # {core_name: {item_id: NVItem}}
        self.modified = False       # 是否有未保存的修改
        self.is_ubi = False         # 是否 UBI 格式
        self._ubi_mode = None       # 'indx'(内嵌INDX) / 'simple'(简单格式)
        self._ubi_indx_offset = 0   # UBI 中 INDX 结构的绝对偏移
        self._raw = None            # 原始文件字节 (保存时保留头部/尾部)
        self._read_file()

    def _read_file(self):
        """读取并解析NV文件"""
        with open(self.filepath, 'rb') as f:
            self._raw = f.read()
            f.seek(0)
            header_data = f.read(NVHeader.SIZE)
            self.header = NVHeader(header_data)

            # 检查是否是UBI格式
            if self.header.magic == UBI_NV_MAGIC:
                self.log("检测到 UBI 格式 NV 文件")
                self._read_ubi_format(f)
                return

            if not self.header.is_valid():
                raise ValueError(
                    f"无效的NV文件: magic=0x{self.header.magic:08X}, "
                    f"期望=0x{INDEX_MAGIC:08X} 或 0x{UBI_NV_MAGIC:08X}")

            self.log(f"文件头: {self.header}")

            # 读取核心信息
            for i in range(self.header.count_core):
                core_data = f.read(NVCoreInfo.SIZE)
                core = NVCoreInfo(core_data)
                self.cores.append(core)
                self.log(f"  核心 {i}: {core}")

            # 读取每个核心的NV items
            for core in self.cores:
                if core.data_size == 0:
                    continue
                f.seek(core.data_offset)
                core_data = f.read(core.data_size)
                items = self._parse_core_items(core_data, core.data_offset)
                self.items[core.core_name] = items
                self.log(f"  核心 '{core.core_name}' 包含 {len(items)} 个 NV items")

    def _read_ubi_format(self, f):
        """读取UBI格式的NV文件"""
        self.is_ubi = True
        f.seek(0)
        ubi_header = f.read(16)
        magic, total_size, data_size, item_count = struct.unpack('<IIII', ubi_header)
        self.log(f"UBI头部: 总大小=0x{total_size:X}, 数据大小=0x{data_size:X}, Item数={item_count}")

        # 跳到0x200处查找INDX
        f.seek(UBI_HEADER_SIZE)
        search_data = f.read(256)
        indx_offset = search_data.find(b'INDX')

        if indx_offset != -1:
            self.log(f"找到 INDX at 0x{UBI_HEADER_SIZE + indx_offset:X}")
            f.seek(UBI_HEADER_SIZE + indx_offset)

            indx_data = f.read(NVHeader.SIZE)
            temp_header = NVHeader(indx_data)

            if temp_header.is_valid():
                self.log(f"INDX头部: {temp_header}")
                self.header = temp_header
                self._ubi_mode = 'indx'
                self._ubi_indx_offset = UBI_HEADER_SIZE + indx_offset

                for i in range(temp_header.count_core):
                    core_data = f.read(NVCoreInfo.SIZE)
                    core = NVCoreInfo(core_data)
                    self.cores.append(core)
                    self.log(f"  核心 {i}: {core}")

                for core in self.cores:
                    if core.data_size == 0:
                        continue
                    f.seek(core.data_offset)
                    core_data = f.read(core.data_size)
                    items = self._parse_core_items(core_data, core.data_offset)
                    self.items[core.core_name] = items
                    self.log(f"  核心 '{core.core_name}' 包含 {len(items)} 个 NV items")
                return

        # 如果没有INDX，尝试直接解析items（简单格式）
        self.log("警告: 未找到 INDX 结构，尝试简单格式解析 (数据起始 0x800)")
        self._ubi_mode = 'simple'
        f.seek(0x800)
        all_data = f.read()
        items = self._parse_core_items(all_data, 0x800)
        self.items["default"] = items
        self.log(f"解析到 {len(items)} 个 NV items")
        self.header = NVHeader(struct.pack('<IHH', INDEX_MAGIC, 0, 1))

    def _parse_core_items(self, data, base_offset=0):
        """解析核心数据中的NV items
        item格式: WORD item_id + WORD item_len + BYTE[] data, 4字节对齐
        """
        items = OrderedDict()
        offset = 0

        while offset + 4 <= len(data):
            item_file_offset = base_offset + offset
            item_id, item_len = struct.unpack('<HH', data[offset:offset + 4])
            offset += 4

            # 结束标记或填充
            if item_id == PADDING_NV_ID or item_id == 0xFFFF:
                break

            if offset + item_len <= len(data):
                item_data = data[offset:offset + item_len]
                offset += item_len
                # 对齐到4字节边界
                align = (4 - (item_len % 4)) % 4
                offset += align
                items[item_id] = NVItem(item_id, item_data, item_file_offset)
            else:
                self.log(f"警告: Item 0x{item_id:04X} 数据长度超出范围")
                break

        return items

    # ---------------- 修改与保存 ----------------
    def replace_item(self, core_name, item_id, new_data):
        """用外部数据替换指定 item (仅在内存中, 需调用 build/save 落盘)"""
        item = self.items[core_name][item_id]
        old_size = item.size
        item.data = bytes(new_data)
        item.size = len(item.data)
        self.modified = True
        return old_size

    @staticmethod
    def _serialize_items(items):
        """将一个核心的 items 序列化为二进制: ID(2B)+Len(2B)+Data+4字节对齐, 末尾 0xFFFF 终止"""
        buf = bytearray()
        for item_id, item in items.items():
            buf += struct.pack('<HH', item_id, item.size)
            buf += item.data
            buf += b'\x00' * ((4 - item.size % 4) % 4)
        buf += struct.pack('<HH', 0xFFFF, 0)  # 结束标记
        return bytes(buf)

    def build(self):
        """重新缝合 NV 文件, 返回完整 bytes (保留 UBI 头部与尾部原始数据)"""
        if self.is_ubi and self._ubi_mode == 'simple':
            # 简单格式: 0x800 之前原样保留, 之后重写序列化 items
            prefix = bytearray(self._raw[:0x800])
            section = self._serialize_items(self.items.get('default', {}))
            struct.pack_into('<IIII', prefix, 0, UBI_NV_MAGIC,
                             0x800 + len(section), len(section),
                             sum(len(v) for v in self.items.values()))
            return bytes(prefix) + section

        # INDX 区段重建 (标准 INDX 文件整体 / UBI 内嵌 INDX)
        start = self._ubi_indx_offset if self.is_ubi else 0
        prefix = bytearray(self._raw[:start]) if self.is_ubi else bytearray()

        # 原 NV 区段结束位置 (其后字节原样保留, 如 ubifs 镜像尾部)
        end = start
        for core in self.cores:
            end = max(end, core.data_offset + core.data_size)
        trailing = self._raw[end:] if (self._raw is not None and len(self._raw) > end) else b''

        n = len(self.cores)
        section = bytearray()
        section += struct.pack('<IHH', INDEX_MAGIC, self.header.version, n)
        data_off = start + NVHeader.SIZE + NVCoreInfo.SIZE * n

        core_blobs = []
        for core in self.cores:
            items = self.items.get(core.core_name)
            if items:
                blob = self._serialize_items(items)
                # 不足原始大小时用 0xFF 填充, 保持布局接近原文件
                if len(blob) < core.data_size:
                    blob += b'\xff' * (core.data_size - len(blob))
            elif core.data_size:
                blob = b'\xff' * core.data_size
            else:
                blob = b''
            core_blobs.append((core, blob, data_off))
            data_off += len(blob)

        for core, blob, off in core_blobs:
            name = core.core_name.encode('utf-8')[:MAX_NV_CORE_NAME].ljust(MAX_NV_CORE_NAME, b'\x00')
            section += name + struct.pack('<II', off, len(blob))
        for _, blob, _ in core_blobs:
            section += blob

        if self.is_ubi:
            # 回写 UBI 头部: magic/total_size/data_size/item_count
            total = len(prefix) + len(section) + len(trailing)
            struct.pack_into('<IIII', prefix, 0, UBI_NV_MAGIC, total, len(section),
                             sum(len(v) for v in self.items.values()))
        return bytes(prefix) + bytes(section) + trailing

    def save(self, path=None):
        """保存到文件 (默认覆盖原路径), 返回保存路径"""
        path = path or self.filepath
        data = self.build()
        with open(path, 'wb') as f:
            f.write(data)
        self.modified = False
        self.filepath = path
        return path, len(data)

    def get_item_by_id(self, item_id):
        """在所有核心中查找指定ID的NV item"""
        for core_name, items in self.items.items():
            if item_id in items:
                return core_name, items[item_id]
        return None, None

    def total_items(self):
        return sum(len(items) for items in self.items.values())


class NVItemDefinition:
    """NV Item定义(从XML加载)"""

    def __init__(self, xml_path, log=print):
        self.items = {}  # {item_id: item_name}
        self.log = log
        self._load_xml(xml_path)

    def _load_xml(self, xml_path):
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for nvbackup in root.findall('.//NVBackup'):
                for nvitem in nvbackup.findall('NVItem'):
                    name = nvitem.get('name', 'Unknown')
                    id_elem = nvitem.find('ID')
                    if id_elem is not None and id_elem.text:
                        id_text = id_elem.text.strip()
                        if id_text.startswith(('0x', '0X')):
                            item_id = int(id_text, 16)
                        else:
                            item_id = int(id_text)
                        self.items[item_id] = name
            self.log(f"从 XML 加载了 {len(self.items)} 个 NV item 定义")
        except Exception as e:
            self.log(f"警告: 加载 XML 文件失败: {e}")
            raise

    def get_name(self, item_id):
        return self.items.get(item_id, "")


# ---------------------------------------------------------------------------
# 十六进制格式化
# ---------------------------------------------------------------------------
def format_hex(data, base_addr=0):
    """生成 16 字节/行 的十六进制显示文本"""
    lines = []
    for i in range(0, len(data), 16):
        line = f"{base_addr + i:08X}  "
        hex_part = ""
        ascii_part = ""
        for j in range(16):
            if i + j < len(data):
                byte = data[i + j]
                hex_part += f"{byte:02X} "
                ascii_part += chr(byte) if 32 <= byte <= 126 else "."
            else:
                hex_part += "   "
                ascii_part += " "
            if j == 7:
                hex_part += " "
        lines.append(line + hex_part + " |" + ascii_part + "|")
    return "\n".join(lines)


def parse_id_text(text):
    """解析用户输入的 ID (支持 0x 前缀十六进制或十进制), 失败返回 None"""
    text = text.strip()
    if not text:
        return None
    try:
        if text.lower().startswith('0x'):
            return int(text, 16)
        # 纯字母 hex 形式 (如 9C4) 也尝试按十六进制解析
        if any(c in 'abcdefABCDEF' for c in text):
            return int(text, 16)
        return int(text)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def parse_hex_bytes(text):
    """解析用户输入的十六进制字节序列为 bytes
    支持格式: "01 02 AB CD" / "0102ABCD" / "0x01 0x02" / "01,02,AB,CD"
    失败返回 None
    """
    t = text.strip().lower().replace('0x', '')
    for sep in (',', ';', ':', '-'):
        t = t.replace(sep, ' ')
    t = ''.join(t.split())  # 去除全部空白
    if not t or len(t) % 2 != 0:
        return None
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


def search_bytes(data, pattern, cap=256):
    """在 data 中查找 pattern, 返回 (匹配起始下标列表, 是否超过cap被截断)"""
    pos = []
    start = 0
    while len(pos) < cap:
        i = data.find(pattern, start)
        if i == -1:
            return pos, False
        pos.append(i)
        start = i + 1
    # 达到上限, 检查是否还有更多
    return pos, data.find(pattern, start) != -1


# ---------------------------------------------------------------------------
# GUI 主程序
# ---------------------------------------------------------------------------
class NVReaderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1100x720")
        self.root.minsize(900, 560)

        self.nv_file = None        # NVFile 实例
        self.nv_defs = None        # NVItemDefinition 实例
        self.nv_path = tk.StringVar()
        self.xml_path = tk.StringVar()
        self.search_text = tk.StringVar()
        self.status_text = tk.StringVar(value="就绪 - 请打开 NV 文件")

        # 树节点 iid -> (core_name, item_id) 映射
        self._tree_map = {}

        self._build_menu()
        self._build_toolbar()
        self._build_main_area()
        self._build_statusbar()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------------- UI 构建 ----------------
    def _build_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="打开 NV 文件...", accelerator="Ctrl+O", command=self.open_nv_file)
        file_menu.add_command(label="加载 XML 定义...", command=self.open_xml_file)
        file_menu.add_separator()
        file_menu.add_command(label="导出选中 Item...", accelerator="Ctrl+E", command=self.export_selected)
        file_menu.add_command(label="导出全部 Items...", command=self.export_all)
        file_menu.add_separator()
        file_menu.add_command(label="保存 NV 文件", accelerator="Ctrl+S", command=self.save_nv)
        file_menu.add_command(label="NV 文件另存为...", command=self.save_nv_as)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        menubar.add_cascade(label="文件", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)

        self.root.config(menu=menubar)
        self.root.bind('<Control-o>', lambda e: self.open_nv_file())
        self.root.bind('<Control-e>', lambda e: self.export_selected())
        self.root.bind('<Control-s>', lambda e: self.save_nv())

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(8, 6))
        bar.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(bar, text="打开NV文件", command=self.open_nv_file).pack(side=tk.LEFT)
        ttk.Button(bar, text="加载XML", command=self.open_xml_file).pack(side=tk.LEFT, padx=(6, 0))

        ttk.Label(bar, text="文件:").pack(side=tk.LEFT, padx=(12, 4))
        path_entry = ttk.Entry(bar, textvariable=self.nv_path, state='readonly')
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Label(bar, text="过滤(ID/名称):").pack(side=tk.LEFT, padx=(12, 4))
        search_entry = ttk.Entry(bar, textvariable=self.search_text, width=18)
        search_entry.pack(side=tk.LEFT)
        search_entry.bind('<Return>', lambda e: self.refresh_tree())
        ttk.Button(bar, text="查找", command=self.refresh_tree).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(bar, text="清除", command=self.clear_search).pack(side=tk.LEFT, padx=(4, 0))

    def _build_main_area(self):
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))

        # ---- 左侧: item 树形列表 ----
        left = ttk.Frame(paned)
        paned.add(left, weight=2)

        columns = ('id_hex', 'id_dec', 'name', 'size', 'offset')
        self.tree = ttk.Treeview(left, columns=columns, show='tree headings', selectmode='browse')
        self.tree.heading('#0', text='核心 / Item', anchor=tk.W)
        self.tree.heading('id_hex', text='ID(十六进制)')
        self.tree.heading('id_dec', text='ID(十进制)')
        self.tree.heading('name', text='名称')
        self.tree.heading('size', text='大小(字节)')
        self.tree.heading('offset', text='文件偏移')

        self.tree.column('#0', width=110, minwidth=80)
        self.tree.column('id_hex', width=95, anchor=tk.CENTER)
        self.tree.column('id_dec', width=80, anchor=tk.E)
        self.tree.column('name', width=180, anchor=tk.W)
        self.tree.column('size', width=80, anchor=tk.E)
        self.tree.column('offset', width=95, anchor=tk.CENTER)

        tree_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(left, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll.set, xscrollcommand=tree_scroll_x.set)
        left.grid_rowconfigure(0, weight=1)
        left.grid_columnconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky='nsew')
        tree_scroll.grid(row=0, column=1, sticky='ns')
        tree_scroll_x.grid(row=1, column=0, sticky='ew')  # 底部横向滚动滑块

        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        self.tree.bind('<Button-3>', self.show_context_menu)

        # ---- 右侧: 详情 + 十六进制 + 日志 ----
        right = ttk.Frame(paned)
        paned.add(right, weight=3)

        # 详情面板
        info = ttk.LabelFrame(right, text="Item 详情", padding=6)
        info.pack(side=tk.TOP, fill=tk.X)

        self.info_vars = {
            'id': tk.StringVar(value='-'),
            'name': tk.StringVar(value='-'),
            'core': tk.StringVar(value='-'),
            'size': tk.StringVar(value='-'),
            'offset': tk.StringVar(value='-'),
        }
        labels = [('ID', 'id'), ('名称', 'name'), ('所属核心', 'core'),
                  ('大小', 'size'), ('文件偏移', 'offset')]
        for idx, (text, key) in enumerate(labels):
            ttk.Label(info, text=f"{text}:").grid(row=0, column=idx * 2, sticky=tk.W, padx=(4, 2))
            ttk.Label(info, textvariable=self.info_vars[key],
                      foreground='#0B5394').grid(row=0, column=idx * 2 + 1, sticky=tk.W, padx=(0, 8))

        # 按钮行
        btn_bar = ttk.Frame(right)
        btn_bar.pack(side=tk.TOP, fill=tk.X, pady=(4, 2))
        ttk.Button(btn_bar, text="导出选中Item", command=self.export_selected).pack(side=tk.LEFT)
        ttk.Button(btn_bar, text="导出全部Items", command=self.export_all).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(btn_bar, text="跳转到ID...", command=self.goto_id).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Button(btn_bar, text="按偏移定位...", command=self.goto_offset).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(btn_bar, text="Hex数值查找...", command=self.find_hex_values).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Button(btn_bar, text="Licence一键查找", command=self.find_license).pack(side=tk.LEFT, padx=(6, 0))

        # 第二行按钮: 修改与保存
        btn_bar2 = ttk.Frame(right)
        btn_bar2.pack(side=tk.TOP, fill=tk.X, pady=(0, 2))
        ttk.Button(btn_bar2, text="导入替换Item...", command=self.import_replace_item).pack(side=tk.LEFT)
        ttk.Button(btn_bar2, text="保存NV文件", command=self.save_nv).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(btn_bar2, text="NV另存为...", command=self.save_nv_as).pack(side=tk.LEFT, padx=(6, 0))
        self.modified_label = ttk.Label(btn_bar2, text="", foreground='#CC0000')
        self.modified_label.pack(side=tk.LEFT, padx=(12, 0))

        # Notebook: hex 查看 / 运行日志
        notebook = ttk.Notebook(right)
        notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        mono = tkfont.Font(family='Consolas', size=10)

        # ---- hex 查看 tab (grid 布局: 右侧垂直 + 底部水平滚动条) ----
        hex_frame = ttk.Frame(notebook)
        self.hex_text = tk.Text(hex_frame, font=mono, wrap=tk.NONE,
                                bg='#1E1E1E', fg='#D4D4D4', insertbackground='#D4D4D4')
        hex_y = ttk.Scrollbar(hex_frame, orient=tk.VERTICAL, command=self.hex_text.yview)
        hex_x = ttk.Scrollbar(hex_frame, orient=tk.HORIZONTAL, command=self.hex_text.xview)
        self.hex_text.configure(yscrollcommand=hex_y.set, xscrollcommand=hex_x.set)
        self.hex_text.tag_config('offset_hl', background='#7A5C00', foreground='#FFFFFF')
        self.hex_text.tag_config('find_hl', background='#0E639C', foreground='#FFFFFF')
        hex_frame.grid_rowconfigure(0, weight=1)
        hex_frame.grid_columnconfigure(0, weight=1)
        self.hex_text.grid(row=0, column=0, sticky='nsew')
        hex_y.grid(row=0, column=1, sticky='ns')
        hex_x.grid(row=1, column=0, sticky='ew')  # 底部水平滚动滑块
        self.hex_text.config(state=tk.DISABLED)
        notebook.add(hex_frame, text=' 十六进制查看 ')

        # ---- 运行日志 tab (顶部工具栏 + 文本区) ----
        log_frame = ttk.Frame(notebook)
        log_bar = ttk.Frame(log_frame)
        log_bar.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(log_bar, text="复制全部日志", command=self.log_copy_all).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(log_bar, text="导出日志...", command=self.log_export).pack(side=tk.LEFT, padx=2)
        ttk.Button(log_bar, text="清空日志", command=self.log_clear).pack(side=tk.LEFT, padx=2)
        ttk.Label(log_bar, text="(右键菜单可复制选中内容)",
                  foreground='#888888').pack(side=tk.LEFT, padx=(10, 0))

        log_body = ttk.Frame(log_frame)
        log_body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.log_text = tk.Text(log_body, font=mono, wrap=tk.WORD, height=8)
        log_y = ttk.Scrollbar(log_body, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_y.set)
        log_body.grid_rowconfigure(0, weight=1)
        log_body.grid_columnconfigure(0, weight=1)
        self.log_text.grid(row=0, column=0, sticky='nsew')
        log_y.grid(row=0, column=1, sticky='ns')
        self.log_text.config(state=tk.DISABLED)
        self.log_text.bind('<Control-a>', self._log_select_all)
        self.log_text.bind('<Button-3>', self._show_log_menu)
        notebook.add(log_frame, text=' 运行日志 ')

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, relief=tk.SUNKEN, padding=(8, 2))
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(bar, textvariable=self.status_text).pack(side=tk.LEFT)
        self.xml_label = ttk.Label(bar, text="XML: 未加载", foreground='#666666')
        self.xml_label.pack(side=tk.RIGHT)

    # ---------------- 日志 ----------------
    def log(self, msg):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, str(msg) + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _log_get(self):
        """获取日志全文 (去除尾部空行)"""
        return self.log_text.get('1.0', tk.END).rstrip('\n')

    def _log_modify(self, fn):
        """在临时解除只读后对日志文本执行修改"""
        self.log_text.config(state=tk.NORMAL)
        try:
            fn()
        finally:
            self.log_text.config(state=tk.DISABLED)

    def log_copy_all(self):
        """复制全部日志到剪贴板"""
        content = self._log_get()
        if not content:
            self.status_text.set("日志为空, 无内容可复制")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_text.set(f"已复制全部日志到剪贴板 ({len(content)} 字符)")

    def _log_copy_selection(self):
        """复制日志中选中的内容"""
        try:
            content = self.log_text.get('sel.first', 'sel.last')
        except tk.TclError:
            content = ''
        if not content:
            self.status_text.set("未选中任何日志内容")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_text.set(f"已复制选中日志 ({len(content)} 字符)")

    def _log_select_all(self, event=None):
        """全选日志 (Ctrl+A / 右键菜单)"""
        self._log_modify(lambda: self.log_text.tag_add('sel', '1.0', tk.END))
        return 'break'

    def log_export(self):
        """导出日志到文本文件"""
        content = self._log_get()
        if not content:
            messagebox.showinfo("提示", "日志为空, 无内容可导出")
            return
        out = filedialog.asksaveasfilename(
            title="导出日志",
            initialfile="nv_read_log.txt",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not out:
            return
        try:
            with open(out, 'w', encoding='utf-8') as f:
                f.write(content + '\n')
            self.status_text.set(f"日志已导出: {out}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def log_clear(self):
        """清空日志"""
        self._log_modify(lambda: self.log_text.delete('1.0', tk.END))
        self.status_text.set("日志已清空")

    def _show_log_menu(self, event):
        """日志右键菜单"""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="复制选中内容", command=self._log_copy_selection)
        menu.add_command(label="全选", command=self._log_select_all)
        menu.add_command(label="复制全部日志", command=self.log_copy_all)
        menu.add_separator()
        menu.add_command(label="导出日志...", command=self.log_export)
        menu.add_command(label="清空日志", command=self.log_clear)
        menu.tk_popup(event.x_root, event.y_root)

    # ---------------- 文件操作 ----------------
    def open_nv_file(self):
        path = filedialog.askopenfilename(
            title="选择 NV 文件",
            filetypes=[("NV/二进制文件", "*.bin *.ubifs *.img *.nv"), ("所有文件", "*.*")])
        if not path:
            return
        self.load_nv(path)

    def load_nv(self, path):
        if self.nv_file is not None and self.nv_file.modified:
            if not messagebox.askyesno("未保存的修改",
                                       "当前 NV 文件有未保存的修改，打开新文件将丢弃修改，继续？"):
                return
        try:
            self.log("=" * 60)
            self.log(f"读取NV文件: {path}")
            self.nv_file = NVFile(path, log=self.log)
        except Exception as e:
            self.nv_file = None
            self.log(f"错误: {e}")
            messagebox.showerror("打开失败", f"解析 NV 文件失败:\n{e}")
            return

        self.nv_path.set(path)
        self.refresh_tree()
        self._update_title()
        fsize = os.path.getsize(path)
        self.status_text.set(
            f"已加载: {os.path.basename(path)}  |  大小 {fsize} 字节  |  "
            f"核心 {len(self.nv_file.cores)} 个  |  Items 共 {self.nv_file.total_items()} 个")

    def open_xml_file(self):
        path = filedialog.askopenfilename(
            title="选择 XML 定义文件 (如 udx710-module.xml)",
            filetypes=[("XML 文件", "*.xml"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            self.nv_defs = NVItemDefinition(path, log=self.log)
        except Exception as e:
            messagebox.showerror("加载失败", f"解析 XML 文件失败:\n{e}")
            return
        self.xml_path.set(path)
        self.xml_label.config(text=f"XML: {os.path.basename(path)}", foreground='#38761D')
        # 重新填充名称列
        self.refresh_tree()

    # ---------------- 树列表 ----------------
    def refresh_tree(self):
        """根据当前 NV 文件与过滤条件刷新树形列表"""
        self.tree.delete(*self.tree.get_children())
        self._tree_map.clear()
        if self.nv_file is None:
            return

        keyword = self.search_text.get().strip().lower()
        shown = 0

        for core_name, items in self.nv_file.items.items():
            core_node = None
            for item_id, item in items.items():
                name = self.nv_defs.get_name(item_id) if self.nv_defs else ""
                # 过滤: 匹配十六进制ID/十进制ID/名称
                if keyword:
                    id_hex = f"0x{item_id:04x}"
                    if (keyword not in id_hex.lower()
                            and keyword not in str(item_id)
                            and keyword not in name.lower()):
                        continue
                if core_node is None:
                    core_node = self.tree.insert(
                        '', tk.END, text=f"[{core_name}]",
                        values=('', '', f"({len(items)} items)", '', ''), open=True)
                iid = f"{core_name}:{item_id}"
                self.tree.insert(core_node, tk.END, iid=iid, text='',
                                 values=(f"0x{item_id:04X}", str(item_id), name,
                                         str(item.size), f"0x{item.offset:08X}"))
                self._tree_map[iid] = (core_name, item_id)
                shown += 1

        if keyword:
            self.status_text.set(f"过滤 '{keyword}': 匹配 {shown} 个 item")

    def clear_search(self):
        self.search_text.set('')
        self.refresh_tree()

    def on_tree_select(self, event=None):
        iid = self.tree.selection()
        if not iid or iid[0] not in self._tree_map:
            return
        core_name, item_id = self._tree_map[iid[0]]
        item = self.nv_file.items[core_name][item_id]
        self.show_item(core_name, item)

    def show_item(self, core_name, item):
        """显示选中 item 的详情与十六进制内容"""
        name = self.nv_defs.get_name(item.id) if self.nv_defs else ""
        self.info_vars['id'].set(f"0x{item.id:04X} ({item.id})")
        self.info_vars['name'].set(name if name else "(未知)")
        self.info_vars['core'].set(core_name)
        self.info_vars['size'].set(f"{item.size} 字节 (0x{item.size:X})")
        self.info_vars['offset'].set(f"0x{item.offset:08X}")

        # 大 item 限制显示前 256KB, 避免界面卡顿
        MAX_SHOW = 256 * 1024
        data = item.data
        truncated = len(data) > MAX_SHOW
        if truncated:
            data = data[:MAX_SHOW]

        text = format_hex(data, base_addr=item.offset + 4)
        if truncated:
            text += f"\n\n... (内容过大, 仅显示前 {MAX_SHOW} 字节, 共 {len(item.data)} 字节, 可导出查看完整数据)"

        self.hex_text.config(state=tk.NORMAL)
        self.hex_text.delete('1.0', tk.END)
        self.hex_text.insert('1.0', text)
        self.hex_text.tag_remove('offset_hl', '1.0', tk.END)  # 清除上次的偏移高亮
        self.hex_text.tag_remove('find_hl', '1.0', tk.END)    # 清除上次的查找高亮
        self.hex_text.config(state=tk.DISABLED)

    # ---------------- 右键菜单 ----------------
    def show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self._tree_map:
            return
        self.tree.selection_set(iid)
        core_name, item_id = self._tree_map[iid]

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="导出此 Item...", command=self.export_selected)
        menu.add_separator()
        menu.add_command(label=f"复制 ID (0x{item_id:04X})",
                         command=lambda: self._copy(f"0x{item_id:04X}"))
        menu.add_command(label=f"复制 ID ({item_id})",
                         command=lambda: self._copy(str(item_id)))
        menu.tk_popup(event.x_root, event.y_root)

    def _copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_text.set(f"已复制: {text}")

    # ---------------- 跳转 ----------------
    def goto_id(self):
        """跳转到指定 ID 的 item"""
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("跳转到 ID")
        dlg.geometry("320x120")
        dlg.transient(self.root)
        dlg.grab_set()
        ttk.Label(dlg, text="输入 Item ID (如 0x9C4 或 2500):").pack(padx=12, pady=(14, 4), anchor=tk.W)
        var = tk.StringVar()
        entry = ttk.Entry(dlg, textvariable=var)
        entry.pack(padx=12, fill=tk.X)
        entry.focus_set()

        def do_jump():
            item_id = parse_id_text(var.get())
            if item_id is None:
                messagebox.showerror("错误", "无效的 ID 格式", parent=dlg)
                return
            iid = None
            for key, (c, i) in self._tree_map.items():
                if i == item_id:
                    iid = key
                    break
            if iid is None:
                # 可能该 item 被过滤掉了
                core_name, item = self.nv_file.get_item_by_id(item_id)
                if item is None:
                    messagebox.showinfo("未找到", f"NV 文件中不存在 ID 0x{item_id:04X}", parent=dlg)
                    return
                self.clear_search()
                for key, (c, i) in self._tree_map.items():
                    if i == item_id:
                        iid = key
                        break
            dlg.destroy()
            if iid:
                self.tree.selection_set(iid)
                self.tree.see(iid)

        ttk.Button(dlg, text="跳转", command=do_jump).pack(pady=10)
        entry.bind('<Return>', lambda e: do_jump())

    # ---------------- 文件偏移定位 ----------------
    def goto_offset(self):
        """按文件偏移搜索定位所属 NV item 并高亮对应行"""
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("按文件偏移定位")
        dlg.geometry("360x130")
        dlg.transient(self.root)
        dlg.grab_set()
        ttk.Label(dlg, text="输入文件偏移地址 (如 0x204 或 516):").pack(
            padx=12, pady=(14, 4), anchor=tk.W)
        var = tk.StringVar()
        entry = ttk.Entry(dlg, textvariable=var)
        entry.pack(padx=12, fill=tk.X)
        entry.focus_set()

        def do_locate():
            off = parse_id_text(var.get())
            if off is None or off < 0:
                messagebox.showerror("错误", "无效的偏移格式", parent=dlg)
                return
            if self.locate_offset(off):
                dlg.destroy()
            else:
                fsize = os.path.getsize(self.nv_file.filepath)
                messagebox.showinfo(
                    "未找到",
                    f"偏移 0x{off:X} 不在任何 NV item 的数据范围内\n"
                    f"(文件大小: 0x{fsize:X})", parent=dlg)

        ttk.Button(dlg, text="定位", command=do_locate).pack(pady=10)
        entry.bind('<Return>', lambda e: do_locate())

    def locate_offset(self, off):
        """查找覆盖文件偏移 off 的 item, 选中并高亮。成功返回 True"""
        for core_name, items in self.nv_file.items.items():
            for item_id, item in items.items():
                # item 在文件中占用: 头部4字节 + 数据 + 4字节对齐填充
                align = (4 - (item.size % 4)) % 4
                start = item.offset
                end = item.offset + 4 + item.size + align  # 开区间
                if start <= off < end:
                    iid = f"{core_name}:{item_id}"
                    if iid not in self._tree_map:
                        self.clear_search()  # 偏移命中但被过滤时先清除过滤
                    if iid in self._tree_map:
                        self.tree.selection_set(iid)
                        self.tree.see(iid)
                    self.show_item(core_name, item)
                    self._highlight_offset(item, off)
                    self.log(f"偏移定位: 0x{off:X} -> 核心 '{core_name}' "
                             f"Item 0x{item_id:04X} (范围 0x{start:X} - 0x{end - 1:X})")
                    return True
        return False

    def _highlight_offset(self, item, off):
        """在 hex 视图中高亮包含目标偏移的行, 并在状态栏说明位置"""
        self.hex_text.config(state=tk.NORMAL)
        try:
            self.hex_text.tag_remove('offset_hl', '1.0', tk.END)
            data_start = item.offset + 4  # 数据区起始 (跳过4字节头部)
            if off < data_start:
                line_no, where = 1, "Item 头部 (ID/Length)"
            else:
                idx = off - data_start
                if idx < item.size:
                    line_no = idx // 16 + 1
                    where = f"数据区第 {idx} 字节"
                else:
                    line_no, where = None, "尾部对齐填充区"

            if line_no is not None:
                last_line = int(self.hex_text.index('end-1c').split('.')[0])
                if line_no <= last_line:
                    self.hex_text.tag_add('offset_hl', f"{line_no}.0", f"{line_no}.end")
                    self.hex_text.see(f"{line_no}.0")
        finally:
            self.hex_text.config(state=tk.DISABLED)

        self.status_text.set(
            f"偏移 0x{off:X} -> Item 0x{item.id:04X} ({where}), 已高亮对应行")

    # ---------------- Hex 数值查找 / Licence 一键查找 ----------------
    def find_hex_values(self):
        """在所有 NV item 数据中查找十六进制字节序列"""
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Hex 数值查找")
        dlg.geometry("460x145")
        dlg.transient(self.root)
        dlg.grab_set()
        ttk.Label(dlg, text="输入要查找的十六进制字节序列:").pack(padx=12, pady=(14, 2), anchor=tk.W)
        ttk.Label(dlg, text="支持格式: 01 02 AB CD / 0102ABCD / 0x01 0x02",
                  foreground='#888888').pack(padx=12, anchor=tk.W)
        var = tk.StringVar()
        entry = ttk.Entry(dlg, textvariable=var)
        entry.pack(padx=12, pady=4, fill=tk.X)
        entry.focus_set()

        def do_search():
            pat = parse_hex_bytes(var.get())
            if pat is None:
                messagebox.showerror("错误", "无效的十六进制序列\n(必须为偶数个十六进制字符)", parent=dlg)
                return
            results = []  # [(core_name, item, positions, more)]
            for core_name, items in self.nv_file.items.items():
                for item_id, item in items.items():
                    pos, more = search_bytes(item.data, pat)
                    if pos:
                        results.append((core_name, item, pos, more))
            dlg.destroy()
            if not results:
                self.log(f"Hex查找: 序列 {pat.hex(' ').upper()} 未找到")
                messagebox.showinfo("查找结果", f"未找到字节序列:\n{pat.hex(' ').upper()}")
                return
            hits = sum(len(r[2]) for r in results)
            self.log(f"Hex查找: 序列 {pat.hex(' ').upper()} 命中 {len(results)} 个 item, "
                     f"共约 {hits} 处匹配")
            self.status_text.set(f"Hex查找: 命中 {len(results)} 个 item")
            self._show_results_dialog(f"Hex 查找结果 - {pat.hex(' ').upper()}", results,
                                      export_prefix='hexfind', match_len=len(pat))

        ttk.Button(dlg, text="查找", command=do_search).pack(pady=6)
        entry.bind('<Return>', lambda e: do_search())

    def find_license(self):
        """一键查找 licence 相关 NV item (按 XML 名称或数据内容匹配) 并可导出"""
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return

        results = []  # [(core_name, item, None, False)]
        for core_name, items in self.nv_file.items.items():
            for item_id, item in items.items():
                name = self.nv_defs.get_name(item_id) if self.nv_defs else ''
                hit_by_name = 'licen' in name.lower()
                hit_by_data = b'licen' in item.data.lower()
                if hit_by_name or hit_by_data:
                    results.append((core_name, item, None, False))

        if not results:
            tip = "未找到 licence 相关的 NV item"
            if self.nv_defs is None:
                tip += "\n\n提示: 加载 XML 定义文件 (文件->加载XML) 可按 item 名称提高命中率"
            self.log("Licence一键查找: 无命中")
            messagebox.showinfo("Licence 查找", tip)
            return

        self.log(f"Licence一键查找: 命中 {len(results)} 个 item")
        for core_name, item, _, _ in results:
            name = self.nv_defs.get_name(item.id) if self.nv_defs else ''
            self.log(f"  [{core_name}] 0x{item.id:04X} ({item.id}) {name} - {item.size} 字节")
        self.status_text.set(f"Licence查找: 命中 {len(results)} 个 item")
        self._show_results_dialog("Licence 查找结果", results, export_prefix='licence')

    def _show_results_dialog(self, title, results, export_prefix='nvitem', match_len=1):
        """通用查找结果对话框: 双击跳转, 支持导出选中/全部
        results: [(core_name, item, positions_or_None, more)]
        match_len: 每个匹配的字节长度 (用于高亮整个匹配)
        """
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.geometry("820x440")
        dlg.transient(self.root)

        ttk.Label(dlg, text=f"共 {len(results)} 个匹配的 item (双击跳转并高亮匹配位置)",
                  padding=(8, 6)).pack(side=tk.TOP, anchor=tk.W)

        body = ttk.Frame(dlg)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8)
        cols = ('core', 'id_hex', 'id_dec', 'name', 'size', 'offset', 'matches')
        tree = ttk.Treeview(body, columns=cols, show='headings', selectmode='browse')
        heads = [('core', '核心', 90, tk.W), ('id_hex', 'ID(十六进制)', 95, tk.CENTER),
                 ('id_dec', 'ID(十进制)', 80, tk.E), ('name', '名称', 200, tk.W),
                 ('size', '大小', 70, tk.E), ('offset', '文件偏移', 95, tk.CENTER),
                 ('matches', '匹配数', 70, tk.E)]
        for key, text, w, anchor in heads:
            tree.heading(key, text=text)
            tree.column(key, width=w, anchor=anchor)
        scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=tree.yview)
        scroll_x = ttk.Scrollbar(body, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=scroll.set, xscrollcommand=scroll_x.set)
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky='nsew')
        scroll.grid(row=0, column=1, sticky='ns')
        scroll_x.grid(row=1, column=0, sticky='ew')  # 底部横向滚动滑块

        result_map = {}  # iid -> (core_name, item, positions)
        for idx, (core_name, item, positions, more) in enumerate(results):
            name = self.nv_defs.get_name(item.id) if self.nv_defs else ''
            if positions is None:
                matches_text = '-'
            else:
                matches_text = f"{len(positions)}+" if more else str(len(positions))
            iid = str(idx)
            tree.insert('', tk.END, iid=iid,
                        values=(core_name, f"0x{item.id:04X}", str(item.id), name,
                                str(item.size), f"0x{item.offset:08X}", matches_text))
            result_map[iid] = (core_name, item, positions)

        def get_selected():
            sel = tree.selection()
            return result_map.get(sel[0]) if sel else None

        def jump(event=None):
            r = get_selected()
            if r is None:
                return
            core_name, item, positions = r
            self._jump_to_match(core_name, item, positions, match_len)

        def export_sel():
            r = get_selected()
            if r is None:
                messagebox.showinfo("提示", "请先选中一条结果", parent=dlg)
                return
            self._export_pairs_to_dir([r[:2]], export_prefix, parent=dlg)

        def export_all_res():
            pairs = [(c, it) for c, it, _, _ in results]
            self._export_pairs_to_dir(pairs, export_prefix, parent=dlg)

        tree.bind('<Double-1>', jump)
        btns = ttk.Frame(dlg)
        btns.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=8)
        ttk.Button(btns, text="跳转选中", command=jump).pack(side=tk.LEFT)
        ttk.Button(btns, text="导出选中Item", command=export_sel).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(btns, text="一键导出全部", command=export_all_res).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(btns, text="关闭", command=dlg.destroy).pack(side=tk.RIGHT)

    def _jump_to_match(self, core_name, item, positions, match_len=1):
        """在主界面中选中并展示 item, 高亮所有匹配字节"""
        iid = f"{core_name}:{item.id}"
        if iid not in self._tree_map:
            self.clear_search()
        if iid in self._tree_map:
            self.tree.selection_set(iid)
            self.tree.see(iid)
        self.show_item(core_name, item)
        if positions:
            self._highlight_find_positions(item, positions, match_len)
            self.status_text.set(
                f"已跳转: Item 0x{item.id:04X}, 蓝色高亮 {len(positions)} 处匹配位置")

    def _highlight_find_positions(self, item, positions, plen):
        """在 hex 视图中精确高亮匹配的字节序列 (蓝色), 每个匹配覆盖 plen 个字节"""
        MAX_SHOW = 256 * 1024
        self.hex_text.config(state=tk.NORMAL)
        try:
            self.hex_text.tag_remove('find_hl', '1.0', tk.END)
            first_line = None
            tags = 0
            for idx in positions:
                if idx >= MAX_SHOW:
                    break
                for k in range(idx, idx + plen):
                    if k >= item.size or k >= MAX_SHOW:
                        break
                    line = k // 16 + 1
                    j = k % 16
                    col = 10 + j * 3 + (1 if j >= 8 else 0)  # 地址列10字符 + 每字节3字符
                    self.hex_text.tag_add('find_hl', f"{line}.{col}", f"{line}.{col + 2}")
                    if first_line is None:
                        first_line = line
                    tags += 1
                    if tags >= 3000:  # 限制 tag 数量避免卡顿
                        break
                if tags >= 3000:
                    break
            if first_line is not None:
                self.hex_text.see(f"{first_line}.0")
        finally:
            self.hex_text.config(state=tk.DISABLED)

    def _export_pairs_to_dir(self, pairs, prefix, parent=None):
        """将 (core_name, item) 列表批量导出到选定目录"""
        out_dir = filedialog.askdirectory(title="选择导出目录", parent=parent)
        if not out_dir:
            return
        count = 0
        try:
            for core_name, item in pairs:
                fname = f"{prefix}_{core_name}_0x{item.id:04X}_{item.id}.bin"
                with open(os.path.join(out_dir, fname), 'wb') as f:
                    f.write(item.data)
                count += 1
            self.log(f"已导出 {count} 个 item (前缀 {prefix}) 到目录: {out_dir}")
            self.status_text.set(f"导出完成: {count} 个 item -> {out_dir}")
            messagebox.showinfo("导出完成", f"已导出 {count} 个 item 到:\n{out_dir}",
                                parent=parent)
        except Exception as e:
            messagebox.showerror("导出失败", str(e), parent=parent)

    # ---------------- 导入替换 / 保存 ----------------
    def import_replace_item(self):
        """导入外部文件替换选中的 NV item (缝合在内存中进行, 保存后生效)"""
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return
        core_name, item = self._get_selected_item()
        if item is None:
            messagebox.showinfo("提示", "请先在左侧列表中选中要替换的 NV item")
            return

        path = filedialog.askopenfilename(
            title="选择用于替换的外部文件",
            filetypes=[("二进制文件", "*.bin"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                new_data = f.read()
        except Exception as e:
            messagebox.showerror("读取失败", str(e))
            return
        if not new_data:
            messagebox.showinfo("提示", "外部文件为空, 未执行替换")
            return
        if len(new_data) > 0xFFFF:
            messagebox.showerror("错误",
                f"文件过大: NV item 数据长度最大 65535 (0xFFFF) 字节\n"
                f"当前文件 {len(new_data)} 字节")
            return

        name = self.nv_defs.get_name(item.id) if self.nv_defs else ''
        ok = messagebox.askyesno(
            "确认替换",
            f"将用外部文件替换选中 item:\n\n"
            f"Item: 0x{item.id:04X} ({item.id}) {name}\n"
            f"所属核心: {core_name}\n"
            f"当前大小: {item.size} 字节\n"
            f"外部文件: {os.path.basename(path)} ({len(new_data)} 字节)\n\n"
            f"替换在内存中进行, 执行 保存/另存为 后才会写入文件。\n确认替换?")
        if not ok:
            return

        old_size = self.nv_file.replace_item(core_name, item.id, new_data)
        iid = f"{core_name}:{item.id}"
        if iid in self._tree_map:
            self.tree.set(iid, 'size', str(item.size))
        self.show_item(core_name, item)
        self.log(f"导入替换: [{core_name}] Item 0x{item.id:04X} <- {path} "
                 f"({old_size} -> {item.size} 字节), 尚未保存")
        self.status_text.set(f"Item 0x{item.id:04X} 已替换为外部文件 ({item.size} 字节), 保存后生效")
        self._update_title()

    def save_nv(self):
        """保存 NV 文件 (覆盖原文件)"""
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return
        if not self.nv_file.modified:
            messagebox.showinfo("提示", "没有需要保存的修改")
            return
        self._do_save(self.nv_file.filepath)

    def save_nv_as(self):
        """NV 文件另存为"""
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return
        path = filedialog.asksaveasfilename(
            title="NV 文件另存为",
            initialfile=os.path.basename(self.nv_file.filepath),
            filetypes=[("NV/二进制文件", "*.bin *.ubifs *.img *.nv"), ("所有文件", "*.*")])
        if not path:
            return
        self._do_save(path)

    def _do_save(self, path):
        try:
            self.nv_file.modified = False  # 避免重载时弹出未保存提示
            saved_path, size = self.nv_file.save(path)
        except Exception as e:
            self.nv_file.modified = True
            messagebox.showerror("保存失败", str(e))
            return
        self.log(f"NV 文件已缝合保存: {saved_path} ({size} 字节)")
        messagebox.showinfo("保存成功", f"已保存:\n{saved_path}\n大小: {size} 字节")
        # 重新加载以刷新各 item 偏移等内部状态
        self.load_nv(saved_path)

    def _update_title(self):
        title = APP_TITLE
        if self.nv_file is not None:
            title += f" - {os.path.basename(self.nv_file.filepath)}"
            if self.nv_file.modified:
                title += " *"
        self.root.title(title)
        if hasattr(self, 'modified_label'):
            self.modified_label.config(
                text="● 已修改未保存" if (self.nv_file and self.nv_file.modified) else "")

    def on_close(self):
        """关闭窗口前检查未保存修改"""
        if self.nv_file is not None and self.nv_file.modified:
            r = messagebox.askyesnocancel(
                "未保存的修改",
                "NV 文件有未保存的修改。\n\n是 = 保存并退出\n否 = 放弃修改退出\n取消 = 返回")
            if r is None:
                return
            if r:
                try:
                    self.nv_file.save()
                except Exception as e:
                    messagebox.showerror("保存失败", str(e))
                    return
        self.root.destroy()

    # ---------------- 导出 ----------------
    def _get_selected_item(self):
        iid = self.tree.selection()
        if not iid or iid[0] not in self._tree_map:
            return None, None
        core_name, item_id = self._tree_map[iid[0]]
        return core_name, self.nv_file.items[core_name][item_id]

    def export_selected(self):
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return
        core_name, item = self._get_selected_item()
        if item is None:
            messagebox.showinfo("提示", "请先在左侧列表中选中一个 NV item")
            return

        out = filedialog.asksaveasfilename(
            title="导出 NV Item",
            initialfile=f"nvitem_0x{item.id:04X}_{item.id}.bin",
            defaultextension=".bin",
            filetypes=[("二进制文件", "*.bin"), ("所有文件", "*.*")])
        if not out:
            return
        try:
            with open(out, 'wb') as f:
                f.write(item.data)
            self.log(f"已导出 NV item 0x{item.id:04X} (核心: {core_name}, "
                     f"大小: {item.size} 字节) -> {out}")
            self.status_text.set(f"导出成功: {out}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def export_all(self):
        if self.nv_file is None:
            messagebox.showinfo("提示", "请先打开 NV 文件")
            return
        out_dir = filedialog.askdirectory(title="选择导出目录")
        if not out_dir:
            return
        total = 0
        try:
            for core_name, items in self.nv_file.items.items():
                core_dir = os.path.join(out_dir, core_name)
                os.makedirs(core_dir, exist_ok=True)
                for item_id, item in items.items():
                    filepath = os.path.join(core_dir, f"nvitem_0x{item_id:04X}_{item_id}.bin")
                    with open(filepath, 'wb') as f:
                        f.write(item.data)
                    total += 1
            self.log(f"已导出 {total} 个 NV items 到目录: {out_dir}")
            self.status_text.set(f"导出完成: 共 {total} 个 items -> {out_dir}")
            messagebox.showinfo("导出完成", f"已导出 {total} 个 NV items 到:\n{out_dir}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    # ---------------- 关于 ----------------
    def show_about(self):
        messagebox.showinfo(
            "关于",
            f"{APP_TITLE} v{APP_VERSION}\n\n"
            "基于 read_nvitem.py 编写 (udx710 刷机程序源码分析)\n"
            "支持 INDX 标准格式与 UBI 格式的 NV 文件解析\n\n"
            "功能: 浏览/搜索 NV items、十六进制查看、按文件偏移定位、\n"
            "Hex 数值序列查找、Licence 一键查找与批量导出、\n"
            "导入外部文件替换 item、NV 文件缝合保存/另存为、日志复制/导出\n\n"
            "仅使用 Python 标准库 (tkinter) 实现")


def main():
    root = tk.Tk()
    app = NVReaderGUI(root)
    # 支持命令行直接传入 NV 文件路径
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        root.after(100, lambda: app.load_nv(sys.argv[1]))
    root.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())

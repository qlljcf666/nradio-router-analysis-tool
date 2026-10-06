# -*- coding: utf-8 -*-
"""
路由器固件图形化解包/打包工具
================================
兼容的固件族（均来自实测样本）：
  1. SF_BOOT 私有全 flash 镜像      例: C8-600_2.3.3.bin (SPI NAND, FIT+squashfs 定槽)
  2. GPT 分区 eMMC 裸镜像           例: C5800-688 (MT7981, kerne/rootf 分区)
  3. legacy uImage + squashfs       例: immortalwrt-ramips / ZX7621C6 sysupgrade
  4. OpenWrt sysupgrade tar + FWx0  例: QWRT huasifei hr6001 / wh3000
  5. 裸 UBI 镜像 (PEB 128K)         例: QWRT hr6001 nand-factory
  6. 私有头 + 裸 UBI                例: ZX7981PG sysupgrade (0x10000 前缀)

解包: 镜像 -> 工程目录(rootfs/ 可直接改文件 + kernel + _project.json + _manifest.jsonl ...)
打包: 工程目录 -> 新镜像 (rootfs 用内置纯 Python squashfs(xz) 写入器重打包)

依赖: tkinter(标准库) + PySquashfsImage (解包只读, pip install PySquashfsImage)
作者: 自动生成
"""
import hashlib
import json
import lzma
import os
import queue
import shutil
import stat
import struct
import sys
import threading
import time
import traceback
import zlib

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except Exception:
    tk = None

try:
    from PySquashfsImage import SquashFsImage
    HAVE_SQFS = True
except Exception:
    HAVE_SQFS = False

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
SQ_MAGIC = 0x73717368
SQ_BYTES = b'hsqs'
FIT_MAGIC = 0xD00DFEED
UBI_EC_MAGIC = 0x55424923
DEADC0DE = b'\xde\xad\xc0\xde'
FWX0 = b'FWx0'

SQ_INV = 0xFFFFFFFFFFFFFFFF
SQ_COMP_XZ = 4  # squashfs 压缩 ID: 1 zlib / 2 lzma / 3 lzo / 4 xz / 5 lz4 / 6 zstd
SQ_FLAG_COMP_OPT = 0x0400

T_DIR, T_REG, T_LNK, T_BLK, T_CHR, T_FIFO, T_SOCK = range(1, 8)
TYPE_FROM_STAT = {
    stat.S_IFDIR: T_DIR, stat.S_IFREG: T_REG, stat.S_IFLNK: T_LNK,
    stat.S_IFBLK: T_BLK, stat.S_IFCHR: T_CHR, stat.S_IFIFO: T_FIFO,
    stat.S_IFSOCK: T_SOCK,
}
TYPE_NAME = {T_DIR: 'dir', T_REG: 'reg', T_LNK: 'symlink', T_BLK: 'blk',
             T_CHR: 'chr', T_FIFO: 'fifo', T_SOCK: 'sock'}


class Canceled(Exception):
    pass


def be32(b, o=0):
    return struct.unpack('>I', b[o:o + 4])[0]


def align_up(v, a):
    return (v + a - 1) // a * a


# ---------------------------------------------------------------------------
# squashfs 超级块解析 / 搜索
# ---------------------------------------------------------------------------
def parse_sq_sb(buf, off):
    sb = buf[off:off + 96]
    if len(sb) < 96 or sb[:4] != SQ_BYTES:
        return None
    inodes, mtime, bsize, frags = struct.unpack('<IIII', sb[4:20])
    comp, blog, flags, no_ids = struct.unpack('<HHHH', sb[20:28])
    vmaj, vmin = struct.unpack('<HH', sb[28:32])
    root_ref, bytes_used = struct.unpack('<QQ', sb[32:48])
    if vmaj != 4 or comp not in (1, 2, 3, 4, 5, 6):
        return None
    if bsize < 4096 or bsize > 1048576 or (1 << blog) != bsize:
        return None
    if bytes_used == 0 or off + bytes_used > len(buf) + (1 << 20):
        return None
    return dict(off=off, inodes=inodes, mtime=mtime, block_size=bsize,
                fragments=frags, comp=comp, block_log=blog, flags=flags,
                no_ids=no_ids, version=(vmaj, vmin), root_ref=root_ref,
                bytes_used=bytes_used)


def find_squashfs(data, start=0, end=None, log=None):
    end = len(data) if end is None else min(end, len(data))
    p = start
    while True:
        i = data.find(SQ_BYTES, p, end)
        if i < 0:
            return None
        sb = parse_sq_sb(data, i)
        if sb:
            return sb
        p = i + 1


def fit_total(data, off):
    if off + 8 <= len(data) and be32(data, off) == FIT_MAGIC:
        ts = be32(data, off + 4)
        if 0x1000 < ts < 0x8000000 and off + ts <= len(data):
            return ts
    return None


COMP_NAME = {1: 'zlib', 2: 'lzma', 3: 'lzo', 4: 'xz', 5: 'lz4', 6: 'zstd'}

# ---------------------------------------------------------------------------
# 解包: squashfs 提取 + 清单
# ---------------------------------------------------------------------------
def win_long(p):
    if os.name == 'nt' and not p.startswith('\\\\?\\'):
        return '\\\\?\\' + os.path.abspath(p)
    return p


_WIN_BAD = set('<>:"|?*')
_WIN_RESERVED = {'CON', 'PRN', 'AUX', 'NUL'} | \
                {'COM%d' % i for i in range(1, 10)} | \
                {'LPT%d' % i for i in range(1, 10)}


def win_bad_name(rel):
    """检查相对路径中的组件是否无法在 Windows 文件系统原样落盘。"""
    for part in rel.split('/'):
        if not part:
            continue
        if any(c in _WIN_BAD or ord(c) < 32 for c in part):
            return True
        if part.endswith(' ') or part.endswith('.'):
            return True
        stem = part.split('.')[0].upper()
        if stem in _WIN_RESERVED:
            return True
    return False


def extract_squashfs(sq_bytes, dest, manifest_path, log, stop=None):
    """把 squashfs 镜像解包到 dest；特殊文件/符号链接/权限写入 JSONL 清单。
    Windows 无法原样落盘的文件名 (含 : 等) 转存到工程目录 _store/, 清单 q 字段记录键。"""
    img = SquashFsImage.from_bytes(sq_bytes)
    nreg = nlnk = nspec = ndir = nstored = 0
    store_dir = os.path.join(os.path.dirname(os.path.abspath(manifest_path)), '_store')
    used_lower = set()       # 已在磁盘实体化的路径 (小写, 相对)
    virtual_dirs = set()     # 大小写冲突/非法名 -> 未落盘的目录 (小写)
    recs = []                # 全部清单记录, 校验落盘后统一写文件
    by_path = {}

    def manifest(rec):
        recs.append(rec)

    def under_virtual(rl):
        parts = rl.split('/')
        cur = ''
        for part in parts[:-1]:
            cur = (cur + '/' + part) if cur else part
            if cur.lower() in virtual_dirs:
                return True
        return False

    def put_store(path, data):
        key = hashlib.sha1(path.encode('utf-8', 'surrogateescape')).hexdigest()
        os.makedirs(win_long(store_dir), exist_ok=True)
        with open(win_long(os.path.join(store_dir, key)), 'wb') as f:
            f.write(data)
        return key

    try:
        all_entries = list(img)
        for _e in all_entries:
            if _e.path:
                by_path[_e.path] = _e
        # 第一遍: 目录, 先确定哪些目录因非法名/大小写冲突需要虚拟化
        for e in all_entries:
            if not e.is_dir:
                continue
            rel = e.path.lstrip('/')
            if not rel:
                continue
            rl = rel.lower()
            fs_path = os.path.join(dest, *rel.split('/'))
            if win_bad_name(rel) or rl in used_lower or under_virtual(rl):
                # 非法名 / 与已有目录仅大小写不同 / 父目录已是虚拟目录 -> 不落盘
                virtual_dirs.add(rl)
            else:
                os.makedirs(win_long(fs_path), exist_ok=True)
                used_lower.add(rl)
                try:
                    os.chmod(win_long(fs_path), 0o755)
                except OSError:
                    pass
        # 第二遍: 清单 + 文件落盘/转存
        for scan_idx, e in enumerate(all_entries):
            if stop and stop.is_set():
                raise Canceled()
            path = e.path
            mode, uid, gid, mt = int(e.mode), int(e.uid), int(e.gid), int(e.time)
            rec = dict(p=path, m=mode, u=uid, g=gid, t=int(mt), o=scan_idx)
            rel = path.lstrip('/')
            fs_path = os.path.join(dest, *rel.split('/')) if rel else dest
            rl = rel.lower()
            illegal = bool(rel) and win_bad_name(rel)
            if e.is_dir:
                ndir += 1
                rec['k'] = 'd'
                manifest(rec)
            elif e.is_symlink:
                nlnk += 1
                rec['k'] = 'l'
                rec['x'] = e.readlink()
                manifest(rec)
            elif e.is_file:
                nreg += 1
                rec['k'] = 'f'
                rec['s'] = int(e.size)
                data = e.read_bytes()
                if illegal or under_virtual(rl) or rl in used_lower:
                    # 非法名 / 位于虚拟目录 / 大小写冲突 -> _store/<sha1(path)>
                    rec['q'] = put_store(path, data)
                    nstored += 1
                else:
                    os.makedirs(win_long(os.path.dirname(fs_path)), exist_ok=True)
                    with open(win_long(fs_path), 'wb') as f:
                        f.write(data)
                    used_lower.add(rl)
                manifest(rec)
            else:
                nspec += 1
                if e.is_block_device:
                    rec['k'] = 'b'
                elif e.is_char_device:
                    rec['k'] = 'c'
                elif e.is_fifo:
                    rec['k'] = 'p'
                else:
                    rec['k'] = 's'
                rec['maj'] = int(e.major)
                rec['min'] = int(e.minor)
                manifest(rec)
        # 第三遍: 校验普通文件确实落盘。杀毒软件(如 Defender)常把路由器
        # 二进制(3proxy/tcphump 等)异步隔离: 写入成功、数秒后文件消失。
        # 多轮检查; 丢失的文件改从镜像重新取内容转存 _store, 保证可重打包。
        quarantined = []
        for rnd in range(4):
            missing = []
            for rec in recs:
                if rec.get('k') != 'f' or rec.get('q'):
                    continue
                rel = rec['p'].lstrip('/')
                if not os.path.isfile(win_long(os.path.join(dest, *rel.split('/')))):
                    missing.append(rec)
            if not missing:
                break
            if rnd == 0 and missing:
                pass
            else:
                time.sleep(2)   # 等待异步扫描/隔离完成
            for rec in missing:
                e0 = by_path.get(rec['p'])
                if e0 is None:
                    continue
                rec['q'] = put_store(rec['p'], e0.read_bytes())
                nstored += 1
                quarantined.append(rec['p'])
        with open(manifest_path, 'w', encoding='utf-8') as mf:
            for rec in recs:
                mf.write(json.dumps(rec, ensure_ascii=False) + '\n')
    finally:
        img.close()
    if quarantined:
        log('警告: %d 个文件写入后被杀毒软件隔离, 已自动转存 _store 保证可重打包: %s'
            % (len(quarantined), ', '.join(quarantined[:5])
               + (' ...' if len(quarantined) > 5 else '')))
    log('squashfs 解包: 目录 %d, 普通文件 %d (其中 %d 个转存 _store), '
        '符号链接 %d, 设备/特殊文件 %d'
        % (ndir, nreg, nstored, nlnk, nspec))
    return dict(nreg=nreg, nlnk=nlnk, nspec=nspec, ndir=ndir, nstored=nstored)


# ---------------------------------------------------------------------------
# 纯 Python squashfs v4 (xz) 写入器
# ---------------------------------------------------------------------------
class _Node:
    __slots__ = ('name', 'kind', 'mode', 'uid', 'gid', 'mtime', 'target',
                 'maj', 'min', 'children', 'ino', 'size', 'data', 'disk_path',
                 'blocks_start', 'block_sizes', 'block_objs', 'ino_ref', 'dir_start',
                 'dir_off', 'dir_bytes', 'parent_ino', 'parent', 'tail', 'tail_cost',
                 'tail_inline', 'tail_blob', 'frag_idx', 'frag_off', 'dup_src', 'path')

    def __init__(self, name, kind):
        self.name = name
        self.kind = kind
        self.mode = 0o755 if kind == T_DIR else 0o644
        self.uid = self.gid = 0
        self.mtime = 0
        self.target = b''
        self.maj = self.min = 0
        self.children = []
        self.ino = 0
        self.size = 0
        self.data = None
        self.blocks_start = 0
        self.block_sizes = []
        self.block_objs = []
        self.ino_ref = (0, 0)
        self.dir_start = 0
        self.dir_off = 0
        self.dir_bytes = 0
        self.parent_ino = 1
        self.parent = None
        self.path = ''
        self.tail = None
        self.tail_cost = 0
        self.tail_inline = False
        self.tail_blob = None
        self.frag_idx = SQ_INV
        self.frag_off = 0
        self.dup_src = None


def _name_bytes(s):
    return s.encode('utf-8', 'surrogateescape')


def load_tree(rootdir, manifest_path, build_mtime, log):
    """合并磁盘内容与清单 -> 内存节点树 (root.name='')。"""
    meta = {}
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    meta[r['p']] = r
    except FileNotFoundError:
        pass

    root = _Node('', T_DIR)
    rm = meta.get('/')
    if rm:
        root.mode, root.uid, root.gid, root.mtime = rm['m'], rm['u'], rm['g'], rm['t']
    nodes = {'/': root}
    store_dir = os.path.join(os.path.dirname(os.path.abspath(manifest_path)), '_store')

    def get_dir(path):
        node = nodes.get(path)
        if node is not None:
            return node
        parts = path.strip('/').split('/')
        cur = ''
        d = root
        for part in parts:
            nxt = cur + '/' + part
            node = nodes.get(nxt)
            if node is None:
                node = _Node(part, T_DIR)
                rr = meta.get(nxt)
                if rr:
                    node.mode, node.uid, node.gid, node.mtime = rr['m'], rr['u'], rr['g'], rr['t']
                else:
                    node.mtime = build_mtime
                d.children.append(node)
                nodes[nxt] = node
            cur = nxt
            d = node
        return node

    # 1) 清单里的目录与特殊文件先建树
    for path, r in meta.items():
        if path == '/':
            continue
        k = r['k']
        parts = path.strip('/').split('/')
        name = parts[-1]
        parent_path = '/' + '/'.join(parts[:-1]) if len(parts) > 1 else '/'
        if k == 'd':
            d = get_dir(path)
            d.mode, d.uid, d.gid, d.mtime = r['m'], r['u'], r['g'], r['t']
            continue
        if k in ('l', 'b', 'c', 'p', 's'):
            d = get_dir(parent_path)
            node = _Node(name, {'l': T_LNK, 'b': T_BLK, 'c': T_CHR,
                                'p': T_FIFO, 's': T_SOCK}[k])
            node.mode, node.uid, node.gid, node.mtime = r['m'], r['u'], r['g'], r['t']
            if k == 'l':
                node.target = r['x'].encode('utf-8', 'surrogateescape')
            else:
                node.maj, node.min = r['maj'], r['min']
            d.children.append(node)
            nodes[path] = node
        elif k == 'f' and r.get('q'):
            # Windows 非法名文件: 内容在 _store/<q>
            stored = os.path.join(store_dir, r['q'])
            d = get_dir(parent_path)
            node = _Node(name, T_REG)
            node.mode, node.uid, node.gid, node.mtime = r['m'], r['u'], r['g'], r['t']
            node.disk_path = stored
            node.size = r['s']
            d.children.append(node)
            nodes[path] = node

    # 2) 磁盘上的真实文件/目录/符号链接 (覆盖/新增清单条目)
    new_files = 0
    for dirpath, dirnames, filenames in os.walk(rootdir, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, rootdir).replace('\\', '/')
            path = '/' + rel
            try:
                st = os.lstat(win_long(full))
            except OSError:
                continue
            kind = TYPE_FROM_STAT.get(stat.S_IFMT(st.st_mode))
            if kind is None:
                continue
            parts = path.strip('/').split('/')
            parent_path = '/' + '/'.join(parts[:-1]) if len(parts) > 1 else '/'
            d = get_dir(parent_path)
            existing = nodes.get(path)
            if kind == T_DIR:
                if existing is None:
                    existing = _Node(name, T_DIR)
                    existing.mtime = build_mtime
                    d.children.append(existing)
                    nodes[path] = existing
                continue
            if existing is not None:
                d.children.remove(existing)
                nodes.pop(path, None)
            node = _Node(name, kind)
            r = meta.get(path)
            if r:
                node.mode, node.uid, node.gid, node.mtime = r['m'], r['u'], r['g'], r['t']
            else:
                node.mode = st.st_mode
                node.uid = node.gid = 0
                node.mtime = build_mtime
                new_files += 1
            if kind == T_LNK:
                tgt = os.readlink(win_long(full))
                node.target = tgt.encode('utf-8', 'surrogateescape')
            elif kind == T_REG:
                node.disk_path = full
                node.size = st.st_size
            d.children.append(node)
            nodes[path] = node

    # 3) 清单普通文件: 磁盘上存在则读磁盘; 不存在时保留节点(disk_path=None),
    #    交给 build_squashfs 尝试从原镜像恢复(多为杀软隔离), 而不是静默丢文件。
    n_missing = 0
    for path, r in meta.items():
        if r['k'] != 'f':
            continue
        node = nodes.get(path)
        if node is not None:
            continue
        rel = path.lstrip('/')
        full = os.path.join(rootdir, *rel.split('/'))
        parts = path.strip('/').split('/')
        parent_path = '/' + '/'.join(parts[:-1]) if len(parts) > 1 else '/'
        d = get_dir(parent_path)
        node = _Node(parts[-1], T_REG)
        node.mode, node.uid, node.gid, node.mtime = r['m'], r['u'], r['g'], r['t']
        if os.path.isfile(win_long(full)):
            node.disk_path = full
        else:
            node.disk_path = None
            n_missing += 1
        node.size = r['s']
        d.children.append(node)
        nodes[path] = node
    if n_missing:
        log('警告: %d 个清单文件在磁盘上不存在(可能被杀毒软件隔离), '
            '打包时将尝试从原镜像恢复' % n_missing)

    # 按原厂 squashfs 的扫描(创建)顺序排序: fragment 分组/数据块写入都依赖
    # 同目录相邻文件的内容相关性, 顺序一致才能达到原厂压缩率。
    # 清单无记录的用户新增条目排末尾(按名)。
    order = {p: r.get('o', 1 << 62) for p, r in meta.items()}
    BIG = 1 << 62

    def sort_tree(n, path):
        def key(c):
            cp = ('/' + c.name) if path == '/' else (path + '/' + c.name)
            return (order.get(cp, BIG), _name_bytes(c.name))
        n.children.sort(key=key)
        for c in n.children:
            if c.kind == T_DIR:
                cp = ('/' + c.name) if path == '/' else (path + '/' + c.name)
                sort_tree(c, cp)
    sort_tree(root, '/')
    if new_files:
        log('发现 %d 个新增文件 (默认 root:root 0644)' % new_files)
    return root


def _xz_block(raw, block_size):
    """压缩一个 squashfs 数据/元数据块; 在多组 lc/lp 参数中取最短输出
    (不同数据构成对 literal/position 位宽偏好不同; 逐块取优不影响解压,
    xz 流头自带过滤器参数, 内核按流头解码)。 """
    best = None
    for extra in (None, {'lc': 1, 'lp': 2}, {'lc': 2, 'lp': 1}):
        f = {'id': lzma.FILTER_LZMA2, 'preset': 6, 'dict_size': block_size}
        if extra:
            f.update(extra)
        c = lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE,
                          filters=[f])
        if best is None or len(c) < len(best):
            best = c
    if len(best) >= len(raw):
        return None
    return best


class _MDWriter:
    """表内相对偏移的元数据写入器: 未压缩块 8192 字节, 块满即 xz 压缩并确定
    下一块的磁盘偏移。ref_here() 返回 (当前块相对表起始的磁盘偏移,
    块内未压缩偏移) —— 这正是 squashfs inode/目录引用的语义。"""
    def __init__(self):
        self.blobs = []        # 已完成块的磁盘字节 (u16 头 + 数据)
        self.cur = bytearray()
        self.cur_start = 0     # 当前块起始的相对磁盘偏移

    @staticmethod
    def _finalize(blk):
        c = lzma.compress(bytes(blk), format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE,
                          filters=[{'id': lzma.FILTER_LZMA2, 'preset': 6}])
        if blk and len(c) < len(blk):
            return struct.pack('<H', len(c)) + c
        return struct.pack('<H', len(blk) | 0x8000) + bytes(blk)

    def _rollover(self):
        self.blobs.append(self._finalize(self.cur))
        self.cur_start += len(self.blobs[-1])
        self.cur = bytearray()

    def write(self, b):
        b = bytes(b)
        while b:
            room = 8192 - len(self.cur)
            if room == 0:
                self._rollover()
                room = 8192
            chunk = b[:room]
            self.cur += chunk
            b = b[len(chunk):]

    def ref_here(self):
        return (self.cur_start, len(self.cur))

    def finish(self):
        if self.cur or not self.blobs:
            self._rollover()
        return b''.join(self.blobs)


def build_squashfs(rootdir, manifest_path, out_path, block_size, mtime_base,
                   log, stop=None, orig_lookup=None):
    tree = load_tree(rootdir, manifest_path, mtime_base, log)

    # inode 编号: root=1, DFS 前序 (目录与文件统一)
    all_nodes = []

    def assign(n, parent_node, ppath):
        n.parent = parent_node
        n.path = ppath
        n.parent_ino = parent_node.ino if parent_node is not None else 1
        n.ino = len(all_nodes) + 1
        all_nodes.append(n)
        for c in n.children:
            cp = ('/' + c.name) if ppath == '/' else (ppath + '/' + c.name)
            assign(c, n, cp)
    assign(tree, None, '/')

    # ---- 第一遍: 读取文件, 压缩完整块; 对每个尾部试压缩(独立块) ----
    nfile = nblk = 0
    tail_nodes = []
    chain_keys = {}   # node -> [每个数据块压缩后字节的 sha1] (用于去重复用)
    for n in all_nodes:
        if n.kind != T_REG:
            continue
        nfile += 1
        if not n.disk_path or not os.path.isfile(win_long(n.disk_path)):
            if orig_lookup is not None:
                buf = orig_lookup(n.path)
                if buf is not None:
                    log('squashfs: %s 磁盘文件丢失(可能被杀毒软件隔离), '
                        '已从原镜像取原始内容打包' % n.path)
            else:
                buf = None
            if buf is None:
                raise RuntimeError(
                    '打包文件丢失: %s —— 内容文件在磁盘上不存在(可能被杀毒软件隔离)。'
                    '请将解包目录加入杀软白名单后重新解包; sf_boot/GPT/UBI 工程可自动从'
                    '_base.bin 恢复, tar/uImage 工程需重新解包' % n.path)
        else:
            with open(win_long(n.disk_path), 'rb') as f:
                buf = f.read()
        n.size = len(buf)
        nfull, rem = divmod(len(buf), block_size)
        sizes, objs, keys = [], [], []
        for bi in range(nfull):
            if stop and stop.is_set():
                raise Canceled()
            raw = buf[bi * block_size:(bi + 1) * block_size]
            c = _xz_block(raw, block_size)
            if c is None:
                sizes.append(len(raw) | 0x01000000)
                objs.append(raw)
            else:
                sizes.append(len(c))
                objs.append(c)
            keys.append(hashlib.sha1(objs[-1]).digest())
            nblk += 1
        chain_keys[n] = keys
        if rem:
            tail = buf[nfull * block_size:]
            n.tail = tail
            if nfull > 0:
                # 实测多家原厂镜像规则: 大文件(>=block_size)的尾部一律作为
                # 最后一个普通数据块内联; 只有小文件(<block_size)才进 fragment 组
                n.tail_inline = True
                n.tail_blob = _xz_block(tail, block_size)
            else:
                n.tail_blob = None
                tail_nodes.append(n)
        n.block_sizes, n.block_objs = sizes, objs
        del buf
    log('squashfs: %d 个普通文件, %d 个完整数据块, %d 个尾部块待分配'
        % (nfile, nblk, len(tail_nodes)))

    # ---- fragment 分组 (全部 8 个样本镜像的统一规则):
    # 仅小文件(<block_size)的内容进入 fragment; 按 inode DFS 顺序以原始容量
    # 256K 贪心装满, 不做跨组回填; 内容完全相同的尾部复用已有偏移。 ----
    frag_raw_groups = []    # [(raw, members)]
    cur = bytearray()
    cur_members = []
    n_inline = sum(1 for n in all_nodes if n.kind == T_REG and n.tail_inline)
    n_dup = 0
    dup_map = {}            # 尾部 sha1 -> 已入组的同源 node

    def finalize(raw, mem):
        idx = len(frag_raw_groups)
        frag_raw_groups.append((bytes(raw), mem))
        for m, off in mem:
            m.frag_idx = idx
            m.frag_off = off

    for n in tail_nodes:
        if stop and stop.is_set():
            raise Canceled()
        tail = n.tail
        tkey = hashlib.sha1(tail).digest()
        src = dup_map.get(tkey)
        if src is not None:
            n.dup_src = src
            n_dup += 1
            continue
        if len(cur) + len(tail) > block_size:
            finalize(cur, cur_members)
            cur, cur_members = bytearray(), []
        off = len(cur)
        cur += tail
        cur_members.append((n, off))
        dup_map[tkey] = n
    if cur_members:
        finalize(cur, cur_members)
    for n in tail_nodes:
        s = n.dup_src
        if s is not None:
            n.frag_idx = s.frag_idx
            n.frag_off = s.frag_off
    if n_dup:
        log('squashfs: 尾部去重 %d 个 (复用已有 fragment 位置)' % n_dup)
    log('squashfs: 尾部分配完成: 大文件尾部内联 %d 个, fragment 块 %d 个 (含尾部 %d 个)'
        % (n_inline, len(frag_raw_groups),
           sum(len(m) for _, m in frag_raw_groups)))

    # ---- 数据块落盘: 完整块+内联尾部按 inode 顺序写;
    # 完全相同的块链复用历史物理位置: 整链相同的文件不贡献新块(可在任意位置
    # 引用); 前缀相同且前缀终点恰为当前写指针时, 后续块接着写。 ----
    data_off = 96 + 2 + 8  # 超级块 + xz compopt 元数据块
    p = data_off
    block_cache = {}        # 压缩块 sha1 -> set(出现过的绝对偏移)
    n_reuse_files = saved_bytes = 0
    for n in all_nodes:
        if n.kind != T_REG:
            continue
        keys = list(chain_keys.get(n, ()))
        size_fields = list(n.block_sizes)
        blobs = list(n.block_objs)
        if n.tail_inline:
            tblob = n.tail_blob if n.tail_blob is not None else n.tail
            keys.append(hashlib.sha1(tblob).digest())
            size_fields.append(
                len(tblob) | (0 if n.tail_blob is not None else 0x01000000))
            blobs.append(tblob)
        match_len = 0
        match_start = None
        if keys and keys[0] in block_cache:
            # 优先整链复用; 再找"终点==当前写指针"的最长前缀
            for start in sorted(block_cache[keys[0]]):
                pos = start
                m = 0
                for k, sf in zip(keys, size_fields):
                    if pos not in block_cache.get(k, ()):
                        break
                    pos += sf & 0xffffff
                    m += 1
                if m == len(keys):
                    match_len, match_start = m, start
                    break
                if pos == p and m > match_len:
                    match_len, match_start = m, start
        if keys and match_len == len(keys):
            n.blocks_start = match_start
            n.block_sizes = size_fields
            n.block_objs = []
            n_reuse_files += 1
            saved_bytes += sum(sf & 0xffffff for sf in size_fields)
        elif match_len > 0:
            n.blocks_start = match_start
            n.block_sizes = size_fields
            n.block_objs = blobs[match_len:]
            n_reuse_files += 1
            saved_bytes += sum(sf & 0xffffff
                               for sf in size_fields[:match_len])
            for k, sf in zip(keys[match_len:], size_fields[match_len:]):
                block_cache.setdefault(k, set()).add(p)
                p += sf & 0xffffff
        else:
            n.blocks_start = p
            for k, sf in zip(keys, size_fields):
                block_cache.setdefault(k, set()).add(p)
                p += sf & 0xffffff
            n.block_sizes = size_fields
            n.block_objs = blobs
    if n_reuse_files:
        log('squashfs: 数据去重: %d 个文件复用历史块链, 少写 %.2f MiB'
            % (n_reuse_files, saved_bytes / 1048576))
    log('squashfs: 数据区 %d 字节' % (p - data_off))

    # ---- fragment 数据块正式压缩 (preset6) 并定位 ----
    frag_entries = []          # (start_abs, size_field)
    frag_data_blobs = []       # 实际写入字节
    for raw, members in frag_raw_groups:
        if stop and stop.is_set():
            raise Canceled()
        start = p
        c = _xz_block(raw, block_size)
        if c is None:
            blob, size_field = bytes(raw), len(raw) | 0x01000000
        else:
            blob, size_field = c, len(c)
        frag_entries.append((start, size_field))
        frag_data_blobs.append(blob)
        p += len(blob)
    log('squashfs: fragment 区 %d 字节, %d 块'
        % (sum(len(b) for b in frag_data_blobs), len(frag_entries)))

    ids = {}

    def id_idx(v):
        if v not in ids:
            ids[v] = len(ids)
        return ids[v]

    def inode_bytes(n):
        # 基础 inode 头: type/mode/uid/gid(u16*4) + mtime/inode_number(u32*2) = 16
        basic = struct.pack('<HHHHII', n.kind, n.mode & 0xFFFF, id_idx(n.uid),
                            id_idx(n.gid), n.mtime & 0xFFFFFFFF, n.ino)
        if n.kind == T_DIR:
            return basic + struct.pack('<IIHHI', n.dir_start, 1,
                                       n.dir_bytes + 3, n.dir_off, n.parent_ino)
        if n.kind == T_REG:
            b = basic + struct.pack('<IIII', n.blocks_start,
                                    n.frag_idx & 0xFFFFFFFF, n.frag_off,
                                    n.size & 0xFFFFFFFF)
            b += b''.join(struct.pack('<I', s) for s in n.block_sizes)
            return b
        if n.kind == T_LNK:
            return basic + struct.pack('<II', 1, len(n.target)) + n.target
        if n.kind in (T_BLK, T_CHR):
            rdev = (n.maj << 8) | n.min
            return basic + struct.pack('<II', 1, rdev)
        return basic + struct.pack('<I', 1)  # fifo/socket

    # ---- 后序交错发射 inode 表与目录表 ----
    # squashfs 的 inode 引用 = (相对 inode 表起始的磁盘块偏移, 块内未压缩偏移);
    # 目录 inode 的 dir_table_start 是相对目录表起始的磁盘偏移。
    # 两者相互引用, 必须按"子 inode → 本目录目录项 → 本目录 inode"后序写入,
    # 保证写入引用时被引用块的磁盘偏移已经确定。
    ino_w = _MDWriter()
    dir_w = _MDWriter()

    def emit(n):
        for c in n.children:
            emit(c)
        if n.kind == T_DIR:
            if not n.children:
                n.dir_bytes = 0
                n.dir_start = n.dir_off = 0
            else:
                n.dir_start, n.dir_off = dir_w.ref_here()
                # 分组: 子 inode 所在磁盘块变化 / delta 超 i16 / 每组最多 256
                groups, cur = [], []
                for c in n.children:
                    if cur:
                        hblk, hnum = cur[0].ino_ref[0], cur[0].ino
                        if c.ino_ref[0] != hblk or c.ino - hnum > 32767 or len(cur) >= 256:
                            groups.append(cur)
                            cur = []
                    cur.append(c)
                if cur:
                    groups.append(cur)
                total = 0
                for grp in groups:
                    first = grp[0]
                    hblk, hnum = first.ino_ref[0], first.ino
                    hdr = struct.pack('<III', len(grp) - 1, hblk, hnum)
                    dir_w.write(hdr)
                    total += len(hdr)
                    for c in grp:
                        _, off = c.ino_ref
                        nb = _name_bytes(c.name)
                        ent = struct.pack('<HhHH', off, c.ino - hnum, c.kind,
                                          len(nb) - 1) + nb
                        dir_w.write(ent)
                        total += len(ent)
                n.dir_bytes = total
        n.ino_ref = ino_w.ref_here()
        ino_w.write(inode_bytes(n))

    emit(tree)
    ino_blob = ino_w.finish()
    dir_blob = dir_w.finish()

    # ---- 输出布局 ----
    inode_table_start = p

    def table_blob(records, rec_fmt, base_off):
        """通用 id/fragment 表: 记录按 8192 切块做元数据块(xz), 后跟每块一个 Q 绝对指针。
        返回 (完整字节, 索引区起始绝对偏移, 索引区长度)。"""
        body = b''.join(struct.pack(rec_fmt, *r) for r in records)
        chunks = [body[i:i + 8192] for i in range(0, len(body), 8192)] or [b'']
        meta = bytearray()
        ptrs = []
        for ch in chunks:
            ptrs.append(base_off + len(meta))
            c = lzma.compress(ch, format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE,
                              filters=[{'id': lzma.FILTER_LZMA2, 'preset': 6}])
            if ch and len(c) < len(ch):
                meta += struct.pack('<H', len(c)) + c
            else:
                meta += struct.pack('<H', len(ch) | 0x8000) + ch
        index_pos = base_off + len(meta)
        index = b''.join(struct.pack('<Q', q) for q in ptrs)
        return bytes(meta) + index, index_pos, len(index)

    dir_table_start = inode_table_start + len(ino_blob)

    frag_meta_off = dir_table_start + len(dir_blob)
    frag_blob, frag_index_off, frag_index_len = table_blob(
        [(st, sf, 0) for st, sf in frag_entries], '<QII', frag_meta_off)
    id_meta_off = frag_index_off + frag_index_len
    id_blob, id_index_off, id_index_len = table_blob(
        [(v,) for v in sorted(ids.keys())], '<I', id_meta_off)
    bytes_used = id_index_off + id_index_len

    root_ref = (tree.ino_ref[0] << 16) | tree.ino_ref[1]
    id_vals = sorted(ids.keys())

    with open(out_path, 'wb') as f:
        sb = struct.pack('<IIIIIHHHHHH', SQ_MAGIC, len(all_nodes), mtime_base & 0xFFFFFFFF,
                         block_size, len(frag_entries), SQ_COMP_XZ,
                         {4096: 12, 8192: 13, 16384: 14, 32768: 15,
                          65536: 16, 131072: 17, 262144: 18, 524288: 19,
                          1048576: 20}[block_size],
                         SQ_FLAG_COMP_OPT, len(id_vals), 4, 0)
        sb += struct.pack('<QQ', root_ref, bytes_used)
        sb += struct.pack('<Q', id_index_off)          # id_table_start
        sb += struct.pack('<Q', SQ_INV)                # xattr
        sb += struct.pack('<Q', inode_table_start)
        sb += struct.pack('<Q', dir_table_start)
        sb += struct.pack('<Q', frag_index_off if frag_entries else SQ_INV)
        sb += struct.pack('<Q', SQ_INV)                # lookup (省略, 内核不要求)
        assert len(sb) == 96
        f.write(sb)
        # xz comp options: u16(8 uncompressed) + dict_size + flags
        f.write(struct.pack('<H', 8 | 0x8000))
        f.write(struct.pack('<II', block_size, 0))
        # 文件完整数据块
        for n in all_nodes:
            if n.kind == T_REG:
                for blob in n.block_objs:
                    f.write(blob)
        # fragment 数据块 (与表项顺序一致, 位置即 inode_table_start 之前)
        for blob in frag_data_blobs:
            f.write(blob)
        f.write(ino_blob)
        f.write(dir_blob)
        f.write(frag_blob)
        f.write(id_blob)
    log('squashfs 写入完成: %d 字节, inode %d, fragment %d, ids %d'
        % (bytes_used, len(all_nodes), len(frag_entries), len(id_vals)))
    return bytes_used


# ---------------------------------------------------------------------------
# tar 处理
# ---------------------------------------------------------------------------
def tar_parse(data):
    members = []
    o = 0
    while o + 512 <= len(data):
        h = data[o:o + 512]
        if h == b'\x00' * 512:
            break
        name = h[:100].split(b'\x00')[0].decode('utf-8', 'replace')
        prefix = h[345:500].split(b'\x00')[0].decode('utf-8', 'replace')
        if prefix:
            name = prefix + '/' + name
        szfield = h[124:136].split(b'\x00')[0] or b'0'
        size = int(szfield or b'0', 8)
        typ = h[156] if h[156] else b'0'
        members.append(dict(off=o, name=name, size=size, type=bytes([typ]),
                            header=h))
        o += 512 + ((size + 511) // 512) * 512
    return members, o


def tar_set_size(hdr, size):
    h = bytearray(hdr)
    h[124:136] = b'%011o\x00' % size
    for i in range(148, 156):
        h[i] = 0x20
    chk = sum(h) & 0xFFFF
    h[148:156] = b'%06o\x00 ' % chk
    return bytes(h)


# ---------------------------------------------------------------------------
# UBI 解析
# ---------------------------------------------------------------------------
def ubi_scan(data, base=0, log=lambda s: None):
    peb = 0x20000
    npeb = (len(data) - base) // peb
    volumes = {}
    pebs = []
    for i in range(npeb):
        p = base + i * peb
        if be32(data, p) != UBI_EC_MAGIC:
            continue
        vid_off = be32(data, p + 16)
        data_off = be32(data, p + 20)
        vp = p + vid_off
        kind = 'free'
        vol_id = lnum = None
        if be32(data, vp) == 0x55424921:
            vol_id = be32(data, vp + 8)
            lnum = be32(data, vp + 12)
            if vol_id == 0x7FFFEFFF:
                kind = 'layout'
            else:
                kind = 'vol'
        pebs.append(dict(idx=i, kind=kind, vol=vol_id, lnum=lnum,
                         data_off=p + data_off, vid_off=vp))
    # vtbl
    layout = [x for x in pebs if x['kind'] == 'layout']
    vtbl = []
    if layout:
        vp = layout[0]['data_off']
        for k in range(128):
            r = data[vp + k * 172: vp + (k + 1) * 172]
            nl = struct.unpack('>H', r[14:16])[0]
            name = r[16:16 + nl].decode('utf-8', 'replace')
            res = be32(r, 0)
            if res and name:
                vtbl.append(dict(id=k, name=name, reserved=res,
                                 flags=r[144], type=r[12]))
    for v in vtbl:
        vls = sorted([x for x in pebs if x['kind'] == 'vol' and x['vol'] == v['id']],
                     key=lambda x: x['lnum'])
        v['pebs'] = vls
        volumes[v['name']] = v
    # LEB = PEB - data_offset (样本均为 0x1f000)
    vid_hdr_off = be32(data, base + 16)
    data_hdr_off = be32(data, base + 20)
    leb = peb - data_hdr_off
    return dict(peb=peb, leb=leb, npeb=npeb, base=base,
                vid_off=vid_hdr_off, data_off=data_hdr_off,
                pebs=pebs, vtbl=vtbl, volumes=volumes)


def ubi_volume_payload(data, info, vol_name, trim_fit=False, sq_size=None):
    v = info['volumes'][vol_name]
    buf = bytearray()
    for x in v['pebs']:
        buf += data[x['data_off']:x['data_off'] + info['leb']]
    if trim_fit and buf[:4] == b'\xd0\x0d\xfe\xed':
        ts = be32(buf, 4)
        if ts <= len(buf):
            del buf[ts:]
    if sq_size is not None:
        del buf[sq_size:]
    return bytes(buf)


def _write_volume(out, info, pebs, blob, name, fill_free=True):
    """把 blob 就地写入某卷各 PEB 的数据区 (blob 不含任何 UBI 头)。"""
    leb, peb = info['leb'], info['peb']
    need = (len(blob) + leb - 1) // leb
    if need > len(pebs):
        raise RuntimeError(
            '%s 需要 %d 个 PEB, 原卷仅 %d 个 (本工具不重建 UBI 布局, 请缩小内容)'
            % (name, need, len(pebs)))
    for i, x in enumerate(pebs):
        p = x['data_off']
        if i < need:
            chunk = blob[i * leb:(i + 1) * leb]
            if len(chunk) < leb:
                chunk = chunk + b'\xff' * (leb - len(chunk))
            out[p:p + leb] = chunk
        elif fill_free:
            # 释放多余 LEB: 数据区擦 FF (保留 EC/VID 头, VID 指向关系不变)
            out[p:p + leb] = b'\xff' * leb


def ubi_patch(base, info, root_vol, sq, log, stop=None,
              kernel_vol=None, kernel_blob=None):
    """在原镜像字节数组上改写 root 卷 (及可选 kernel 卷), 返回新 bytes。"""
    out = bytearray(base)
    rv = info['volumes'][root_vol]
    rpebs = rv['pebs']
    leb, peb = info['leb'], info['peb']
    need = (len(sq) + leb - 1) // leb
    if need > len(rpebs):
        raise RuntimeError(
            '新 rootfs 需要 %d 个 PEB, 原卷仅 %d 个 (本工具不重建 UBI 布局, '
            '请缩小 rootfs)' % (need, len(rpebs)))
    for i, x in enumerate(rpebs):
        if stop and stop.is_set():
            raise Canceled()
        p = x['data_off']
        if i < need:
            chunk = sq[i * leb:(i + 1) * leb]
            if len(chunk) < leb:
                chunk = chunk + b'\xff' * (leb - len(chunk))
            out[p:p + leb] = chunk
        else:
            # 释放多余 LEB: VID+数据区擦为 FF (保留 EC 头)
            pend = info['base'] + (x['idx'] + 1) * peb
            out[x['vid_off']:pend] = b'\xff' * (pend - x['vid_off'])
    log('UBI: rootfs 写入 %d PEB (原 %d), 释放 %d PEB'
        % (need, len(rpebs), max(0, len(rpebs) - need)))
    if kernel_vol is not None and kernel_blob is not None:
        kpebs = info['volumes'][kernel_vol]['pebs']
        _write_volume(out, info, kpebs, kernel_blob, 'kernel')
        log('UBI: kernel 写入 %d PEB (卷共 %d)'
            % ((len(kernel_blob) + leb - 1) // leb, len(kpebs)))
    return bytes(out)


# ---------------------------------------------------------------------------
# 格式识别
# ---------------------------------------------------------------------------
def identify(path, log=lambda s: None):
    with open(path, 'rb') as f:
        data = f.read()
    size = len(data)
    desc = dict(path=path, size=size)

    if data[:7] == b'SF_BOOT':
        sq = find_squashfs(data, 0x1000, size, log)
        # kernel: 0xe0000 处 FIT (兼容搜索)
        koff = 0xe0000
        ksz = fit_total(data, koff)
        if ksz is None:
            koff = data.rfind(b'\xd0\x0d\xfe\xed', 0, sq['off'] if sq else size)
            ksz = fit_total(data, koff) if koff >= 0 else None
        desc.update(fmt='sf_boot', fmt_name='SF_BOOT 私有全 flash 镜像 (SPI NAND)',
                    sq=sq, kernel_off=koff, kernel_size=ksz,
                    parts=[
                        ('boot/头部', 0, sq['off'] if sq else koff, 'SF_BOOT/BRLYT/uboot/FIT 引导区'),
                        ('kernel', koff, ksz, 'FIT uImage'),
                        ('rootfs', sq['off'], sq['bytes_used'],
                         'squashfs %s' % COMP_NAME.get(sq['comp'], sq['comp'])),
                    ])
        return desc

    if data[257:262] == b'ustar':
        members, tar_end = tar_parse(data)
        km = next((m for m in members if m['name'].endswith('/kernel')), None)
        rm = next((m for m in members if m['name'].endswith('/root')), None)
        cm = next((m for m in members if m['name'].endswith('/CONTROL')), None)
        sq = find_squashfs(data, rm['off'] if rm else 0,
                           (rm['off'] + rm['size']) if rm else size) if rm else None
        board = members[0]['name'].strip('/').split('/')[0] if members else '?'
        # tar 结束 (双零块) 之后的 JSON 元数据
        json_off = -1
        mv = data.find(b'metadata_version', tar_end)
        if mv >= 0:
            json_off = data.rfind(b'{', tar_end, mv + 1)
        desc.update(fmt='sysupgrade_tar',
                    fmt_name='OpenWrt sysupgrade tar (kernel+root+FWx0)',
                    sq=sq, members=members, tar_end=tar_end,
                    json_off=json_off,
                    board=board,
                    parts=[
                        ('tar 目录', 0, tar_end, '%s (成员 %d)' % (board, len(members))),
                        ('kernel', km['off'] + 512, km['size'], 'tar 成员 (FIT)'),
                        ('rootfs', sq['off'], sq['bytes_used'],
                         'squashfs %s' % COMP_NAME.get(sq['comp'], sq['comp'])),
                    ])
        if cm:
            desc['control'] = data[cm['off'] + 512: cm['off'] + 512 + cm['size']]
        return desc

    if be32(data, 0) == UBI_EC_MAGIC or (
            size > 0x10000 and be32(data, 0x10000) == UBI_EC_MAGIC):
        base = 0 if be32(data, 0) == UBI_EC_MAGIC else 0x10000
        info = ubi_scan(data, base, log)
        kv = rv = None
        for name, v in info['volumes'].items():
            if not v['pebs']:
                continue
            head = data[v['pebs'][0]['data_off']:v['pebs'][0]['data_off'] + 4]
            if head == SQ_BYTES and rv is None:
                rv = name
            if head == b'\xd0\x0d\xfe\xed' and kv is None:
                kv = name
        sq = None
        if rv:
            off = info['volumes'][rv]['pebs'][0]['data_off']
            sq = find_squashfs(data, off, off + 4)
            # 卷内 sb 起点就是 data_off
            sb = parse_sq_sb(data, off)
            if sb:
                sq = sb
        desc.update(fmt='raw_ubi', base=base, ubi=info,
                    kernel_vol=kv, root_vol=rv, sq=sq,
                    fmt_name=('裸 UBI 镜像 (PEB %dK)' % (info['peb'] // 1024)) +
                    (('，前缀 %d 字节私有头' % base) if base else ''))
        parts = []
        if base:
            parts.append(('私有头', 0, base, '型号名+签名'))
        for name, v in info['volumes'].items():
            tag = 'autoresize' if v['flags'] & 1 else 'reserved %d PEB' % v['reserved']
            if name == kv:
                tag = 'FIT kernel, ' + tag
            if name == rv:
                tag = 'squashfs %s, ' % COMP_NAME.get(sq['comp'], sq['comp']) + tag
            first = v['pebs'][0]['idx'] if v['pebs'] else 0
            parts.append(('UBI卷:' + name, base + first * info['peb'],
                          len(v['pebs']) * info['peb'], tag))
        desc['parts'] = parts
        return desc

    if data[0x200:0x208] == b'EFI PART':
        cur_lba = be32(data, 0x200 + 72)
        # entries @ LBA2
        parts_raw = []
        for k in range(128):
            e = data[0x400 + k * 128: 0x400 + (k + 1) * 128]
            if e[:16] == b'\x00' * 16:
                continue
            first = struct.unpack('<Q', e[32:40])[0]
            last = struct.unpack('<Q', e[40:48])[0]
            name = e[56:].decode('utf-16-le').split('\x00')[0]
            parts_raw.append((name, first * 512, (last - first + 1) * 512))
        kp = rp = None
        for nm, off, sz in parts_raw:
            if fit_total(data, off) and kp is None:
                kp = (nm, off, sz)
            sb = parse_sq_sb(data, off)
            if sb and rp is None:
                rp = (nm, off, sz, sb)
        desc.update(fmt='gpt_emmc', fmt_name='GPT 分区 eMMC 裸镜像',
                    gpt_parts=parts_raw,
                    kernel_part=kp, root_part=rp,
                    sq=rp[3] if rp else None,
                    kernel_off=kp[1] if kp else None,
                    kernel_size=fit_total(data, kp[1]) if kp else None)
        parts = [('GPT/保留区', 0, parts_raw[0][1] if parts_raw else 0x4400, 'MBR+GPT+引导加载器')]
        for nm, off, sz in parts_raw:
            tag = ''
            if kp and nm == kp[0]:
                tag = 'FIT kernel'
            if rp and nm == rp[0]:
                tag = 'squashfs %s' % COMP_NAME.get(rp[3]['comp'], rp[3]['comp'])
            parts.append((nm, off, sz, tag))
        desc['parts'] = parts
        return desc

    if be32(data, 0) == 0x27051956:
        usize = be32(data, 12)
        name = data[32:64].split(b'\x00')[0].decode('latin1', 'replace')
        # squashfs 通常紧跟 uImage; 私有固件可能略微提前
        sq = find_squashfs(data, max(0, usize - 0x1000), min(size, usize + 0x400))
        if sq is None:
            sq = find_squashfs(data, 64, size)
        # 尾部 JSON (DEADC0DE + 8 NUL 后紧跟)
        json_off = data.find(b'metadata_version', sq['off'] + sq['bytes_used'] if sq else 0)
        if json_off >= 0:
            json_off = data.rfind(b'{', sq['off'] + sq['bytes_used'] - 0x20000 if sq else 0,
                                  json_off + 1)
        marker = json_off - 12 if json_off >= 0 and \
            data[json_off - 12:json_off - 8] == DEADC0DE else -1
        signed = b'untrusted comment' in data[-8192:]
        desc.update(fmt='legacy_uimage',
                    fmt_name='legacy uImage + squashfs sysupgrade',
                    uimage_name=name, uimage_dsize=usize, sq=sq,
                    kernel_size=sq['off'], json_off=json_off, marker=marker,
                    parts=[
                        ('kernel', 0, sq['off'], 'uImage: ' + name),
                        ('rootfs', sq['off'], sq['bytes_used'],
                         'squashfs %s' % COMP_NAME.get(sq['comp'], sq['comp'])),
                        ('元数据/签名', marker if marker >= 0 else json_off,
                         size - (marker if marker >= 0 else json_off),
                         'DEADC0DE+JSON' + ('+FWx0签名' if signed else '(无签名)')),
                    ])
        return desc

    raise RuntimeError('无法识别的镜像格式 (未匹配 SF_BOOT/GPT/uImage/tar/UBI)')


# ---------------------------------------------------------------------------
# 解包 / 打包 工程
# ---------------------------------------------------------------------------
META_NAME = '_project.json'
MANIFEST_NAME = '_manifest.jsonl'


def unpack_image(path, projdir, opts, log, stop=None):
    if not HAVE_SQFS:
        raise RuntimeError('缺少 PySquashfsImage, 请先: pip install PySquashfsImage')
    desc = identify(path, log)
    os.makedirs(projdir, exist_ok=True)
    with open(path, 'rb') as f:
        data = f.read()
    rootdir = os.path.join(projdir, 'rootfs')
    os.makedirs(rootdir, exist_ok=True)
    manifest = os.path.join(projdir, MANIFEST_NAME)
    meta = dict(fmt=desc['fmt'], fmt_name=desc['fmt_name'],
                source=os.path.basename(path), source_size=desc['size'],
                created=time.strftime('%Y-%m-%d %H:%M:%S'))

    fmt = desc['fmt']
    sq = desc['sq']
    if sq is None:
        raise RuntimeError('未找到 squashfs 超级块, 该镜像暂不支持')
    if sq['comp'] != SQ_COMP_XZ:
        log('警告: 压缩算法为 %s, 本工具打包仅支持 xz; 解包仍可继续'
            % COMP_NAME.get(sq['comp'], sq['comp']))
    meta['block_size'] = sq['block_size']

    log('格式: %s' % desc['fmt_name'])

    if fmt == 'sf_boot':
        sqb = data[sq['off']:sq['off'] + sq['bytes_used']]
        extract_squashfs(sqb, rootdir, manifest, log, stop)
        with open(os.path.join(projdir, 'kernel'), 'wb') as f:
            f.write(data[desc['kernel_off']:desc['kernel_off'] + desc['kernel_size']])
        shutil.copyfile(path, os.path.join(projdir, '_base.bin'))
        # 统计空块标记点
        markers = []
        for i in range(sq['off'] + sq['bytes_used'], 0xFB0004):
            if data[i:i + 4] == DEADC0DE:
                markers.append(i)
        meta.update(kernel_off=desc['kernel_off'],
                    root_off=sq['off'], root_end_limit=0xFB0000,
                    markers=markers, has_base=True)

    elif fmt == 'gpt_emmc':
        sqb = data[sq['off']:sq['off'] + sq['bytes_used']]
        extract_squashfs(sqb, rootdir, manifest, log, stop)
        kp, rp = desc['kernel_part'], desc['root_part']
        with open(os.path.join(projdir, 'kernel'), 'wb') as f:
            f.write(data[kp[1]:kp[1] + desc['kernel_size']])
        shutil.copyfile(path, os.path.join(projdir, '_base.bin'))
        meta.update(kernel_off=kp[1], kernel_slot=kp[2],
                    root_off=rp[1], root_slot=rp[2],
                    orig_size=desc['size'], has_base=True)

    elif fmt == 'raw_ubi':
        info = desc['ubi']
        sqb = ubi_volume_payload(data, info, desc['root_vol'], sq_size=sq['bytes_used'])
        extract_squashfs(sqb, rootdir, manifest, log, stop)
        kb = ubi_volume_payload(data, info, desc['kernel_vol'], trim_fit=True)
        with open(os.path.join(projdir, 'kernel'), 'wb') as f:
            f.write(kb)
        shutil.copyfile(path, os.path.join(projdir, '_base.bin'))
        meta.update(base=info['base'], peb=info['peb'], leb=info['leb'],
                    kernel_vol=desc['kernel_vol'], root_vol=desc['root_vol'],
                    vid_off=info['vid_off'], data_off=info['data_off'],
                    root_peb_count=len(info['volumes'][desc['root_vol']]['pebs']),
                    kernel_peb_count=len(info['volumes'][desc['kernel_vol']]['pebs']),
                    has_base=True)

    elif fmt == 'legacy_uimage':
        sqb = data[sq['off']:sq['off'] + sq['bytes_used']]
        extract_squashfs(sqb, rootdir, manifest, log, stop)
        with open(os.path.join(projdir, 'kernel'), 'wb') as f:
            f.write(data[:sq['off']])
        # 保留 JSON(+签名+toc) 全尾部
        has_tail = desc['json_off'] >= 0
        if has_tail:
            tail_start = desc['marker'] if desc['marker'] >= 0 else desc['json_off']
            with open(os.path.join(projdir, '_tail.bin'), 'wb') as f:
                f.write(data[tail_start:])
        meta.update(has_tail=has_tail,
                    tail_from_marker=desc['marker'] >= 0,
                    kernel_size=sq['off'])

    elif fmt == 'sysupgrade_tar':
        sqb = data[sq['off']:sq['off'] + sq['bytes_used']]
        extract_squashfs(sqb, rootdir, manifest, log, stop)
        members = desc['members']
        km = next(m for m in members if m['name'].endswith('/kernel'))
        with open(os.path.join(projdir, 'kernel'), 'wb') as f:
            f.write(data[km['off'] + 512: km['off'] + 512 + km['size']])
        rm2 = next(m for m in members if m['name'].endswith('/root'))
        cm = next((m for m in members if m['name'].endswith('/CONTROL')), None)
        if cm:
            with open(os.path.join(projdir, '_control.bin'), 'wb') as f:
                f.write(data[cm['off'] + 512: cm['off'] + 512 + cm['size']])
        if desc.get('json_off', -1) >= 0:
            with open(os.path.join(projdir, '_tail.bin'), 'wb') as f:
                f.write(data[desc['json_off']:])
        meta.update(tar_board=desc['board'],
                    dir_header=members[0]['header'].hex(),
                    control_header=cm['header'].hex() if cm else None,
                    kernel_header=km['header'].hex(),
                    root_header=rm2['header'].hex(),
                    has_tail=desc.get('json_off', -1) >= 0)
    else:
        raise RuntimeError('未知格式: %s' % fmt)

    meta['sq_mtime'] = sq['mtime']
    with open(os.path.join(projdir, META_NAME), 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False, indent=1)
    log('解包完成 -> %s' % projdir)
    return desc


def pack_image(projdir, outpath, opts, log, stop=None):
    with open(os.path.join(projdir, META_NAME), 'r', encoding='utf-8') as f:
        meta = json.load(f)
    fmt = meta['fmt']
    rootdir = os.path.join(projdir, 'rootfs')
    manifest = os.path.join(projdir, MANIFEST_NAME)
    block_size = meta['block_size']

    # 1) 重建 squashfs
    tmp_sq = os.path.join(projdir, '_rootfs.new')
    base = None
    if fmt in ('sf_boot', 'gpt_emmc', 'raw_ubi'):
        basep = os.path.join(projdir, '_base.bin')
        if os.path.isfile(basep):
            with open(basep, 'rb') as f:
                base = f.read()

    def orig_lookup(path):
        """磁盘文件丢失(多为杀软隔离)时, 从 _base.bin 原镜像按路径取回原内容。"""
        if base is None:
            return None
        try:
            if fmt in ('sf_boot', 'gpt_emmc'):
                off = meta['root_off']
                sb = parse_sq_sb(base, off)
                sqb = base[off:off + sb['bytes_used']]
            else:
                info = ubi_scan(base, meta['base'], lambda s: None)
                payload = ubi_volume_payload(base, info, meta['root_vol'])
                sb = parse_sq_sb(payload, 0)
                sqb = payload[:sb['bytes_used']]
            img = SquashFsImage.from_bytes(sqb)
            for e in img:
                if e.path == path and e.is_file:
                    return e.read_bytes()
        except Exception:
            pass
        return None

    build_squashfs(rootdir, manifest, tmp_sq, block_size,
                   int(meta.get('sq_mtime', 0)) or int(time.time()), log, stop,
                   orig_lookup if base is not None else None)
    sq = open(tmp_sq, 'rb').read()

    # 2) 按格式重组
    if fmt in ('sf_boot', 'gpt_emmc', 'raw_ubi'):
        if base is None:
            with open(os.path.join(projdir, '_base.bin'), 'rb') as f:
                base = f.read()

    if fmt == 'sf_boot':
        out = bytearray(base)
        kernel = open(os.path.join(projdir, 'kernel'), 'rb').read()
        koff = meta['kernel_off']
        roff = meta['root_off']
        if koff + len(kernel) > roff:
            raise RuntimeError('kernel 过大 (%d > 槽位 %d)' % (len(kernel), roff - koff))
        out[koff:roff] = b'\x00' * (roff - koff)
        out[koff:koff + len(kernel)] = kernel
        if roff + len(sq) > meta['root_end_limit']:
            raise RuntimeError('rootfs 过大: 结束 %#x 超过限制 %#x'
                               % (roff + len(sq), meta['root_end_limit']))
        end = meta['root_end_limit']
        out[roff:end] = b'\xff' * (end - roff)
        out[roff:roff + len(sq)] = sq
        for m in meta.get('markers', []):
            if m >= roff + len(sq):
                out[m:m + 4] = DEADC0DE
        data_out = bytes(out)

    elif fmt == 'gpt_emmc':
        out = bytearray(base)
        kernel = open(os.path.join(projdir, 'kernel'), 'rb').read()
        koff, kslot = meta['kernel_off'], meta['kernel_slot']
        roff, rslot = meta['root_off'], meta['root_slot']
        if len(kernel) > kslot:
            raise RuntimeError('kernel 过大 (%d > 分区 %d)' % (len(kernel), kslot))
        out[koff:koff + kslot] = b'\x00' * kslot
        out[koff:koff + len(kernel)] = kernel
        if len(sq) > rslot:
            raise RuntimeError('rootfs 过大 (%d > 分区 %d)' % (len(sq), rslot))
        need_end = align_up(roff + len(sq), 0x10000)
        if need_end > len(out):
            out += b'\x00' * (need_end - len(out))
        fill_end = min(roff + rslot, len(out))
        out[roff:fill_end] = b'\x00' * (fill_end - roff)
        out[roff:roff + len(sq)] = sq
        data_out = bytes(out)

    elif fmt == 'raw_ubi':
        info = ubi_scan(base, meta['base'], log)
        kernel = open(os.path.join(projdir, 'kernel'), 'rb').read()
        data_out = ubi_patch(base, info, meta['root_vol'], sq, log, stop,
                             kernel_vol=meta['kernel_vol'], kernel_blob=kernel)

    elif fmt == 'legacy_uimage':
        kernel = open(os.path.join(projdir, 'kernel'), 'rb').read()
        payload_end = len(kernel) + len(sq)
        out = bytearray()
        out += kernel
        out += sq
        if meta.get('has_tail'):
            tail = open(os.path.join(projdir, '_tail.bin'), 'rb').read()
            boundary = align_up(payload_end, 0x10000)
            out += b'\xff' * (boundary - payload_end)
            out += DEADC0DE + b'\x00' * 8
            # tail 原始内容以 DEADC0DE 开头? 保存的 tail 从 marker 开始
            if meta.get('tail_from_marker') and tail[:4] == DEADC0DE:
                tail = tail[12:]  # 去掉原 marker+8NUL
            out += tail
        data_out = bytes(out)

    elif fmt == 'sysupgrade_tar':
        kernel = open(os.path.join(projdir, 'kernel'), 'rb').read()
        out = bytearray()
        out += bytes.fromhex(meta['dir_header'])
        if meta.get('control_header'):
            ctrl = open(os.path.join(projdir, '_control.bin'), 'rb').read()
            out += tar_set_size(bytes.fromhex(meta['control_header']), len(ctrl))
            out += ctrl + b'\x00' * ((512 - len(ctrl) % 512) % 512)
        out += tar_set_size(bytes.fromhex(meta['kernel_header']), len(kernel))
        out += kernel + b'\x00' * ((512 - len(kernel) % 512) % 512)
        out += tar_set_size(bytes.fromhex(meta['root_header']), len(sq))
        out += sq + b'\x00' * ((512 - len(sq) % 512) % 512)
        out += b'\x00' * 1024  # tar 结束双零块
        if meta.get('has_tail'):
            tail = open(os.path.join(projdir, '_tail.bin'), 'rb').read()
            # 对齐到原厂 JSON 位置规律 (len % 0x1000 == 0x808)
            while len(out) % 0x1000 != 0x808:
                out += b'\x00'
            out += tail
        data_out = bytes(out)
    else:
        raise RuntimeError('未知格式: %s' % fmt)

    with open(outpath, 'wb') as f:
        f.write(data_out)
    try:
        os.remove(tmp_sq)
    except OSError:
        pass
    log('打包完成 -> %s (%d 字节)' % (outpath, len(data_out)))
    if b'untrusted comment' in data_out[-8192:]:
        log('提醒: 镜像含 FWx0 签名块, 已原样保留; 修改内容后签名实际失效, 仅限关闭校验的设备刷写')
    return len(data_out)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class App:
    def __init__(self, root):
        self.root = root
        root.title('路由器固件 解包/打包工具')
        root.geometry('900x680')
        self.stop_ev = threading.Event()
        self.worker = None
        self.last_proj = None
        self.desc = None
        self._build()

    def _build(self):
        frm = ttk.Frame(self.root, padding=8)
        frm.pack(fill='x')
        ttk.Label(frm, text='固件文件:').grid(row=0, column=0, sticky='w')
        self.var_file = tk.StringVar()
        ttk.Entry(frm, textvariable=self.var_file).grid(row=0, column=1, sticky='ew', padx=4)
        ttk.Button(frm, text='浏览…', command=self.pick_file).grid(row=0, column=2)
        ttk.Button(frm, text='识别格式', command=self.do_identify).grid(row=0, column=3, padx=4)
        frm.columnconfigure(1, weight=1)

        self.var_fmt = tk.StringVar(value='未识别')
        ttk.Label(self.root, textvariable=self.var_fmt, foreground='#0a7',
                  padding=(10, 4)).pack(fill='x')

        tvf = ttk.Frame(self.root, padding=(8, 0))
        tvf.pack(fill='both', expand=False)
        self.tv = ttk.Treeview(tvf, columns=('off', 'size', 'note'),
                               show='tree headings', height=8)
        self.tv.heading('#0', text='分区/成员')
        self.tv.heading('off', text='偏移')
        self.tv.heading('size', text='大小')
        self.tv.heading('note', text='说明')
        self.tv.column('#0', width=200)
        self.tv.column('off', width=110)
        self.tv.column('size', width=110)
        self.tv.column('note', width=380)
        self.tv.pack(side='left', fill='both', expand=True)
        sb = ttk.Scrollbar(tvf, command=self.tv.yview)
        sb.pack(side='right', fill='y')
        self.tv.configure(yscrollcommand=sb.set)

        bf = ttk.Frame(self.root, padding=8)
        bf.pack(fill='x')
        self.btn_unp = ttk.Button(bf, text='解包到目录…', command=self.do_unpack)
        self.btn_unp.pack(side='left')
        ttk.Button(bf, text='打包工程目录…', command=self.do_pack).pack(side='left', padx=6)
        self.btn_stop = ttk.Button(bf, text='停止', command=self.do_stop, state='disabled')
        self.btn_stop.pack(side='right')
        self.pg = ttk.Progressbar(bf, mode='indeterminate')
        self.pg.pack(side='left', fill='x', expand=True, padx=12)

        self.logw = scrolledtext.ScrolledText(self.root, height=14, font=('Consolas', 9))
        self.logw.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self.logw.configure(state='disabled')
        self.log('就绪。支持: SF_BOOT / GPT eMMC / legacy uImage / sysupgrade tar / 裸UBI / 私有头+UBI')
        if not HAVE_SQFS:
            self.log('警告: 未安装 PySquashfsImage (pip install PySquashfsImage), 解包功能不可用')

    def log(self, s):
        def _a():
            self.logw.configure(state='normal')
            self.logw.insert('end', s + '\n')
            self.logw.see('end')
            self.logw.configure(state='disabled')
        self.root.after(0, _a)

    def pick_file(self):
        p = filedialog.askopenfilename(
            title='选择路由器固件',
            filetypes=[('固件/镜像', '*.bin *.img *.*'), ('所有文件', '*.*')])
        if p:
            self.var_file.set(p)
            self.do_identify()

    def do_identify(self):
        p = self.var_file.get().strip()
        if not p or not os.path.isfile(p):
            messagebox.showwarning('提示', '请先选择有效的固件文件')
            return
        self.tv.delete(*self.tv.get_children())
        self.var_fmt.set('识别中…')
        try:
            self.desc = identify(p, self.log)
        except Exception as ex:
            self.var_fmt.set('识别失败')
            messagebox.showerror('识别失败', str(ex))
            return
        d = self.desc
        self.var_fmt.set('%s   |   文件 %d 字节 (%s)'
                         % (d['fmt_name'], d['size'], os.path.basename(p)))
        for nm, off, sz, note in d['parts']:
            self.tv.insert('', 'end', text=nm,
                           values=('%#x' % off, '%d (%#x)' % (sz, sz), note))

    def _run(self, fn, btns):
        self.stop_ev.clear()
        for b in btns:
            b.configure(state='disabled')
        self.btn_stop.configure(state='normal')
        self.pg.start(12)

        def wrap():
            err = None
            try:
                fn(self.stop_ev)
            except Canceled:
                self.log('已停止')
            except Exception as e:
                err = e
                self.log('错误: %s' % e)
                self.log(traceback.format_exc())

            def done():
                self.pg.stop()
                self.btn_stop.configure(state='disabled')
                for b in btns:
                    b.configure(state='normal')
                if err:
                    messagebox.showerror('失败', str(err))
            self.root.after(0, done)
        threading.Thread(target=wrap, daemon=True).start()

    def do_unpack(self):
        p = self.var_file.get().strip()
        if not p or not os.path.isfile(p):
            messagebox.showwarning('提示', '请先选择固件文件')
            return
        proj = filedialog.askdirectory(title='选择解包输出目录（工程目录）')
        if not proj:
            return
        proj = os.path.join(proj, os.path.splitext(os.path.basename(p))[0] + '_unpack')
        if os.path.exists(proj) and os.listdir(proj):
            if not messagebox.askyesno('确认', '目录已存在且非空:\n%s\n继续将覆盖清单文件，是否继续？' % proj):
                return

        def task(ev):
            self.log('开始解包: %s' % p)
            unpack_image(p, proj, {}, self.log, ev)
            self.last_proj = proj
            self.log('工程目录: %s（可直接编辑 rootfs/ 与 kernel 后打包）' % proj)
        self._run(task, [self.btn_unp])

    def do_pack(self):
        proj = filedialog.askdirectory(title='选择解包工程目录（含 _project.json）')
        if not proj:
            return
        if not os.path.isfile(os.path.join(proj, META_NAME)):
            messagebox.showerror('错误', '该目录不是有效的解包工程（缺少 %s）' % META_NAME)
            return
        out = filedialog.asksaveasfilename(
            title='新镜像保存为', defaultextension='.bin',
            initialfile=os.path.basename(proj).replace('_unpack', '') + '_new.bin')
        if not out:
            return

        def task(ev):
            self.log('开始打包: %s' % proj)
            pack_image(proj, out, {}, self.log, ev)
        self._run(task, [self.btn_unp])

    def do_stop(self):
        self.stop_ev.set()
        self.log('请求停止…')


def main():
    if tk is None:
        print('当前 Python 无 tkinter, 无法启动图形界面')
        return 1
    r = tk.Tk()
    App(r)
    r.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())

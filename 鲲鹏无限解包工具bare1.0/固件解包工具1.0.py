#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================
 固件 / NRadio .nr 备份 可视化解包-打包工具 (Windows, 单文件, 零三方依赖)
================================================================
把 firmware-unpack 解包流 (fw-scan.ps1 + cpio_newc.py + magic 表
+ 分区切段 + 文件系统解包) 与 nr_tool.py (.nr 备份修改/打包) 整合进
一个三页签 Tkinter 界面, 并按解包流逆向提供打包能力。

页签① 固件解包:
  [1 扫描识别]   头/尾 hex、全文件 magic 命中表、gzip 成员(FLG/FNAME)、
                 偏移 0 类型自动判定与下一步建议
  [2 剥一层压缩] gzip/xz/lzma-alone/bzip2/zstd, 可指定偏移, 报剩余字节
  [3 解包 cpio]  内嵌 newc(070701)/crc(070702) 解析器, 支持串联成员
  [4 切分区段]   偏移/长度切片 (0x、K/M/G), 块大小+skip/count 一键填充
  [5 解包文件系统] JFFS2(jefferson)/squashfs/UBI/ext4/tar/zip
  [6 找分区线索] ptable/xloader/hiboot/kernel/system/teeos 段名偏移
  [一键智能解包] 压缩层逐层剥 -> cpio/tar 解开 -> FS 外部解包器

页签② NR 备份 (设备 /sbin/sysupgrade 逆向: NUL+ASCII头+gzip(tar),
  crc=MD5(b"nradio_security_akxo1f\\n"+gz)):
  [NR 查看信息+校验] [NR 严格校验] [NR 解包到目录]
  [目录打包为 .nr] [★一键制作解锁备份](注入 uci-defaults: SSH+adbd+AT页)

页签③ 逆向打包 (解包流反向):
  [目录→cpio(+压缩)] 纯 Python newc 生成器, 4 对齐, TRAILER, 512 块补齐
  [目录→tar(+压缩)]  GNU tar, 保留目录/符号链接/权限
  [文件→压缩包裹]    gzip(mtime0)/xz/lzma/bzip2/zstd
  [目录→JFFS2/squashfs 镜像] 调外部 mkfs.jffs2/mksquashfs (一般在 WSL)
  [分区段拼接为整镜像] 按序拼接, 可选按擦除块 0xFF 填充 (切段的逆操作)
  [★分区→fwtool升级包] partitions 11 段按段表拼内镜像→gzip(FNAME
    firmware.bin)→8NUL+JSON+FWx0 尾(CRC32), 还原 DD-5G 全量升级 .bin

CLI (无界面): 见各 add_parser; 例:
  --cli scan/peel/cpio/split/fs/parts/auto
  --cli nr-info/nr-verify/nr-unpack/nr-pack/nr-unlock
  --cli pack-cpio/pack-tar/compress/mkfs/join/pack-fwtool
================================================================
"""
import argparse
import bz2
import glob
import gzip
import io
import lzma
import os
import queue
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import zipfile
import zlib

try:  # GUI 依赖 (Windows 标准 Python 自带); 纯 CLI 环境缺失也不影响引擎
    import tkinter as tk
    from tkinter import filedialog, ttk
except ImportError:  # pragma: no cover
    tk = None

# ------------------------------------------------------------------ magic 表
# (显示名, 字节特征, 类别)  类别: comp=压缩容器, image=引导镜像, fs=文件系统, arch=归档
MAGIC_TABLE = [
    ("gzip 1F8B08",         b"\x1f\x8b\x08",            "comp"),
    ("xz 7zXZ",             b"\xfd7zXZ\x00",            "comp"),
    ("zstd 28B52FFD",       b"\x28\xb5\x2f\xfd",        "comp"),
    ("bzip2 BZh",           b"BZh",                     "comp"),
    ("lzma-alone 5D000080", b"\x5d\x00\x00\x80",        "comp"),
    ("lzma-alone 5D000000", b"\x5d\x00\x00\x00",        "comp"),
    ("cpio newc 070701",    b"070701",                  "arch"),
    ("cpio crc 070702",     b"070702",                  "arch"),
    ("cpio oldc 070707",    b"070707",                  "arch"),
    ("squashfs hsqs (LE)",  b"hsqs",                    "fs"),
    ("squashfs sqsh (BE)",  b"sqsh",                    "fs"),
    ("tar ustar",           b"ustar",                   "arch"),
    ("JFFS2 dirent (LE)",   b"\x85\x19\x01\xe0",        "fs"),
    ("JFFS2 inode (LE)",    b"\x85\x19\x02\xe0",        "fs"),
    ("JFFS2 (BE 1985)",     b"\x19\x85\x20\x03",        "fs"),
    ("UBI#",                b"UBI#",                    "fs"),
    ("cramfs LE",           b"\x45\x3d\xcd\x28",        "fs"),
    ("cramfs BE",           b"\x28\xcd\x3d\x45",        "fs"),
    ("ext4 53EF@0x438",     b"\x53\xef",                "fs"),
    ("f2fs F2F5@1024",      b"\xf2\xf5\x20\x10",        "fs"),
    ("erofs@1024",          b"\xe2\xe1\xf5\xe0",        "fs"),
    ("romfs -rom1fs-",      b"-rom1fs-",                "fs"),
    ("uImage 27051956",     b"\x27\x05\x19\x56",        "image"),
    ("FIT/DTB d00dfeed",    b"\xd0\x0d\xfe\xed",        "image"),
    ("ANDROID!",            b"ANDROID!",                "image"),
    ("ELF 7F454C46",        b"\x7fELF",                 "image"),
    ("PK zip 504B0304",     b"PK\x03\x04",              "arch"),
]

PARTITION_NAMES = [
    "ptable", "xloader", "hiboot", "m3image", "mnvdload", "fastboot",
    "kernel", "system", "teeos", "trusted_fw", "uce", "modem_fw",
    "nvimg", "nvbak", "userdata", "oeminfo", "boot", "rootfs",
    "uboot", "dtb", "fw_linux", "fw_ramdisk",
]

# ================================================================== 工具函数
def parse_size(s, default=0):
    s = str(s).strip()
    if not s:
        return default
    if s.lower().startswith("0x"):
        return int(s, 16)
    mult = 1
    if s and s[-1].upper() in "KMG":
        mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}[s[-1].upper()]
        s = s[:-1]
    return int(float(s) * mult)


def hexdump(data, base=0, count=256, width=16):
    """data 从逻辑偏移 base 开始, 只 dump 前 count 字节(不超过 data 长度)。"""
    lines = []
    end = min(count, len(data))
    for rel in range(0, end, width):
        chunk = data[rel:rel + width]
        h = " ".join(f"{b:02X}" for b in chunk).ljust(width * 3 - 1)
        a = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"{base + rel:08X}  {h}  {a}")
    return "\n".join(lines)


def detect_head(data):
    """返回 (显示名, 类别) 或 None。只看偏移0及已知固定偏移, 杜绝内部误报。"""
    if data[:3] == b"\x1f\x8b\x08":
        return ("gzip", "comp")
    if data[:6] == b"\xfd7zXZ\x00":
        return ("xz", "comp")
    if data[:4] == b"\x28\xb5\x2f\xfd":
        return ("zstd", "comp")
    if data[:3] == b"BZh":
        return ("bzip2", "comp")
    if data[:4] in (b"\x5d\x00\x00\x80", b"\x5d\x00\x00\x00"):
        return ("lzma-alone", "comp")
    if data[:6] in (b"070701", b"070702"):
        return ("cpio newc/crc", "arch")
    if data[:6] == b"070707":
        return ("cpio odc(老格式, 建议cpio -H odc)", "arch")
    if data[:4] == b"hsqs":
        return ("squashfs LE", "fs")
    if data[:4] == b"sqsh":
        return ("squashfs BE", "fs")
    if data[:4] in (b"\x85\x19\x01\xe0", b"\x85\x19\x02\xe0"):
        return ("JFFS2 LE", "fs")
    if data[:4] == b"\x19\x85\x20\x03":
        return ("JFFS2 BE", "fs")
    if data[:4] == b"UBI#":
        return ("UBI 镜像", "fs")
    if data[:4] == b"\x45\x3d\xcd\x28":
        return ("cramfs LE", "fs")
    if data[:4] == b"\x28\xcd\x3d\x45":
        return ("cramfs BE", "fs")
    if len(data) > 0x43A and data[0x438:0x43A] == b"\x53\xef":
        return ("ext4 (magic@0x438)", "fs")
    if len(data) > 1028 and data[1024:1028] == b"\xf2\xf5\x20\x10":
        return ("f2fs (magic@1024)", "fs")
    if len(data) > 1028 and data[1024:1028] == b"\xe2\xe1\xf5\xe0":
        return ("erofs (magic@1024)", "fs")
    if data[:8] == b"-rom1fs-":
        return ("romfs", "fs")
    if data[:4] == b"\x27\x05\x19\x56":
        return ("uImage legacy (可去64字节头后继续剥)", "image")
    if data[:4] == b"\xd0\x0d\xfe\xed":
        return ("FIT/DTB", "image")
    if data[:8] == b"ANDROID!":
        # 真 boot 头: 0x08 处 kernel_size 应为合理的小端二进制数(高位多为00)
        ks = int.from_bytes(data[8:12], "little")
        if 0 < ks < len(data) and data[12:16] != b"ANDROID!":
            return (f"Android boot (kernel_size={ks})", "image")
    if data[:4] == b"\x7fELF":
        return ("ELF (内核/可执行文件, 非解包对象)", "image")
    if data[:4] == b"PK\x03\x04":
        return ("ZIP/JAR", "arch")
    if data[257:262] == b"ustar":
        return ("tar (ustar@257)", "arch")
    return None


def find_magic_hits(data, table, max_hits=12):
    res = {}
    for name, needle, _cat in table:
        hits, start = [], 0
        while len(hits) < max_hits:
            i = data.find(needle, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
        if hits:
            res[name] = hits
    return res


def list_gzip_members(data, max_hits=12):
    out, start = [], 0
    while len(out) < max_hits:
        i = data.find(b"\x1f\x8b\x08", start)
        if i < 0:
            break
        start = i + 1
        if i + 10 > len(data):
            continue
        flg = data[i + 3]
        fname, p = "", i + 10
        try:
            if (flg & 0x04) and p + 2 <= len(data):
                p += 2 + data[p] + (data[p + 1] << 8)
            if (flg & 0x08):
                while p < len(data) and data[p] != 0:
                    if 0x20 <= data[p] <= 0x7E:
                        fname += chr(data[p])
                    p += 1
        except IndexError:
            pass
        out.append((i, flg, data[i + 8], fname))
    return out


def validate_gzip_at(data, off, cap=64 << 20):
    """在 off 处尝试真实解压一个 gzip 成员。
    返回 (是否有效, 解出字节数, 备注)。有效判据: FLG 保留位合法、能解出
    >=512 字节。压缩流内部巧合的 1F8B08 会在此被识破。"""
    note = ""
    if off + 10 > len(data):
        return False, 0, "(数据不足)"
    flg = data[off + 3]
    if flg & 0xE0:
        return False, 0, "(FLG 保留位置位)"
    total = 0
    try:
        d = zlib.decompressobj(31)
        # 分段喂入并封顶, 避免误报点触发超长解压
        pos, end = off, min(len(data), off + 16 << 20)
        while pos < end and total < cap:
            chunk = data[pos:pos + 1 << 20]
            piece = d.decompress(chunk)
            total += len(piece)
            if d.eof:
                break
            pos += len(chunk)
        if not d.eof and total < cap:
            d.flush()
        if total < 512:
            return False, total, "(解出过小)"
        head_kind = ""
        if total >= 6:
            d2 = zlib.decompressobj(31)
            o2 = d2.decompress(data[off:off + (16 << 20)])
            if o2[:6] in (b"070701", b"070702"):
                head_kind = "->cpio"
            elif o2[:4] == b"hsqs":
                head_kind = "->squashfs"
            elif o2[:2] == b"\x1f\x8b":
                head_kind = "->嵌套gzip?"
        return True, total, head_kind
    except Exception as e:
        return False, total, "(" + str(e)[:40] + ")"


# ------------------------------------------------------------------ 压缩剥离
def decompress_one(data, fmt="auto"):
    """返回 (out_bytes, unused_bytes, fmt名)。只剥 offset0 的一个成员。"""
    if fmt == "auto":
        head = detect_head(data)
        if not head or head[1] != "comp":
            raise ValueError("偏移 0 不是已知压缩格式, 无法剥层 (先扫描确认)")
        fmt = head[0]
    if fmt == "gzip":
        d = zlib.decompressobj(31)
        out = d.decompress(data)
        out += d.flush()
        return out, d.unused_data, "gzip"
    if fmt == "xz":
        d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        out = d.decompress(data)
        return out, d.unused_data, "xz"
    if fmt == "lzma-alone":
        d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        out = d.decompress(data)
        return out, d.unused_data, "lzma-alone"
    if fmt == "bzip2":
        d = bz2.BZ2Decompressor()
        out = d.decompress(data)
        return out, d.unused_data, "bzip2"
    if fmt == "zstd":
        try:
            import zstandard
        except ImportError:
            raise ValueError("需要 zstandard: python -m pip install --user zstandard")
        dobj = zstandard.ZstdDecompressor().decompressobj()
        out = dobj.decompress(data)
        out += dobj.flush()
        return out, dobj.unused_tail_data, "zstd"
    raise ValueError(f"不支持的压缩格式: {fmt}")


# ------------------------------------------------- fwtool 尾部元数据
def parse_fwtool_trailer(tail):
    """OpenWrt fwtool 升级包尾部: 若干填充 + JSON + '\\n' + 'FWx0..'。
    返回 (json文本/None, 字段dict/None)。"""
    if not tail:
        return None, None
    if b"FWx0" not in tail and b"metadata_version" not in tail:
        return None, None
    import json
    i, j = tail.find(b"{"), tail.rfind(b"}")
    if i < 0 or j <= i:
        return None, None
    txt = tail[i:j + 1].decode("utf-8", "replace")
    try:
        return txt, json.loads(txt)
    except Exception:
        return txt, None


def save_fwtool_metadata(tail, outpath, log=print):
    txt, meta = parse_fwtool_trailer(tail)
    if txt is None:
        return None
    raw_path = outpath + ".fwtool_trailer.bin"
    json_path = outpath + ".metadata.json"
    with open(raw_path, "wb") as fp:
        fp.write(tail)
    with open(json_path, "w", encoding="utf-8", newline="\n") as fp:
        fp.write(txt)
    log(f"fwtool 尾部元数据 {len(tail)} 字节 -> {raw_path} / {json_path}")
    if meta:
        v = meta.get("version", {})
        log(f"  supported_devices={meta.get('supported_devices')}  "
            f"version={v.get('version')} target={v.get('target')} "
            f"board={v.get('board')} type={v.get('type')}")
    return json_path


# ------------------------------------------------------------------ cpio 解包
CPIO_MAGICS = (b"070701", b"070702")
CPIO_INVALID = '<>:"|?*\x00'


def cpio_align4(n):
    return (n + 3) & ~3


def cpio_sanitize(rel):
    parts = []
    for seg in rel.lstrip("/").split("/"):
        if seg in ("", ".", ".."):
            continue
        for ch in CPIO_INVALID:
            seg = seg.replace(ch, "_")
        head = seg.split(".")[0].upper()
        if head in ("CON", "PRN", "AUX", "NUL") or (
            head.startswith(("COM", "LPT")) and head[3:].isdigit()):
            seg = "_" + seg
        parts.append(seg)
    return os.path.join(*parts) if parts else ""


def cpio_extract(data, outdir, log=print):
    os.makedirs(outdir, exist_ok=True)
    pos, entries, chains = 0, 0, 0
    saw_trailer = False
    corrupt = False
    while pos + 110 <= len(data):
        magic = data[pos:pos + 6]
        if magic not in CPIO_MAGICS:
            nxt = min([j for j in (data.find(m, pos + 1) for m in CPIO_MAGICS)
                       if j >= 0], default=-1)
            if nxt < 0:
                break
            log(f"  跳过填充 0x{pos:X}..0x{nxt:X}")
            pos = nxt
            continue
        chains += 1
        try:
            mode = int(data[pos + 14:pos + 22], 16)
            fsize = int(data[pos + 54:pos + 62], 16)
            nsize = int(data[pos + 94:pos + 102], 16)
        except ValueError:
            log(f"  头损坏 @0x{pos:X}, 停止")
            corrupt = True
            break
        name = data[pos + 110:pos + 110 + nsize - 1].decode("utf-8", "replace")
        doff = cpio_align4(pos + 110 + nsize)
        if name == "TRAILER!!!":
            saw_trailer = True
            log(f"  TRAILER!!! @0x{pos:X} (本成员 {entries} 项)")
            nxt = min([j for j in (data.find(m, doff) for m in CPIO_MAGICS)
                       if j >= 0], default=-1)
            if nxt < 0:
                break
            pos, entries = nxt, 0
            continue
        ftype = stat.S_IFMT(mode)
        if ftype in (stat.S_IFREG, stat.S_IFLNK):
            rel = cpio_sanitize(name)
            if rel:
                dst = os.path.join(outdir, rel)
                blob = data[doff:doff + fsize]
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if ftype == stat.S_IFREG:
                    with open(dst, "wb") as fp:
                        fp.write(blob)
                else:
                    with open(dst + ".symlink.txt", "w", encoding="utf-8",
                              newline="\n") as fp:
                        fp.write(blob.decode("utf-8", "replace"))
        entries += 1
        pos = cpio_align4(doff + fsize)
    log(f"cpio 完成: 共解析 {chains} 个文件头")
    if chains == 0:
        raise ValueError("未找到任何 cpio(070701/070702) 头 —— 该文件不是 "
                         "newc/crc cpio (可能是分段裸镜像, 应先[剥压缩]或"
                         "[切分区段], 而不是直接解 cpio)")
    if not saw_trailer:
        raise ValueError(f"在 0x{pos:X} 前只找到 {chains} 个 cpio 头且未遇到 "
                         "TRAILER!!! —— 是二进制里巧合的 070701 字节, 不是 "
                         "cpio 归档 (真归档必以 TRAILER!!! 结尾); "
                         "请先定位内核/teeos 的 gzip 成员再剥")
    if corrupt:
        raise ValueError(f"cpio 头在 0x{pos:X} 损坏, 归档不完整")
    return True


# ------------------------------------------------------------------ FS 外部工具
def find_jefferson():
    p = shutil.which("jefferson") or shutil.which("jefferson.exe")
    if p:
        return p
    base = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Packages")
    for hit in glob.glob(os.path.join(base, "PythonSoftwareFoundation.*_*",
            "LocalCache", "local-packages", "Python*", "Scripts",
            "jefferson*")):
        if hit.endswith((".exe", ".cmd", "")) or os.path.isfile(hit):
            return hit
    return None


def find_7z():
    for c in (r"C:\Program Files\7-Zip\7z.exe",
              r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if os.path.isfile(c):
            return c
    return shutil.which("7z") or shutil.which("7z.exe")


def run_external(cmd, log=print, cwd=None):
    log("  $ " + " ".join(str(x) for x in cmd))
    # jefferson 等 Python 子进程在中文 Windows 上 stdout 默认 gbk,
    # 文件名含 ő 等字符时会 UnicodeEncodeError 中途崩掉 -> 强制 UTF-8
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           env=env, timeout=3600)
    except FileNotFoundError:
        return 127, "", "executable not found"
    if p.stdout:
        log(p.stdout.rstrip())
    if p.stderr:
        log(p.stderr.rstrip())
    return p.returncode, p.stdout or "", p.stderr or ""


def extract_archive_python(path, outdir, kind, log=print):
    os.makedirs(outdir, exist_ok=True)
    if kind == "tar":
        with tarfile.open(path, "r:*") as tf:
            members = tf.getmembers()
            try:
                tf.extractall(outdir, filter="data")  # py3.12+
            except TypeError:
                tf.extractall(outdir)
        log(f"tar 解开 {len(members)} 项 -> {outdir}")
        return True
    if kind == "zip":
        with zipfile.ZipFile(path) as zf:
            zf.extractall(outdir)
        log(f"zip 解开 {len(zf.namelist())} 项 -> {outdir}")
        return True
    return False


def extract_fs(path, outdir, log=print, _depth=0):
    data = open(path, "rb").read()
    head = detect_head(data[:65536] + b"\x00" * 0x100)
    if not head:
        # 可能是剥层后的分段裸镜像: 内嵌 JFFS2 system 段
        if _depth == 0 and len(data) > 1 << 20:
            info = probe_segmented(data, log)
            if info["jffs2"] is not None:
                off = info["jffs2"]
                pdir = os.path.join(os.path.dirname(os.path.abspath(outdir)),
                                    "_embedded_segments")
                os.makedirs(pdir, exist_ok=True)
                seg = os.path.join(pdir, f"system_0x{off:X}.bin")
                with open(seg, "wb") as fp:
                    fp.write(data[off:])
                log(f"分段裸包: 已切出内嵌 JFFS2 @0x{off:X} -> {seg}")
                return extract_fs(seg, outdir, log, _depth + 1)
        raise ValueError("未识别的文件系统/归档格式 (若为分段裸镜像, 可用 "
                         "[7分段裸包探测]/[一键智能解包] 自动切段)")
    name, cat = head
    # 外层套了压缩 (gzip/xz/...): 自动剥一层后递归再判 FS
    if cat == "comp":
        if _depth >= 6:
            raise ValueError("压缩嵌套超过 6 层, 终止")
        out, tail, used = decompress_one(data)
        pdir = os.path.join(os.path.dirname(os.path.abspath(outdir)),
                            "_peeled_layers")
        os.makedirs(pdir, exist_ok=True)
        nxt = os.path.join(pdir, os.path.basename(path) + f".{_depth}.{used}")
        with open(nxt, "wb") as fp:
            fp.write(out)
        log(f"输入为 {used} 压缩, 自动剥层 {len(out)} 字节 -> {nxt}")
        if tail:
            save_fwtool_metadata(tail, nxt, log)
        return extract_fs(nxt, outdir, log, _depth + 1)
    # 直接就是 cpio 归档
    if name.startswith("cpio"):
        log("识别: cpio 归档, 走 cpio 解包")
        cpio_extract(data, outdir, log)
        return True
    log(f"识别: {name}")
    if cat != "fs" and name not in ("tar (ustar@257)", "ZIP/JAR"):
        raise ValueError(f"{name} 不是文件系统/归档; 若为压缩外壳工具会自动剥, "
                         f"若为 uImage 请先去头")
    if name.startswith("JFFS2"):
        j = find_jefferson()
        if not j:
            raise ValueError("未找到 jefferson, 先安装: "
                             "python -m pip install --user jefferson")
        if os.path.isdir(outdir):
            # jefferson 要求目标不存在; 重跑时先清掉旧的解包目录
            shutil.rmtree(outdir)
        rc, _, err = run_external([j, "-d", outdir, path], log)
        if rc != 0:
            raise ValueError(f"jefferson 退出码 {rc}, JFFS2 解包不完整"
                             + (f": {err[-200:]}" if err else ""))
        return True
    if name.startswith("squashfs"):
        u = shutil.which("unsquashfs")
        if u:
            if run_external([u, "-f", "-d", outdir, path], log)[0] == 0:
                return True
        z = find_7z()
        if z:
            log("unsquashfs 不可用, 改用 7-Zip (非标准压缩可能失败)")
            if run_external([z, "x", f"-o{outdir}", "-y", path], log)[0] == 0:
                return True
        raise ValueError("squashfs 需要 unsquashfs/sasquatch, 或安装 7-Zip")
    if name == "UBI 镜像":
        u = shutil.which("ubireader_extract_files")
        if not u:
            raise ValueError("需要 ubi_reader: "
                             "python -m pip install --user ubi_reader")
        return run_external([u, "-o", outdir, path], log)[0] == 0
    if name in ("cramfs LE", "cramfs BE", "ext4 (magic@0x438)",
                "f2fs (magic@1024)", "erofs (magic@1024)", "romfs"):
        z = find_7z()
        if z:
            return run_external([z, "x", f"-o{outdir}", "-y", path],
                                log)[0] == 0
        raise ValueError("该格式建议安装 7-Zip (或 WSL 挂载)")
    if name == "tar (ustar@257)":
        return extract_archive_python(path, outdir, "tar", log)
    if name == "ZIP/JAR":
        return extract_archive_python(path, outdir, "zip", log)
    raise ValueError(f"暂不支持自动解包: {name}")


# ------------------------------------------------------------------ 高层流程
def default_outdir(path):
    stem = os.path.splitext(os.path.basename(path))[0]
    return os.path.join(os.path.dirname(os.path.abspath(path)),
                        stem + "_unpack")


def do_scan(path, head_n=256, max_hits=12, log=print):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    size = os.path.getsize(path)
    log(f"文件: {path}")
    log(f"大小: {size} 字节 (0x{size:X})")
    with open(path, "rb") as fp:
        head = fp.read(max(head_n, 512))
        fp.seek(max(0, size - 1024))
        tail = fp.read(1024) if size > head_n else b""
    log("\n===== 头部 hex =====")
    log(hexdump(head, 0, min(head_n, len(head))))
    if tail:
        show = tail[-128:]
        log("\n===== 尾部 hex (OpenWrt fwtool 元数据常附在压缩流尾部) =====")
        log(hexdump(show, size - len(show), len(show)))
        _txt, _meta = parse_fwtool_trailer(tail)
        if _meta:
            v = _meta.get("version", {})
            log(f"  >>> fwtool 元数据: devices={_meta.get('supported_devices')} "
                f"v={v.get('version')} target={v.get('target')} "
                f"board={v.get('board')} type={v.get('type')}  "
                f"(无需解包即可确认平台)")
    with open(path, "rb") as fp:
        data = fp.read()
    log("\n===== magic 命中表 (偏移候选; 压缩流内部命中多为巧合) =====")
    for name, hits in find_magic_hits(data, MAGIC_TABLE, max_hits).items():
        log(f"  {name:<22} " + ", ".join(f"0x{i:X}" for i in hits))
    log("\n===== gzip 成员 (逐个实解验证, 排除压缩流内部巧合命中) =====")
    mem = list_gzip_members(data, max_hits)
    if not mem:
        log("  (无)")
    for off, flg, xfl, fname in mem:
        valid, olen, note = validate_gzip_at(data, off)
        tag = "VALID" if valid else "误报?"
        shown = fname if len(fname) <= 40 else fname[:40] + "…"
        log(f"  @0x{off:08X}  FLG=0x{flg:02X} XFL=0x{xfl:02X} "
            f"FNAME=[{shown}]  [{tag}{note}] 解出~0x{olen:X}")
    det = detect_head(data)
    log("\n===== 偏移 0 判定 =====")
    if det:
        name, cat = det
        log(f"  >>> {name}  [{cat}]")
        tips = {
            "comp": "下一步: 点 [2 剥一层压缩] (或直接[一键智能解包]), "
                    "然后对产物再扫描 (可能多层)",
            "arch": "下一步: cpio/tar 点 [3 解包cpio] 或 [5 解包文件系统]",
            "fs":   "下一步: 点 [5 解包文件系统] (JFFS2 需 jefferson)",
            "image": "引导镜像: uImage 可按偏移64 [4切分区段] 后再扫描; "
                     "FIT 用 dumpimage",
        }
        log("  建议: " + tips.get(cat, ""))
    else:
        log("  偏移 0 无已知 magic -> 厂商分段裸包 (私有头+按擦除块对齐的分区)")
        log("  建议: 点 [7 分段裸包探测] 自动定位 JFFS2/内核/段名, "
            "或 [一键智能解包] 全自动; 手工则 [6 找分区线索]+[4 切分区段]")
    return det


def do_peel(path, offset, outpath, fmt="auto", log=print):
    raw = open(path, "rb").read()
    out, tail, used = decompress_one(raw[offset:] if offset else raw, fmt)
    os.makedirs(os.path.dirname(os.path.abspath(outpath)), exist_ok=True)
    with open(outpath, "wb") as fp:
        fp.write(out)
    log(f"{used} @0x{offset:X}: 解压 {len(out)} 字节 -> {outpath}")
    if tail:
        log(f"注意: 流后剩余 {len(tail)} 字节")
        if save_fwtool_metadata(tail, outpath, log) is None:
            log("  (非 fwtool 元数据; 可能是分段镜像后续数据/第二成员)")
    det = detect_head(out)
    log(f"产物偏移0: {det[0]} [{det[1]}]" if det else
        "产物偏移0: 无已知 magic (很可能是分段裸包, 用[7分段裸包探测])")
    return outpath


def do_split(path, offset, length, outpath, log=print):
    size = os.path.getsize(path)
    if length <= 0:
        length = size - offset
    if offset < 0 or offset + length > size:
        raise ValueError(f"切片越界: 文件 0x{size:X}, "
                         f"请求 0x{offset:X}+0x{length:X}")
    with open(path, "rb") as fp:
        fp.seek(offset)
        blob = fp.read(length)
    os.makedirs(os.path.dirname(os.path.abspath(outpath)), exist_ok=True)
    with open(outpath, "wb") as fp:
        fp.write(blob)
    log(f"切片 0x{offset:X}..0x{offset + length:X} ({len(blob)} 字节) "
        f"-> {outpath}")
    det = detect_head(blob)
    log(f"段首类型: {det[0]}" if det else "段首无 magic (检查偏移/块对齐)")
    return outpath


def do_find_partitions(path, max_hits=8, log=print):
    data = open(path, "rb").read()
    log("===== 分区名 ASCII 串命中 (用于反推段边界) =====")
    any_hit = False
    for nm in PARTITION_NAMES:
        needle = nm.encode()
        hits, start = [], 0
        while len(hits) < max_hits:
            i = data.find(needle, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
        if hits:
            any_hit = True
            log(f"  {nm:<12} " + ", ".join(f"0x{i:X}" for i in hits))
    if not any_hit:
        log("  (无) — 段表可能在 initramfs 的 upgrade.sh/platform.sh 里")
    log("提示: 海思 Hi6352 常见 11 段(xloader/hiboot/m3image/teeos/"
        "trusted_fw/kernel/system...), 块 0x20000")
    return any_hit


def probe_segmented(data, log=print, max_hits=12):
    """对"偏移0无 magic"的厂商分段裸包做内部探测 (解包流 1.4):
    JFFS2 根文件系统段 / 可实解的 gzip 成员(标明 cpio/kernel) / FIT / 段名。
    只做识别, 不写文件。返回 dict。"""
    log("===== 分段裸包内部探测 =====")
    res = {"jffs2": None, "cpio_gzip": [], "gzips": [],
           "fit": [], "names": {}}
    n = len(data)
    # 1) JFFS2: dirent 节点后 0x2C 处通常紧跟 inode 节点, 双 magic 互证
    dj = b"\x85\x19\x01\xe0"
    ij = b"\x85\x19\x02\xe0"
    s = 0
    while True:
        i = data.find(dj, s)
        if i < 0:
            break
        s = i + 1
        if i + 0x40 < n and data[i + 0x2C:i + 0x30] == ij:
            res["jffs2"] = i
            break
    if res["jffs2"] is not None:
        o = res["jffs2"]
        log(f"  [JFFS2 rootfs] 起始 @0x{o:X}  (dirent+inode 双节点互证, "
            f"对齐 0x{o % 0x20000:X}/0x20000)")
    # 2) 全部可实解的 gzip 成员; 产物头是 cpio 的另列
    for off, flg, xfl, fname in list_gzip_members(data, max_hits):
        valid, olen, note = validate_gzip_at(data, off)
        if not valid or olen < 0x10000:
            continue
        res["gzips"].append((off, xfl, olen, note))
        if "cpio" in note:
            res["cpio_gzip"].append((off, olen))
            log(f"  [gzip->cpio] @0x{off:X} XFL=0x{xfl:02X} "
                f"解出 ~0x{olen:X} 字节")
        elif xfl == 2:
            log(f"  [gzip->内核Image?] @0x{off:X} XFL=2 "
                f"解出 ~0x{olen:X} 字节")
    # 3) FIT/DTB
    f = data.find(b"\xd0\x0d\xfe\xed")
    if f >= 0:
        res["fit"].append(f)
        log(f"  [FIT/DTB] @0x{f:X}")
    # 4) 段名
    for nm in PARTITION_NAMES:
        needle = nm.encode()
        hits, st = [], 0
        while len(hits) < 5:
            i = data.find(needle, st)
            if i < 0:
                break
            hits.append(i)
            st = i + 1
        if hits:
            res["names"][nm] = hits
    if res["names"]:
        log("  [段名] " + "; ".join(
            f"{k}@0x{v[0]:X}" for k, v in list(res["names"].items())[:8]))
    if res["jffs2"] is None and not res["cpio_gzip"]:
        log("  未自动定位 rootfs/内核; 请在已解出的 initramfs 内找 "
            "bin/upgrade.sh|platform.sh|sbin/sysupgrade 里的 "
            "<文件> <mtd> <块> skip count 段表 (skip/count 按十进制)")
    return res


# ------------------------------------------------- upgrade.sh 段表解析
def _block_size(tok):
    """128k/0x20000/131072 -> 字节数。"""
    t = tok.strip().lower()
    mul = 1
    if t[-1:] in ("k", "m"):
        mul = 1024 if t[-1] == "k" else 1024 * 1024
        t = t[:-1]
    return int(t, 0) * mul


def parse_upgrade_table(blob):
    """从(已解压的)initramfs cpio 数据里解析 upgrade.sh 的 fw_full_upgrade 段表。
    行格式: fw_full_upgrade $1 <mtd名> <擦除块如128k> <skip十进制> [count十进制]
    count 缺省=到镜像尾。自动合并 *bk 备份段。
    返回 [(name, offset, length_or_0)], 按 offset 排序; 无表返回 []。"""
    if b"fw_full_upgrade" not in blob:
        return []
    pat = re.compile(
        rb"fw_full_upgrade\s+\S+\s+([A-Za-z0-9_]+)\s+"
        rb"([0-9][0-9A-Za-z]*)\s+(\d+)(?:\s+(\d+))?")
    seen = {}
    block = 0x20000
    for m in pat.finditer(blob):
        name = m.group(1).decode("ascii", "replace")
        if name.endswith("bk"):
            name = name[:-2]
        try:
            block = _block_size(m.group(2).decode())
            skip = int(m.group(3))
            count = int(m.group(4)) if m.group(4) else 0
        except ValueError:
            continue
        if name not in seen:  # 同名只取第一次 (bk 段与正式段布局一致)
            seen[name] = (skip * block, count * block, skip, count)
    out = [(nm, v[0], v[1]) for nm, v in seen.items()]
    out.sort(key=lambda x: x[1])
    return out


def gunzip_member(data, off):
    d = zlib.decompressobj(31)
    return d.decompress(data[off:]) + d.flush()


def do_probe(path, log=print):
    data = open(path, "rb").read()
    return probe_segmented(data, log)


def _auto_segmented(data, cur, outdir, log):
    """分段裸包全自动: 先用 initramfs 内 upgrade.sh 段表切出全部分区
    (与手工解包目录同构), 再解 system rootfs / initramfs, 并导出
    teeos_cpio / kernel_Image 等衍生件。"""
    info = probe_segmented(data, log)
    pdir = os.path.join(outdir, "partitions")
    os.makedirs(pdir, exist_ok=True)
    n = len(data)
    did = False

    # --- 先解出最大的 cpio-gzip (主 initramfs), 从中拿权威段表 ---
    cpio_blobs = []  # (off, blob)
    for off, _osz in info["cpio_gzip"]:
        cpio_blobs.append((off, gunzip_member(data, off)))
    table = []
    main_off, main_blob = None, None
    if cpio_blobs:
        main_off, main_blob = max(cpio_blobs, key=lambda x: len(x[1]))
        # 段表可能在主 initramfs 也可能在 teeos 安装小镜像里, 全部搜一遍
        table = parse_upgrade_table(b"\n".join(b for _, b in cpio_blobs))
    if table:
        log("===== 从 initramfs upgrade.sh 解析到段表 "
            f"(块 0x{_table_block(table, n):X}) =====")
        spans = {}
        for i, (nm, off, length) in enumerate(table):
            end = off + length if length else n
            end = min(end, n)
            spans[nm] = (off, end)
            segp = os.path.join(pdir, nm + ".bin")
            with open(segp, "wb") as fp:
                fp.write(data[off:end])
            log(f"  {nm:<10} @0x{off:08X}..0x{end:08X} "
                f"(0x{end - off:X}) -> {segp}")
            did = True
    else:
        log("未在 initramfs 中找到 fw_full_upgrade 段表, "
            "退回 JFFS2 单段模式")
        spans = {}
        if info["jffs2"] is not None:
            spans["system"] = (info["jffs2"], n)

    # --- system 段 -> jefferson rootfs ---
    if "system" in spans:
        off, end = spans["system"]
        if data[off:off + 4] != b"\x85\x19\x01\xe0":
            log(f"  注意: system 段头 0x{off:X} 不是 JFFS2 magic, 仍尝试解包")
        segp = os.path.join(pdir, "system.bin")
        if not os.path.isfile(segp):
            with open(segp, "wb") as fp:
                fp.write(data[off:end])
        root = os.path.join(outdir, "system_rootfs")
        try:
            extract_fs(segp, root, log)
            log(f"  >>> system rootfs 已解 -> {root}")
            did = True
        except Exception as e:
            log(f"  JFFS2 解包失败: {e}")

    # --- 按分区跨度给 gzip 成员归类, 导出衍生件 ---
    def span_of(o):
        for nm, (a, b) in spans.items():
            if a <= o < b:
                return nm
        return ""

    teeos_done = False
    initramfs_done = False
    for off, xfl, olen, note in info["gzips"]:
        where = span_of(off)
        blob = None
        if where == "teeos" and "cpio" in note and not teeos_done:
            blob = gunzip_member(data, off)
            cpf = os.path.join(outdir, "teeos_cpio.bin")
            with open(cpf, "wb") as fp:
                fp.write(blob)
            log(f"  teeos 段内 cpio @0x{off:X} -> {cpf}")
            teeos_done = True
            did = True
        elif where == "kernel" and xfl == 2:
            kip = os.path.join(outdir, "kernel_Image.bin")
            with open(kip, "wb") as fp:
                fp.write(gunzip_member(data, off))
            log(f"  kernel 段内 Linux Image @0x{off:X} -> {kip}")
            did = True
        elif where == "kernel" and "cpio" in note:
            blob = gunzip_member(data, off)
            cpf = os.path.join(outdir, "initramfs_cpio.bin")
            with open(cpf, "wb") as fp:
                fp.write(blob)
            root = os.path.join(outdir, "initramfs")
            log(f"  kernel 段内 initramfs @0x{off:X} -> {cpf}")
            cpio_extract(blob, root, log)
            log(f"  >>> initramfs 已解 -> {root}")
            initramfs_done = True
            did = True

    # 无段表时的兜底: 全部 cpio-gzip 照旧解
    if not table:
        for off, blob in cpio_blobs:
            root = os.path.join(outdir, f"initramfs_{off:08X}_root")
            log(f"  initramfs @0x{off:X}")
            cpio_extract(blob, root, log)
            log(f"  >>> initramfs 已解 -> {root}")
            did = True
    return did


def _table_block(table, n):
    """从段表各项偏移反推擦除块大小(相邻偏移差的 GCD), 仅供日志显示。"""
    import math
    offs = sorted({o for _, o, _ in table if o})
    if len(offs) < 2:
        return 0x20000
    d = offs[1] - offs[0]
    for a, b in zip(offs, offs[1:]):
        d = math.gcd(d, b - a)
    return d or 0x20000


def do_auto(path, outdir, log=print):
    """逐层剥压缩 -> 归档/FS 解包; 剥到分段裸包则按段表切全分区并解 rootfs。"""
    os.makedirs(outdir, exist_ok=True)
    cur = path
    layer = 0
    while layer < 8:
        data = open(cur, "rb").read()
        det = detect_head(data)
        if not det:
            if len(data) > 1 << 20:
                log(f"[层{layer}] 偏移0无 magic 且体积 0x{len(data):X}, "
                    "按厂商分段裸包处理")
                if _auto_segmented(data, cur, outdir, log):
                    log("一键解包完成: 全分区在 partitions/, "
                        "rootfs 在 system_rootfs/, initramfs 在 initramfs/")
                    return
            log("无法继续自动识别: 请用 [6找分区线索]/[7分段探测] 或查 "
                "initramfs 内 upgrade.sh 段表")
            return
        name, cat = det
        log(f"[层{layer}] {os.path.basename(cur)} -> {name} [{cat}]")
        if cat == "comp":
            out, tail, used = decompress_one(data)
            # gzip 头带 FNAME(如 firmware.bin) 时沿用原名, 与设备内文件同名
            base = None
            if used == "gzip":
                mem = list_gzip_members(data, 1)
                if mem and mem[0][0] == 0 and mem[0][3]:
                    cand = mem[0][3].replace("/", "_").replace("\\", "_")
                    if cand and re.fullmatch(r"[\w.\- ]+", cand):
                        base = cand
            nxt = os.path.join(outdir, base or f"layer{layer + 1}_{used}.bin")
            with open(nxt, "wb") as fp:
                fp.write(out)
            log(f"  解压 {len(out)} 字节 -> {nxt}")
            if tail:
                if save_fwtool_metadata(tail, nxt, log) is None:
                    log(f"  流后剩余 {len(tail)} 字节 (后续数据/第二成员)")
            cur, layer = nxt, layer + 1
            continue
        if name.startswith("cpio"):
            target = os.path.join(outdir, "initramfs_root")
            cpio_extract(data, target, log)
            log(f"  initramfs -> {target}")
            return
        if name in ("tar (ustar@257)",):
            target = os.path.join(outdir, "tar_root")
            extract_archive_python(cur, target, "tar", log)
            return
        if name == "ZIP/JAR":
            target = os.path.join(outdir, "zip_root")
            extract_archive_python(cur, target, "zip", log)
            return
        if cat == "fs":
            target = os.path.join(outdir,
                                  name.split()[0].lower() + "_root")
            extract_fs(cur, target, log)
            log(f"  文件系统 -> {target}")
            return
        log("引导/ELF 镜像, 需人工处理 (uImage 去64字节头; FIT 用 "
            "dumpimage); 或继续 [4 切分区段]")
        return
    log("已达最大层数 8")


# ================================================================== NRadio .nr
# 移植自 nr_tool.py (逆向 /sbin/sysupgrade 实证): NUL + ASCII头 + gzip(tar),
# crc = MD5(b"nradio_security_akxo1f\n" + gzip)
NR_KEY_DATA = b"nradio_security_akxo1f"
NR_UNLOCK_SCRIPT = "etc/uci-defaults/99-nr-unlock"


class NrError(Exception):
    pass


def nr_split(data):
    if not data or data[0] != 0x00:
        raise NrError("不是合法 .nr 文件 (首字节应为 0x00)")
    nl = data.find(b"\n")
    if nl < 0:
        raise NrError("找不到头部换行符")
    return data[1:nl], data[nl + 1:]


def nr_parse_head(head):
    fields = {}
    for tok in head.split(b" "):
        if b"=" in tok:
            k, v = tok.split(b"=", 1)
            fields[k.decode()] = v.decode()
    for k in ("name", "size", "crc", "type"):
        if k not in fields:
            raise NrError(f"头部缺字段 {k}: {head!r}")
    return fields


def nr_calc_crc(gz):
    import hashlib
    return hashlib.md5(NR_KEY_DATA + b"\n" + gz).hexdigest()


def nr_make_gzip(tar_bytes, level=6):
    """设备风格 gzip: mtime=0, XFL=0, OS=Unix(3)。"""
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=level,
                       fileobj=buf, mtime=0) as gf:
        gf.write(tar_bytes)
    out = bytearray(buf.getvalue())
    out[9] = 0x03
    return bytes(out)


def nr_read(path):
    data = open(path, "rb").read()
    head, gz = nr_split(data)
    fields = nr_parse_head(head)
    real_crc = nr_calc_crc(gz)
    members, tar_ok, tar_bytes = [], False, b""
    try:
        tar_bytes = gzip.decompress(gz)
        tf = tarfile.open(fileobj=io.BytesIO(tar_bytes))
        members = tf.getmembers()
        tf.close()
        tar_ok = True
    except Exception:
        pass
    return {
        "fields": fields, "gz": gz, "tar": tar_bytes, "members": members,
        "tar_ok": tar_ok, "ok_size": int(fields["size"]) == len(gz),
        "ok_crc": fields["crc"] == real_crc, "real_crc": real_crc,
    }


def nr_info(path, log=print):
    r = nr_read(path)
    f = r["fields"]
    log(f"文件        : {path}")
    log(f"name/type   : {f['name']} / {f['type']}")
    log(f"size 声称/实际: {f['size']} / {len(r['gz'])}   "
        f"{'OK' if r['ok_size'] else 'MISMATCH'}")
    log(f"crc  声称    : {f['crc']}")
    log(f"crc  实算    : {r['real_crc']}   "
        f"{'OK(盐校验通过)' if r['ok_crc'] else 'MISMATCH'}")
    log(f"tar 完整性   : {'OK' if r['tar_ok'] else '损坏'}")
    log(f"包内文件数   : {len(r['members'])}")
    for m in r["members"][:200]:
        kind = "d" if m.isdir() else ("l" if m.issym() else "f")
        log(f"  [{kind}] {oct(m.mode)[2:]:>4} {m.size:7d}  {m.name}")
    if len(r["members"]) > 200:
        log(f"  … 其余 {len(r['members']) - 200} 项略")
    return r


def nr_verify(path, log=print):
    r = nr_read(path)
    bad = []
    if not r["ok_size"]:
        bad.append("size 字段不匹配")
    if not r["ok_crc"]:
        bad.append("crc 不匹配 (改过内容但未重打包?)")
    if not r["tar_ok"]:
        bad.append("tar/gzip 损坏")
    if bad:
        for x in bad:
            log("FAIL: " + x, )
        raise NrError("校验失败: " + "; ".join(bad))
    log("PASS: 头部 / crc(盐 nradio_security_akxo1f) / tar 全部合法, "
        "设备 sysupgrade --valid-tag 可接受")
    return True


def nr_unpack(path, outdir, log=print):
    r = nr_read(path)
    if not r["tar_ok"]:
        raise NrError("tar 损坏, 拒绝解包")
    if not outdir:
        base = os.path.splitext(os.path.basename(path))[0]
        outdir = os.path.join(os.path.dirname(os.path.abspath(path)),
                              base + "_unpacked")
    if os.path.isdir(outdir) and os.listdir(outdir):
        raise NrError(f"目录非空, 请换空目录: {outdir}")
    os.makedirs(outdir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(r["tar"])) as tf:
        try:
            tf.extractall(outdir, filter="data")
        except TypeError:
            tf.extractall(outdir)
    log(f"已解包 {len(r['members'])} 个文件 -> {outdir}")
    return outdir


def nr_is_exec_path(rel):
    if "/init.d/" in "/" + rel or rel.startswith("etc/uci-defaults/"):
        return True
    if rel == "etc/rc.local":
        return True
    return rel.endswith(".sh") and any(
        ("/" + rel).startswith(p) for p in
        ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"))


def nr_build_tar(srcdir):
    """复刻设备 tar: 仅文件/符号链接, 相对 POSIX 路径, root:root。"""
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
    srcdir = os.path.abspath(srcdir)
    for root, dirs, files in os.walk(srcdir):
        dirs.sort()
        files.sort()
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, srcdir).replace(os.sep, "/")
            if rel.startswith("./"):
                rel = rel[2:]
            ti = tarfile.TarInfo(rel)
            ti.uid = ti.gid = 0
            if os.path.islink(full):
                ti.type = tarfile.SYMTYPE
                ti.linkname = os.readlink(full)
                ti.mode = 0o777
                ti.mtime = 0
                tf.addfile(ti)
            else:
                st = os.stat(full)
                ti.size = st.st_size
                ti.mode = 0o755 if nr_is_exec_path(rel) else 0o644
                ti.mtime = int(st.st_mtime)
                with open(full, "rb") as fp:
                    tf.addfile(ti, fp)
    tf.close()
    return buf.getvalue()


def nr_write(tar_bytes, outpath):
    gz = nr_make_gzip(tar_bytes)
    crc = nr_calc_crc(gz)
    head = f"name=- size={len(gz)} crc={crc} type=config\n".encode()
    os.makedirs(os.path.dirname(os.path.abspath(outpath)), exist_ok=True)
    tmp = outpath + ".tmp"
    with open(tmp, "wb") as fp:
        fp.write(b"\x00" + head + gz)
    os.replace(tmp, outpath)
    return len(gz), crc


def nr_pack(srcdir, outpath, log=print):
    if not os.path.isdir(srcdir):
        raise NrError(f"不是目录: {srcdir}")
    gz_len, crc = nr_write(nr_build_tar(srcdir), outpath)
    log(f"已打包 -> {outpath}  (gzip {gz_len} 字节, crc={crc})")
    log("可直接在网页[备份/升级]-[恢复备份]上传。")
    return outpath


NR_UNLOCK_SH = """#!/bin/sh
# Injected by GUI tool - runs once on next boot via /etc/uci-defaults
# (sourced by /etc/init.d/boot, deleted automatically after success).

# 1) SSH: firewall 中名为 ssh 的规则置 ACCEPT (等同隐藏安全页)
uci -q delete firewall.ssh
uci set firewall.ssh=rule
uci set firewall.ssh.name='Allow-SSH'
uci set firewall.ssh.src='lan'
uci set firewall.ssh.family='ipv4'
uci set firewall.ssh.proto='tcp'
uci set firewall.ssh.dest_port='22'
uci set firewall.ssh.target='ACCEPT'

# 2) adbd (恢复逻辑会丢弃包内 adbd 配置, 只能开机脚本设置)
uci set adbd.service.enable='1'

# 3) 显示隐藏 AT 指令页 (仅 oem 标记为 odm 时; 二次密码 admin@0515)
if [ "$(uci -q get oem.custom.com)" = "odm" ]; then
	uci set oem.custom.com=' '
fi

exit 0
"""


def nr_unlock(path, outpath, at=True, log=print):
    import shutil
    import tempfile
    r = nr_read(path)
    if not r["tar_ok"]:
        raise NrError("源备份损坏")
    if not outpath:
        outpath = os.path.join(
            os.path.dirname(os.path.abspath(path)) or ".",
            os.path.splitext(os.path.basename(path))[0] + "-unlock.nr")
    work = tempfile.mkdtemp(prefix="nr_unlock_")
    try:
        with tarfile.open(fileobj=io.BytesIO(r["tar"])) as tf:
            try:
                tf.extractall(work, filter="data")
            except TypeError:
                tf.extractall(work)
        p = os.path.join(work, *NR_UNLOCK_SCRIPT.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        body = NR_UNLOCK_SH
        if not at:
            body = body.replace(
                "\n# 3) 显示隐藏 AT 指令页 (仅 oem 标记为 odm 时; "
                "二次密码 admin@0515)\n"
                "if [ \"$(uci -q get oem.custom.com)\" = \"odm\" ]; then\n"
                "\tuci set oem.custom.com=' '\n"
                "fi\n", "")
        with open(p, "w", newline="\n", encoding="utf-8") as fp:
            fp.write(body)
        gz_len, crc = nr_write(nr_build_tar(work), outpath)
        log("=" * 56)
        log(f"一键解锁备份已生成: {outpath}")
        log(f"注入: {NR_UNLOCK_SCRIPT}  (gzip {gz_len}, crc={crc})")
        log("开机效果: 1) LAN SSH(dropbear:22, root/admin)  2) adbd"
            + ("" if not at else "  3) 显示 AT 页(admin@0515)"))
        log("上传: 网页[备份/升级]->[恢复备份], 校验通过后自动重启, "
            "脚本执行一次后自删。")
        log("=" * 56)
        return outpath
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ========================================================= 逆向打包 (解包流反向)
def compress_bytes(data, fmt, level=6):
    """裸数据 -> 压缩流。gzip 仿真设备(mtime=0/OS=3)。"""
    if fmt == "gzip":
        return nr_make_gzip(data, level)
    if fmt == "xz":
        return lzma.compress(data, format=lzma.FORMAT_XZ, preset=level)
    if fmt == "lzma":
        return lzma.compress(data, format=lzma.FORMAT_ALONE, preset=level)
    if fmt == "bz2":
        return bz2.compress(data, compresslevel=min(9, max(1, level)))
    if fmt == "zstd":
        try:
            import zstandard
        except ImportError:
            raise ValueError("需要 zstandard: "
                             "python -m pip install --user zstandard")
        return zstandard.ZstdCompressor(level=level).compress(data)
    raise ValueError(f"不支持的压缩格式: {fmt}")


def _tar_add_dirs(tf, srcdir):
    """向 tar 补充目录条目(打包归档时保留空目录)。"""
    srcdir = os.path.abspath(srcdir)
    for root, dirs, _files in os.walk(srcdir):
        dirs.sort()
        for d in dirs:
            full = os.path.join(root, d)
            rel = os.path.relpath(full, srcdir).replace(os.sep, "/")
            ti = tarfile.TarInfo(rel + "/")
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            ti.uid = ti.gid = 0
            ti.mtime = 0
            tf.addfile(ti)


def build_tar_full(srcdir):
    """通用打包: 目录/文件/符号链接全部保留, 权限沿用源文件, root:root。"""
    buf = io.BytesIO()
    srcdir = os.path.abspath(srcdir)
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for root, dirs, files in os.walk(srcdir):
            dirs.sort()
            files.sort()
            names = dirs + files
            for nm in names:
                full = os.path.join(root, nm)
                rel = os.path.relpath(full, srcdir).replace(os.sep, "/")
                st = os.lstat(full)
                ti = tarfile.TarInfo(rel + ("/" if os.path.isdir(full)
                                            and not os.path.islink(full)
                                            else ""))
                ti.uid = ti.gid = 0
                ti.mtime = 0
                if os.path.islink(full):
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = os.readlink(full)
                    ti.mode = 0o777
                    tf.addfile(ti)
                elif os.path.isdir(full):
                    ti.type = tarfile.DIRTYPE
                    ti.mode = 0o755
                    tf.addfile(ti)
                elif os.path.isfile(full):
                    ti.size = st.st_size
                    ti.mode = st.st_mode & 0o7777 or 0o644
                    with open(full, "rb") as fp:
                        tf.addfile(ti, fp)
    return buf.getvalue()


def build_cpio_newc(srcdir):
    """目录 -> cpio newc(070701) 字节流 (initramfs 反向打包)。

    4 字节对齐; 含目录/普通文件/符号链接; root:root; 末尾 TRAILER!!!;
    最后补 0 到 512 字节块边界 (内核 initramfs 惯例)。
    """
    def hx(v):
        return f"{v:08X}".encode()

    def entry(name, mode, size, body=b"", ftype=None, ino=1):
        # newc 13 个 8-hex 字段 (magic 之后):
        # ino mode uid gid nlink mtime filesize devmaj devmin rdevmaj
        # rdevmin namesize check
        n = name.encode() + b"\x00"
        hdr = b"070701" + b"".join(hx(x) for x in (
            ino, mode, 0, 0,
            2 if ftype == stat.S_IFDIR else 1,
            0, size, 0, 0, 0, 0, len(n), 0))
        blob = hdr + n
        blob += b"\x00" * ((4 - len(blob) % 4) % 4)
        blob += body
        blob += b"\x00" * ((4 - len(blob) % 4) % 4)
        return blob

    srcdir = os.path.abspath(srcdir)
    out, ino = b"", 1
    out += entry(".", stat.S_IFDIR | 0o755, 0, ftype=stat.S_IFDIR, ino=ino)
    for root, dirs, files in os.walk(srcdir):
        dirs.sort()
        files.sort()
        for nm in dirs + files:
            full = os.path.join(root, nm)
            rel = os.path.relpath(full, srcdir).replace(os.sep, "/")
            ino += 1
            st = os.lstat(full)
            if os.path.islink(full):
                tgt = os.readlink(full).encode()
                out += entry(rel, stat.S_IFLNK | 0o777, len(tgt), tgt,
                             ino=ino)
            elif os.path.isdir(full):
                out += entry(rel, stat.S_IFDIR | 0o755, 0,
                             ftype=stat.S_IFDIR, ino=ino)
            elif os.path.isfile(full):
                mode = stat.S_IFREG | (st.st_mode & 0o7777 or 0o644)
                with open(full, "rb") as fp:
                    body = fp.read()
                out += entry(rel, mode, len(body), body, ino=ino)
    out += entry("TRAILER!!!", 0, 0, ino=ino + 1)
    out += b"\x00" * ((512 - len(out) % 512) % 512)
    return out


def do_pack_archive(srcdir, outpath, kind, comp, log=print):
    if not os.path.isdir(srcdir):
        raise ValueError(f"不是目录: {srcdir}")
    raw = build_cpio_newc(srcdir) if kind == "cpio" else build_tar_full(srcdir)
    n_file = 0
    for _r, _d, fs in os.walk(srcdir):
        n_file += len(fs)
    if comp and comp != "none":
        blob = compress_bytes(raw, comp)
        if not outpath:
            outpath = os.path.abspath(srcdir.rstrip("/\\")) + (
                ".cpio." + ("gz" if comp == "gzip" else comp)) \
                if kind == "cpio" else os.path.abspath(
                    srcdir.rstrip("/\\")) + ".tar." + (
                    "gz" if comp == "gzip" else comp)
        log(f"{kind} {n_file} 文件, 原始 {len(raw)} -> {comp} "
            f"{len(blob)} 字节 -> {outpath}")
    else:
        blob = raw
        if not outpath:
            outpath = os.path.abspath(srcdir.rstrip("/\\")) + (
                ".cpio" if kind == "cpio" else ".tar")
        log(f"{kind} {n_file} 文件, {len(blob)} 字节 -> {outpath}")
    os.makedirs(os.path.dirname(os.path.abspath(outpath)), exist_ok=True)
    with open(outpath, "wb") as fp:
        fp.write(blob)
    return outpath


def do_compress_file(path, fmt, outpath, log=print):
    raw = open(path, "rb").read()
    blob = compress_bytes(raw, fmt)
    if not outpath:
        ext = {"gzip": ".gz", "xz": ".xz", "lzma": ".lzma",
               "bz2": ".bz2", "zstd": ".zst"}[fmt]
        outpath = path + ext
    with open(outpath, "wb") as fp:
        fp.write(blob)
    log(f"{os.path.basename(path)} {len(raw)} -> {fmt} {len(blob)} "
        f"-> {outpath}")
    return outpath


def do_mkfs(srcdir, outpath, fs, eraseblock, comp, log=print):
    """目录重打包为文件系统镜像 (依赖外部 mkfs 工具, Windows 少见)。"""
    if not os.path.isdir(srcdir):
        raise ValueError(f"不是目录: {srcdir}")
    if fs == "jffs2":
        tool = shutil.which("mkfs.jffs2")
        if not tool:
            raise ValueError("需要 mkfs.jffs2 (mtd-utils, 仅 Linux/WSL)。"
                             "替代: 在 WSL 内执行 "
                             f"mkfs.jffs2 -r <目录> -o out.jffs2 "
                             f"-e 0x{eraseblock:x} -n")
        cmd = [tool, "-r", srcdir, "-o", outpath,
               "-e", hex(eraseblock), "-n", "--little-endian"]
        rc = run_external(cmd, log)[0]
        if rc != 0:
            raise ValueError("mkfs.jffs2 失败")
        log(f"JFFS2 镜像 -> {outpath} (擦除块 0x{eraseblock:X})")
        return outpath
    if fs == "squashfs":
        tool = shutil.which("mksquashfs")
        if not tool:
            raise ValueError("需要 mksquashfs (Linux/WSL 或 sasquatch)")
        cmd = [tool, srcdir, outpath, "-noappend", "-comp",
               comp or "xz"]
        if run_external(cmd, log)[0] != 0:
            raise ValueError("mksquashfs 失败")
        log(f"squashfs({comp or 'xz'}) -> {outpath}")
        return outpath
    raise ValueError(f"不支持的文件系统打包: {fs}")


def do_join(segments, outpath, pad_block=0, fill=0xFF, log=print):
    """分区段按序拼接 (切分区段的逆操作)。pad_block>0 时除最后一段外,
    每段后用 fill 填充到块边界(海思分段镜像块对齐, 常用 0x20000/0xFF)。"""
    if not segments:
        raise ValueError("未选择段文件")
    total = 0
    with open(outpath, "wb") as out:
        for idx, seg in enumerate(segments):
            blob = open(seg, "rb").read()
            out.write(blob)
            total += len(blob)
            extra = ""
            if pad_block and idx < len(segments) - 1 and len(blob) % pad_block:
                pad = pad_block - len(blob) % pad_block
                out.write(bytes([fill]) * pad)
                total += pad
                extra = f"  +填充0x{pad:X}"
            log(f"  [{idx}] {os.path.basename(seg)} 0x{len(blob):X}{extra}")
    log(f"拼接完成 {len(segments)} 段, 共 0x{total:X} -> {outpath}")
    return outpath


# ------------------------------------- fwtool 全量升级包逆向打包 (分段裸包)
FWTOOL_BLOCK = 0x20000
# moses(华为 Hi6352 RedCap) 全量升级段表: (分区名, 块数), 块=128K;
# 块数 0 = 最后一段(system/JFFS2), 长度到镜像尾。偏移按顺序累计,
# 与 initramfs 内 upgrade.sh 的 fw_full_upgrade 段表一致。
FWTOOL_LAYOUTS = {
    "moses": [
        ("xloader", 4), ("ptable", 3), ("mnvdload", 4), ("uce", 3),
        ("hiboot", 10), ("dts", 4), ("m3image", 4), ("teeos", 8),
        ("trusted_fw", 3), ("kernel", 50), ("system", 0),
    ],
}
FWTOOL_DEFAULT_META = (
    '{ "metadata_version": "1.1", "compat_version": "1.1", '
    '"supported_devices": ["moses"], "version": { "version": "v24.1.1.101", '
    '"target": "TD-RedCap", "board": "moses", "type": "user" } }'
)


def fwtool_make_gzip(data, level=9, mtime=0):
    """构造厂商风格 gzip 帧: FLG=0x08 带 FNAME=firmware.bin,
    XFL=2(最大压缩标记), OS=3(Unix)。设备端 zcat 只要求能完整解压。"""
    co = zlib.compressobj(level, zlib.DEFLATED, -15)
    body = co.compress(data) + co.flush()
    head = (b"\x1f\x8b\x08\x08" + struct.pack("<I", mtime & 0xFFFFFFFF)
            + b"\x02\x03firmware.bin\x00")
    tail = struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF,
                       len(data) & 0xFFFFFFFF)
    return head + body + tail


def fwtool_load_metadata(partitions_dir, metadata_path, log=print):
    """元数据 JSON 来源: 显式指定 > 解包时自动保存的
    peeled_0x0.bin.metadata.json(或同级其它 *.metadata.json) > 内置默认。"""
    if metadata_path:
        with open(metadata_path, "r", encoding="utf-8") as fp:
            log(f"  元数据(指定): {metadata_path}")
            return fp.read()
    parent = os.path.dirname(os.path.abspath(partitions_dir.rstrip("/\\")))
    prefer = os.path.join(parent, "peeled_0x0.bin.metadata.json")
    cands = [prefer] if os.path.isfile(prefer) else []
    cands += [p for p in sorted(glob.glob(
        os.path.join(parent, "*.metadata.json"))) if p not in cands]
    if cands:
        with open(cands[0], "r", encoding="utf-8") as fp:
            log(f"  元数据(自动): {cands[0]}")
            return fp.read()
    log("  未找到解包保存的 metadata.json, 使用内置 moses 默认元数据")
    return FWTOOL_DEFAULT_META


def build_fwtool_package(partitions_dir, outpath, metadata_path=None,
                         layout="moses", level=9, log=print):
    """partitions 目录(11 个 <name>.bin) -> OpenWrt fwtool 全量升级包,
    是"一键智能解包"的逆过程:
      1. 按 upgrade.sh 段表顺序拼出分段内镜像(各段已块对齐, 不额外填充)
      2. gzip 压缩(FLG=FNAME firmware.bin, XFL=2, OS=3)
      3. 追加 fwtool 尾部: 8xNUL 头 + JSON+'\\n' + 16 字节 'FWx0' 尾
    尾 CRC32 = 标准 CRC32(初值 FFFFFFFF, 末位不取反) 覆盖
    gzip整包 + 8字节NUL头 + JSON(含LF); size=8+len(json)+16。
    """
    table = FWTOOL_LAYOUTS.get(layout)
    if not table:
        raise ValueError(
            f"未知段布局: {layout} (已知: {', '.join(FWTOOL_LAYOUTS)})")
    if not os.path.isdir(partitions_dir):
        raise ValueError(f"不是分区目录: {partitions_dir}")
    log(f"===== 打包 fwtool 升级包 (布局={layout}, 块 0x{FWTOOL_BLOCK:X}) =====")
    pieces, off = [], 0
    for i, (nm, cnt) in enumerate(table):
        segp = os.path.join(partitions_dir, nm + ".bin")
        if not os.path.isfile(segp):
            raise ValueError(f"缺少分区段文件: {segp}")
        blob = open(segp, "rb").read()
        expect = cnt * FWTOOL_BLOCK if cnt else 0
        if expect:
            if len(blob) != expect:
                raise ValueError(
                    f"段 {nm} 长度 0x{len(blob):X} 与段表定义 "
                    f"0x{expect:X}({cnt} 块)不符; 固定段长度不能改, "
                    "否则其后各段偏移会全部错位 (尾段 system 除外)")
        elif i != len(table) - 1:
            raise ValueError(f"段表内部错误: 块数0(到镜像尾)只能是最后一段 "
                             f"{nm}")
        pieces.append(blob)
        log(f"  {nm:<10} @0x{off:08X} 0x{len(blob):X}"
            + ("" if expect else "  (尾段, 长度随 rootfs)"))
        off += len(blob)
    inner = b"".join(pieces)
    log(f"  内镜像拼接完成: 0x{len(inner):X} ({len(inner)} 字节)")

    meta_txt = fwtool_load_metadata(partitions_dir, metadata_path, log)
    jsonnl = meta_txt.strip().encode("utf-8") + b"\n"
    gz = fwtool_make_gzip(inner, level)
    hdr8 = b"\x00" * 8
    crc = (~zlib.crc32(gz + hdr8 + jsonnl)) & 0xFFFFFFFF
    total = 8 + len(jsonnl) + 16
    trailer = (b"FWx0" + struct.pack(">I", crc) + b"\x01\x00\x00\x00"
               + struct.pack(">I", total))
    package = gz + hdr8 + jsonnl + trailer
    os.makedirs(os.path.dirname(os.path.abspath(outpath)), exist_ok=True)
    with open(outpath, "wb") as fp:
        fp.write(package)
    log(f"  gzip: 0x{len(inner):X} -> 0x{len(gz):X}, "
        "FNAME=firmware.bin XFL=2 OS=3")
    log(f"  fwtool 尾部 {total} 字节 (JSON {len(jsonnl)}), "
        f"尾CRC32={crc:08X}")
    log(f"  升级包写出: {outpath} ({len(package)} 字节)")
    log("  提示: 修改 system_rootfs 后需先在 WSL 内用 "
        "mkfs.jffs2 -r <目录> -o system.bin -e 0x20000 -n 重建该段")
    return outpath


# ================================================================== GUI
class App:
    def __init__(self, root):
        self.root = root
        root.title("固件 / NR备份 可视化解包-打包工具")
        root.geometry("1040x780")
        self.q = queue.Queue()
        self.busy = False

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=False, padx=6, pady=(6, 2))
        tab_fw = ttk.Frame(nb)
        tab_nr = ttk.Frame(nb)
        tab_pk = ttk.Frame(nb)
        nb.add(tab_fw, text=" ① 固件解包 ")
        nb.add(tab_nr, text=" ② NR 备份 (info/解包/打包/解锁) ")
        nb.add(tab_pk, text=" ③ 逆向打包 (cpio/tar/压缩/镜像/拼接) ")

        self._build_tab_fw(tab_fw)
        self._build_tab_nr(tab_nr)
        self._build_tab_pk(tab_pk)

        logbar = ttk.Frame(root)
        ttk_button(logbar, "清空日志", self.clear_log, width=12).pack(
            side="left", padx=2)
        ttk_button(logbar, "保存日志", self.save_log, width=12).pack(
            side="left", padx=2)
        logbar.pack(fill="x", padx=6)

        self.logw = tk.Text(root, wrap="none", bg="#11141a", fg="#d8dee9",
                            font=("Consolas", 9), undo=False)
        ysb = ttk.Scrollbar(root, command=self.logw.yview)
        self.logw.configure(yscrollcommand=ysb.set)
        self.logw.tag_config("err", foreground="#f38ba8")
        self.logw.tag_config("ok", foreground="#a6e3a1")
        self.logw.tag_config("warn", foreground="#f9e2af")
        self.status = tk.StringVar(value="就绪")
        ttk.Label(root, textvariable=self.status, relief="sunken").pack(
            fill="x", side="bottom")
        ysb.pack(side="right", fill="y")
        self.logw.pack(fill="both", expand=True, padx=6, pady=4)

        self._pump()

    # ------------------------------------------------- 公共小部件构造
    @staticmethod
    def _row_path(parent, row, label, var, browse_cmd, dir_mode=False):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w",
                                           padx=4, pady=3)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1,
                                                 sticky="we", padx=4)
        ttk.Button(parent, text="浏览…", command=browse_cmd,
                   width=10).grid(row=row, column=2, padx=4)

    @staticmethod
    def _btn_grid(parent, specs, per_row=5):
        for i, (txt, fn) in enumerate(specs):
            ttk.Button(parent, text=txt, command=fn,
                       width=20).grid(row=i // per_row, column=i % per_row,
                                      padx=4, pady=3)

    # ------------------------------------------------- Tab1 固件解包
    def _build_tab_fw(self, p):
        frm = ttk.Frame(p)
        self.var_in = tk.StringVar()
        self.var_out = tk.StringVar()
        self._row_path(frm, 0, "固件文件:", self.var_in, self.browse_in)
        self._row_path(frm, 1, "输出目录:", self.var_out, self.browse_out)
        self.var_in.trace_add("write", self._auto_out)
        frm.columnconfigure(1, weight=1)
        frm.pack(fill="x")

        opt = ttk.LabelFrame(p, text="切段参数 (偏移/长度支持 0x.. 与 K/M/G)")
        self.var_off = tk.StringVar(value="0")
        self.var_len = tk.StringVar(value="0")
        self.var_block = tk.StringVar(value="0x20000")
        self.var_skip = tk.StringVar(value="0")
        self.var_count = tk.StringVar(value="0")
        ttk.Label(opt, text="偏移:").grid(row=0, column=0, sticky="e", padx=4)
        ttk.Entry(opt, textvariable=self.var_off, width=14).grid(
            row=0, column=1, sticky="w")
        ttk.Label(opt, text="长度(0=到尾):").grid(row=0, column=2, sticky="e")
        ttk.Entry(opt, textvariable=self.var_len, width=14).grid(
            row=0, column=3, sticky="w")
        ttk.Label(opt, text="块大小:").grid(row=1, column=0, sticky="e",
                                            padx=4)
        ttk.Entry(opt, textvariable=self.var_block, width=14).grid(
            row=1, column=1, sticky="w")
        ttk.Label(opt, text="skip块:").grid(row=1, column=2, sticky="e")
        ttk.Entry(opt, textvariable=self.var_skip, width=8).grid(
            row=1, column=3, sticky="w")
        ttk.Label(opt, text="count块:").grid(row=1, column=4, sticky="e")
        ttk.Entry(opt, textvariable=self.var_count, width=8).grid(
            row=1, column=5, sticky="w")
        ttk.Button(opt, text="按skip/count填充",
                   command=self.fill_block).grid(row=1, column=6, padx=8)
        opt.pack(fill="x", pady=4)

        btns = ttk.Frame(p)
        self._btn_grid(btns, [
            ("1 扫描识别", self.t_scan),
            ("2 剥一层压缩", self.t_peel),
            ("3 解包 cpio", self.t_cpio),
            ("4 切分区段", self.t_split),
            ("5 解包文件系统", self.t_fs),
            ("6 找分区线索", self.t_parts),
            ("7 分段裸包探测", self.t_probe),
            ("一键智能解包", self.t_auto),
        ])
        btns.pack(fill="x", pady=4)
        self.var_peel_follow = tk.BooleanVar(value=True)
        ttk.Checkbutton(p, text="剥层完成后自动载入产物继续扫描",
                        variable=self.var_peel_follow).pack(anchor="w",
                                                            padx=4)

    # ------------------------------------------------- Tab2 NR 备份
    def _build_tab_nr(self, p):
        frm = ttk.LabelFrame(p, text="路径")
        self.var_nr_in = tk.StringVar()
        self.var_nr_out = tk.StringVar()
        self.var_nr_dir = tk.StringVar()
        self._row_path(frm, 0, ".nr 备份文件:", self.var_nr_in,
                       self.nr_browse_in)
        self._row_path(frm, 1, "解包目录/打包源:", self.var_nr_dir,
                       self.nr_browse_dir)
        self._row_path(frm, 2, "输出 .nr (可空):", self.var_nr_out,
                       self.nr_browse_out)
        self.var_nr_in.trace_add("write", self._nr_auto)
        frm.columnconfigure(1, weight=1)
        frm.pack(fill="x")

        opt = ttk.LabelFrame(p, text="一键解锁选项")
        self.var_nr_at = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="同时取消隐藏 AT 指令页 (不改可勾掉; "
                        "SSH+adbd 始终开启)",
                        variable=self.var_nr_at).grid(row=0, column=0,
                                                      sticky="w", padx=6)
        opt.pack(fill="x", pady=4)

        btns = ttk.Frame(p)
        self._btn_grid(btns, [
            ("NR 查看信息+校验", self.t_nr_info),
            ("NR 严格校验 verify", self.t_nr_verify),
            ("NR 解包到目录", self.t_nr_unpack),
            ("目录打包为 .nr", self.t_nr_pack),
            ("★ 一键制作解锁备份", self.t_nr_unlock),
        ])
        btns.pack(fill="x", pady=4)
        ttk.Label(p, foreground="#666",
                  text="流程: 网页[备份/升级]导出 .nr → 点★生成 -unlock.nr "
                  "→ 网页恢复备份上传; 也可解包后手工改 etc/config/* 再打包。"
                  ).pack(anchor="w", padx=4)

    # ------------------------------------------------- Tab3 逆向打包
    def _build_tab_pk(self, p):
        frm = ttk.LabelFrame(p, text="路径")
        self.var_pk_dir = tk.StringVar()
        self.var_pk_file = tk.StringVar()
        self.var_pk_out = tk.StringVar()
        self._row_path(frm, 0, "源目录(归档/镜像):", self.var_pk_dir,
                       self.pk_browse_dir)
        self._row_path(frm, 1, "源文件(压缩包裹):", self.var_pk_file,
                       self.pk_browse_file)
        self._row_path(frm, 2, "输出路径(可空):", self.var_pk_out,
                       self.pk_browse_out)
        self.var_pk_meta = tk.StringVar()
        self._row_path(frm, 3, "fwtool元数据(可空):", self.var_pk_meta,
                       self.pk_browse_meta)
        frm.columnconfigure(1, weight=1)
        frm.pack(fill="x")

        opt = ttk.LabelFrame(p, text="选项")
        ttk.Label(opt, text="压缩格式:").grid(row=0, column=0, sticky="e",
                                              padx=4)
        self.var_pk_comp = tk.StringVar(value="gzip")
        ttk.Combobox(opt, textvariable=self.var_pk_comp, width=8,
                     state="readonly",
                     values=("none", "gzip", "xz", "lzma", "bz2",
                             "zstd")).grid(row=0, column=1, sticky="w")
        ttk.Label(opt, text="JFFS2擦除块:").grid(row=0, column=2, sticky="e",
                                                 padx=4)
        self.var_pk_eb = tk.StringVar(value="0x20000")
        ttk.Entry(opt, textvariable=self.var_pk_eb, width=12).grid(
            row=0, column=3, sticky="w")
        ttk.Label(opt, text="squashfs压缩:").grid(row=0, column=4, sticky="e",
                                                  padx=4)
        self.var_pk_sq = tk.StringVar(value="xz")
        ttk.Combobox(opt, textvariable=self.var_pk_sq, width=8,
                     state="readonly",
                     values=("xz", "gzip", "lzma", "zstd", "lzo")).grid(
            row=0, column=5, sticky="w")
        ttk.Label(opt, text="拼接填充块:").grid(row=1, column=0, sticky="e",
                                               padx=4)
        self.var_pk_pad = tk.StringVar(value="0x20000")
        ttk.Entry(opt, textvariable=self.var_pk_pad, width=12).grid(
            row=1, column=1, sticky="w")
        ttk.Label(opt, text="(0=不填充; 段顺序=选择顺序, 海思用0x20000)"
                  ).grid(row=1, column=2, columnspan=4, sticky="w")
        opt.pack(fill="x", pady=4)

        btns = ttk.Frame(p)
        self._btn_grid(btns, [
            ("目录→cpio (+压缩)", self.t_pk_cpio),
            ("目录→tar (+压缩)", self.t_pk_tar),
            ("文件→压缩包裹", self.t_pk_compress),
            ("目录→JFFS2镜像", self.t_pk_jffs2),
            ("目录→squashfs镜像", self.t_pk_squash),
            ("分区段拼接为整镜像", self.t_pk_join),
            ("★分区→fwtool升级包", self.t_pk_fwtool),
        ])
        btns.pack(fill="x", pady=4)
        ttk.Label(p, foreground="#666",
                  text="逆向对应解包流: cpio(newc,4对齐)→gzip 即 initramfs; "
                  "tar→gzip 即备份/rootfs 流; JFFS2/squashfs 需外部 "
                  "mkfs.jffs2/mksquashfs (一般在 WSL 内执行)。"
                  ).pack(anchor="w", padx=4)
        ttk.Label(p, foreground="#1a5fb4",
                  text="★ fwtool: 源目录选一键解包产出的 partitions 目录"
                  "(11 个分区 bin), 按段表拼内镜像→gzip→追加元数据尾部, "
                  "还原 DD-5G 这种全量升级 .bin; 元数据留空则自动复用解包时"
                  "保存的 metadata.json。"
                  ).pack(anchor="w", padx=4, pady=(2, 0))

    # ------------------------------------------------- 通用
    def _auto_out(self, *_):
        p = self.var_in.get()
        if p and os.path.isfile(p) and not self.var_out.get():
            self.var_out.set(default_outdir(p))

    def browse_in(self):
        p = filedialog.askopenfilename(title="选择固件/镜像文件")
        if p:
            self.var_in.set(p)
            self.var_out.set(default_outdir(p))

    def browse_out(self):
        d = filedialog.askdirectory(title="选择输出目录")
        if d:
            self.var_out.set(d)

    def fill_block(self):
        block = parse_size(self.var_block.get(), 0x20000)
        skip = parse_size(self.var_skip.get(), 0)
        count = parse_size(self.var_count.get(), 0)
        self.var_off.set(hex(skip * block))
        self.var_len.set(hex(count * block) if count else "0")

    def need_io(self):
        p = self.var_in.get().strip().strip('"')
        if not p or not os.path.isfile(p):
            raise ValueError("请先选择存在的固件文件")
        d = self.var_out.get().strip().strip('"') or default_outdir(p)
        return p, d

    # ------------------------------------------------- NR 浏览
    def nr_browse_in(self):
        p = filedialog.askopenfilename(
            title="选择设备导出的 .nr 备份",
            filetypes=[("NR 备份", "*.nr"), ("所有文件", "*.*")])
        if p:
            self.var_nr_in.set(p)

    def _nr_auto(self, *_):
        p = self.var_nr_in.get()
        if not p or not os.path.isfile(p):
            return
        if not self.var_nr_dir.get():
            base = os.path.splitext(p)[0]
            self.var_nr_dir.set(base + "_unpacked")
        if not self.var_nr_out.get():
            self.var_nr_out.set(os.path.splitext(p)[0] + "-unlock.nr")

    def nr_browse_dir(self):
        d = filedialog.askdirectory(title="选择解包目录 / 打包源目录")
        if d:
            self.var_nr_dir.set(d)

    def nr_browse_out(self):
        p = filedialog.asksaveasfilename(
            title="输出 .nr", defaultextension=".nr",
            filetypes=[("NR 备份", "*.nr")])
        if p:
            self.var_nr_out.set(p)

    # ------------------------------------------------- 打包页浏览
    def pk_browse_dir(self):
        d = filedialog.askdirectory(title="选择要打包的源目录")
        if d:
            self.var_pk_dir.set(d)

    def pk_browse_file(self):
        p = filedialog.askopenfilename(title="选择要压缩的文件")
        if p:
            self.var_pk_file.set(p)

    def pk_browse_out(self):
        p = filedialog.asksaveasfilename(title="选择输出文件")
        if p:
            self.var_pk_out.set(p)

    def pk_browse_meta(self):
        p = filedialog.askopenfilename(
            title="选择 fwtool metadata.json (可留空, 默认自动查找)")
        if p:
            self.var_pk_meta.set(p)

    # ------------------------------------------------- 日志/线程
    def log(self, s="", tag=None):
        self.q.put((str(s), tag))

    def clear_log(self):
        self.logw.delete("1.0", "end")

    def save_log(self):
        p = filedialog.asksaveasfilename(title="保存日志",
                                         initialfile="unpack_log.txt")
        if p:
            with open(p, "w", encoding="utf-8") as fp:
                fp.write(self.logw.get("1.0", "end"))
            self.log(f"日志已存: {p}", "ok")

    def start(self, title, fn):
        if self.busy:
            return
        self.busy = True
        self.status.set(title + " …")

        def worker():
            try:
                fn()
                self.q.put(("==== 完成: " + title + " ====\n", "ok"))
            except Exception as e:
                self.q.put((f"[错误] {type(e).__name__}: {e}", "err"))
            finally:
                self.q.put(("__DONE__" + title, None))

        threading.Thread(target=worker, daemon=True).start()

    def _pump(self):
        try:
            while True:
                s, tag = self.q.get_nowait()
                if s.startswith("__DONE__"):
                    self.busy = False
                    self.status.set("就绪: " + s[8:] + " 结束")
                    follow = getattr(self, "_follow_scan", None)
                    if follow:
                        self._follow_scan = None
                        self.var_in.set(follow)
                        self.start("扫描识别(剥层产物)",
                                   lambda: do_scan(follow, log=self.log))
                else:
                    self.logw.insert("end", s + "\n", tag)
                    self.logw.see("end")
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    # ------------------------------------------------- Tab1 任务
    def t_scan(self):
        p, _ = self.need_io()
        self.start("扫描识别", lambda: do_scan(p, log=self.log))

    def t_peel(self):
        p, d = self.need_io()
        off = parse_size(self.var_off.get(), 0)
        out = os.path.join(d, f"peeled_0x{off:X}.bin")

        def job():
            do_peel(p, off, out, "auto", self.log)
            if self.var_peel_follow.get():
                self._follow_scan = out
        self.start("剥压缩层", job)

    def t_probe(self):
        p, _ = self.need_io()
        self.start("分段裸包探测", lambda: do_probe(p, self.log))

    def t_cpio(self):
        p, d = self.need_io()
        target = os.path.join(d, "cpio_root")

        def job():
            data = open(p, "rb").read()
            cpio_extract(data, target, self.log)
            self.log(f"-> {target}", "ok")
        self.start("解包 cpio", job)

    def t_split(self):
        p, d = self.need_io()
        off = parse_size(self.var_off.get(), 0)
        length = parse_size(self.var_len.get(), 0)
        out = os.path.join(d, f"part_0x{off:X}.bin")
        self.start("切分区段",
                   lambda: do_split(p, off, length, out, self.log))

    def t_fs(self):
        p, d = self.need_io()
        target = os.path.join(d, "fs_root")
        self.start("解包文件系统",
                   lambda: (extract_fs(p, target, self.log),
                            self.log(f"-> {target}", "ok")))

    def t_parts(self):
        p, _ = self.need_io()
        self.start("找分区线索", lambda: do_find_partitions(p, log=self.log))

    def t_auto(self):
        p, d = self.need_io()
        self.start("一键智能解包", lambda: do_auto(p, d, self.log))

    # ------------------------------------------------- Tab2 NR 任务
    def _nr_need_in(self):
        p = self.var_nr_in.get().strip().strip('"')
        if not p or not os.path.isfile(p):
            raise ValueError("请先选择存在的 .nr 备份文件")
        return p

    def t_nr_info(self):
        p = self._nr_need_in()
        self.start("NR 查看信息", lambda: nr_info(p, self.log))

    def t_nr_verify(self):
        p = self._nr_need_in()
        self.start("NR 校验", lambda: nr_verify(p, self.log))

    def t_nr_unpack(self):
        p = self._nr_need_in()
        d = self.var_nr_dir.get().strip().strip('"') or None
        self.start("NR 解包",
                   lambda: self.log(f"-> {nr_unpack(p, d, self.log)}", "ok"))

    def t_nr_pack(self):
        d = self.var_nr_dir.get().strip().strip('"')
        if not d or not os.path.isdir(d):
            raise ValueError("请先选择解包后的源目录")
        out = self.var_nr_out.get().strip().strip('"') or (
            os.path.join(os.path.dirname(d.rstrip("/\\")),
                         os.path.basename(d.rstrip("/\\")) + "-repacked.nr"))
        self.start("NR 打包",
                   lambda: self.log(f"-> {nr_pack(d, out, self.log)}", "ok"))

    def t_nr_unlock(self):
        p = self._nr_need_in()
        out = self.var_nr_out.get().strip().strip('"') or None
        at = bool(self.var_nr_at.get())
        self.start("NR 一键解锁",
                   lambda: self.log(f"-> {nr_unlock(p, out, at, self.log)}",
                                    "ok"))

    # ------------------------------------------------- Tab3 打包任务
    def _pk_dir(self):
        d = self.var_pk_dir.get().strip().strip('"')
        if not d or not os.path.isdir(d):
            raise ValueError("请先选择源目录")
        return d

    def _pk_out(self, default_name):
        out = self.var_pk_out.get().strip().strip('"')
        if out:
            return out
        d = self.var_pk_dir.get().strip().strip('"') or os.path.dirname(
            self.var_pk_file.get().strip().strip('"'))
        return os.path.join(d or ".", default_name)

    def t_pk_cpio(self):
        d = self._pk_dir()
        comp = self.var_pk_comp.get()
        suffix = ".cpio" if comp == "none" else ".cpio." + (
            "gz" if comp == "gzip" else comp)
        out = self._pk_out(os.path.basename(d.rstrip("/\\")) + suffix)

        def job():
            do_pack_archive(d, out, "cpio",
                            None if comp == "none" else comp, self.log)
            self.log("提示: 内核 initramfs 需 cpio 外再包 gzip, "
                     "且无 uImage 头时可直接作为 gzip 成员", "warn")
        self.start("打包 cpio", job)

    def t_pk_tar(self):
        d = self._pk_dir()
        comp = self.var_pk_comp.get()
        suffix = ".tar" if comp == "none" else ".tar." + (
            "gz" if comp == "gzip" else comp)
        out = self._pk_out(os.path.basename(d.rstrip("/\\")) + suffix)
        self.start("打包 tar", lambda: do_pack_archive(
            d, out, "tar", None if comp == "none" else comp, self.log))

    def t_pk_compress(self):
        f = self.var_pk_file.get().strip().strip('"')
        if not f or not os.path.isfile(f):
            raise ValueError("请先选择要压缩的源文件")
        comp = self.var_pk_comp.get()
        if comp == "none":
            raise ValueError("压缩格式不能是 none")
        out = self.var_pk_out.get().strip().strip('"') or None
        self.start("压缩包裹",
                   lambda: do_compress_file(f, comp, out, self.log))

    def t_pk_jffs2(self):
        d = self._pk_dir()
        eb = parse_size(self.var_pk_eb.get(), 0x20000)
        out = self._pk_out(os.path.basename(d.rstrip("/\\")) + ".jffs2")
        self.start("制作 JFFS2",
                   lambda: do_mkfs(d, out, "jffs2", eb, None, self.log))

    def t_pk_squash(self):
        d = self._pk_dir()
        out = self._pk_out(os.path.basename(d.rstrip("/\\")) + ".squashfs")
        sq = self.var_pk_sq.get()
        self.start("制作 squashfs",
                   lambda: do_mkfs(d, out, "squashfs", 0, sq, self.log))

    def t_pk_join(self):
        segs = filedialog.askopenfilenames(title="按顺序选择分区段文件")
        if not segs:
            return
        pad = parse_size(self.var_pk_pad.get(), 0)
        out = self.var_pk_out.get().strip().strip('"') or os.path.join(
            os.path.dirname(segs[0]), "joined_fullflash.bin")

        def job():
            for i, s in enumerate(segs):
                self.log(f"  选择[{i}] {s}")
            do_join(list(segs), out, pad, 0xFF, self.log)
        self.start("分区拼接", job)

    def t_pk_fwtool(self):
        d = self._pk_dir()
        parent = os.path.basename(
            os.path.dirname(os.path.abspath(d.rstrip("/\\")))) or "firmware"
        if parent.endswith("_unpack"):
            parent = parent[:-7]
        out = self._pk_out(parent + ".repack.bin")
        meta = self.var_pk_meta.get().strip().strip('"') or None

        def job():
            build_fwtool_package(d, out, meta, log=self.log)
        self.start("打包 fwtool 升级包", job)


# 薄封装, 便于阅读与日后换主题
def ttk_frame(parent, text=None, top=False):
    return ttk.LabelFrame(parent, text=text) if text else ttk.Frame(parent)


def ttk_label(parent, text):
    return ttk.Label(parent, text=text)


def ttk_button(parent, text, cmd, width=None):
    return ttk.Button(parent, text=text, command=cmd, width=width)


def filedialog_open(title):
    return filedialog.askopenfilename(title=title)


def filedialog_save(title, name):
    return filedialog.asksaveasfilename(title=title, initialfile=name,
                                        defaultextension=".txt")


def filedialog_dir():
    return filedialog.askdirectory(title="选择输出目录")


# ================================================================== CLI
def cli_main(argv):
    ap = argparse.ArgumentParser(description="固件解包工具 CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("file")
    s = sub.add_parser("peel"); s.add_argument("file")
    s.add_argument("-o", "--out"); s.add_argument("--offset", default="0")
    s = sub.add_parser("cpio"); s.add_argument("file")
    s.add_argument("-o", "--out", required=True)
    s = sub.add_parser("split"); s.add_argument("file")
    s.add_argument("--offset", default="0"); s.add_argument("--length",
                                                            default="0")
    s.add_argument("-o", "--out", required=True)
    s = sub.add_parser("fs"); s.add_argument("file")
    s.add_argument("-o", "--out", required=True)
    s = sub.add_parser("parts"); s.add_argument("file")
    s = sub.add_parser("probe"); s.add_argument("file")
    s = sub.add_parser("auto"); s.add_argument("file")
    s.add_argument("-o", "--out")
    # ---- NR .nr ----
    s = sub.add_parser("nr-info"); s.add_argument("nr")
    s = sub.add_parser("nr-verify"); s.add_argument("nr")
    s = sub.add_parser("nr-unpack"); s.add_argument("nr")
    s.add_argument("-d", "--dir")
    s = sub.add_parser("nr-pack"); s.add_argument("dir")
    s.add_argument("-o", "--out", required=True)
    s = sub.add_parser("nr-unlock"); s.add_argument("nr")
    s.add_argument("-o", "--out"); s.add_argument("--no-at",
                                                 action="store_true")
    # ---- 逆向打包 ----
    s = sub.add_parser("pack-cpio"); s.add_argument("dir")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--compress", default="none",
                   choices=["none", "gzip", "xz", "lzma", "bz2", "zstd"])
    s = sub.add_parser("pack-tar"); s.add_argument("dir")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--compress", default="none",
                   choices=["none", "gzip", "xz", "lzma", "bz2", "zstd"])
    s = sub.add_parser("compress"); s.add_argument("file")
    s.add_argument("--format", required=True,
                   choices=["gzip", "xz", "lzma", "bz2", "zstd"])
    s.add_argument("-o", "--out")
    s = sub.add_parser("mkfs"); s.add_argument("dir")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--fs", required=True, choices=["jffs2", "squashfs"])
    s.add_argument("--eraseblock", default="0x20000")
    s.add_argument("--squash-comp", default="xz")
    s = sub.add_parser("join")
    s.add_argument("segments", nargs="+")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--pad-block", default="0")
    s = sub.add_parser("pack-fwtool", help="partitions 目录 -> fwtool 全量升级包")
    s.add_argument("partitions", help="一键解包产出的 partitions 目录")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--metadata", help="metadata.json (默认自动查找/内置)")
    s.add_argument("--layout", default="moses",
                   choices=sorted(FWTOOL_LAYOUTS))
    s.add_argument("--level", type=int, default=9)
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        do_scan(a.file)
    elif a.cmd == "peel":
        out = a.out or os.path.join(default_outdir(a.file), "peeled.bin")
        do_peel(a.file, parse_size(a.offset, 0), out)
    elif a.cmd == "cpio":
        cpio_extract(open(a.file, "rb").read(), a.out)
    elif a.cmd == "split":
        do_split(a.file, parse_size(a.offset, 0),
                 parse_size(a.length, 0), a.out)
    elif a.cmd == "fs":
        extract_fs(a.file, a.out)
    elif a.cmd == "parts":
        do_find_partitions(a.file)
    elif a.cmd == "probe":
        do_probe(a.file)
    elif a.cmd == "auto":
        do_auto(a.file, a.out or default_outdir(a.file))
    elif a.cmd == "nr-info":
        nr_info(a.nr)
    elif a.cmd == "nr-verify":
        nr_verify(a.nr)
    elif a.cmd == "nr-unpack":
        nr_unpack(a.nr, a.dir)
    elif a.cmd == "nr-pack":
        nr_pack(a.dir, a.out)
    elif a.cmd == "nr-unlock":
        nr_unlock(a.nr, a.out, at=not a.no_at)
    elif a.cmd == "pack-cpio":
        do_pack_archive(a.dir, a.out, "cpio",
                        None if a.compress == "none" else a.compress)
    elif a.cmd == "pack-tar":
        do_pack_archive(a.dir, a.out, "tar",
                        None if a.compress == "none" else a.compress)
    elif a.cmd == "compress":
        do_compress_file(a.file, a.format, a.out)
    elif a.cmd == "mkfs":
        do_mkfs(a.dir, a.out, a.fs, parse_size(a.eraseblock, 0x20000),
                a.squash_comp)
    elif a.cmd == "join":
        do_join(a.segments, a.out, parse_size(a.pad_block, 0))
    elif a.cmd == "pack-fwtool":
        build_fwtool_package(a.partitions, a.out, a.metadata,
                             layout=a.layout, level=a.level)


def gui_main():
    if tk is None:
        print("当前 Python 无 tkinter, 请使用 --cli 模式")
        return 1
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        try:
            cli_main(sys.argv[2:])
        except (ValueError, NrError, FileNotFoundError) as e:
            print(f"错误: {e}")
            sys.exit(1)
    else:
        sys.exit(gui_main())

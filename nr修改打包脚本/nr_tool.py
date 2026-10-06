#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================
 NRadio DD-5G (WT2967 / Hi6352) .nr 配置备份 一键修改与打包工具
================================================================
适用固件: 2.1.11 / 2.2.15 (OpenWrt, BusyBox 1.35)

.nr 文件结构 (逆向 /sbin/sysupgrade 与设备实测确认):
    偏移 0      : 1 字节 0x00
    偏移 1      : 一行 ASCII 头部, 以 \\n 结束:
                  "name=- size=<gz字节数> crc=<MD5> type=config"
    偏移 52/68..: 完整 gzip(tar) 数据 (gzip mtime=0)
    crc = MD5( b"nradio_security_akxo1f\\n" + gzip数据 )     <- 硬编码盐
    恢复命令   : sysupgrade --valid-tag --restore-backup <file>
    恢复时设备会丢弃包内 etc/config/firewall 与 etc/config/adbd,
    故注入点必须在开机阶段重建配置, 本工具提供两种注入方式:
      uci (默认): 写 etc/uci-defaults/99-nr-unlock —— 下次开机
                  /etc/init.d/boot 会 source 执行, 成功后系统自动删除;
      rc        : 写 etc/rc.local —— 开机流程末尾执行一次,
                  uci commit + 立即 reload/start 服务, 随后 sed 自删除注入块。

用法:
  无参数直接双击运行 : 启动图形界面 (四个页签: 一键解锁 / 信息校验 / 解包 / 打包)
子命令 (命令行/批处理):
  info    <in.nr>                       查看头部 / 校验 crc / 列内容
  verify  <in.nr>                       严格校验 (头/crc/tar)
  unpack  <in.nr> [-d 目录]             解包到目录 (默认 <同名>_unpacked)
  pack    <目录> -o <out.nr>            从目录重新打包
  unlock  <in.nr> [-o out.nr] [--no-at] [--method uci|rc]
               一键: 解包→注入开机解锁脚本→重打包
               --method uci (默认): etc/uci-defaults 一次性脚本 (SSH+ADB+可选AT页)
               --method rc        : etc/rc.local 开机末尾一次性脚本 (仅 SSH+ADB, 自删除)
  menu                                  中文文本交互菜单 (供旧批处理调用)
================================================================
"""
import argparse
import gzip
import hashlib
import io
import os
import re
import stat
import sys
import tarfile
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

KEY_DATA = b"nradio_security_akxo1f"
UNLOCK_SCRIPT = "etc/uci-defaults/99-nr-unlock"
GZIP_OS_UNIX = 0x03

# ---------------------------------------------------------------- 头部解析
class NrError(Exception):
    pass


def split_nr(data: bytes):
    """返回 (head_text_without_nul_nl, gzip_bytes)。第一行 0x00 开头。"""
    if not data or data[0] != 0x00:
        raise NrError("不是合法 .nr 文件 (首字节应为 0x00)")
    nl = data.find(b"\n")
    if nl < 0:
        raise NrError("找不到头部换行符")
    head = data[1:nl]
    gz = data[nl + 1:]
    return head, gz


def parse_head(head: bytes):
    fields = {}
    for tok in head.split(b" "):
        if b"=" in tok:
            k, v = tok.split(b"=", 1)
            fields[k.decode()] = v.decode()
    for k in ("name", "size", "crc", "type"):
        if k not in fields:
            raise NrError(f"头部缺字段 {k}: {head!r}")
    return fields


def calc_crc(gz: bytes) -> str:
    # 设备: sed "1i nradio_security_akxo1f" payload | md5sum
    return hashlib.md5(KEY_DATA + b"\n" + gz).hexdigest()


def make_gzip(tar_bytes: bytes) -> bytes:
    """设备风格 gzip: mtime=0, XFL=0, OS=Unix(3), 压缩级别 6。"""
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=6,
                       fileobj=buf, mtime=0) as gf:
        gf.write(tar_bytes)
    out = bytearray(buf.getvalue())
    out[9] = GZIP_OS_UNIX          # OS 字段, 仅仿真, 不影响解压
    return bytes(out)


# ---------------------------------------------------------------- 读 .nr
def read_nr(path):
    data = open(path, "rb").read()
    head, gz = split_nr(data)
    fields = parse_head(head)
    real_crc = calc_crc(gz)
    ok_size = int(fields["size"]) == len(gz)
    ok_crc = fields["crc"] == real_crc
    try:
        tar_bytes = gzip.decompress(gz)
        tf = tarfile.open(fileobj=io.BytesIO(tar_bytes))
        members = tf.getmembers()
        tf.close()
        tar_ok = True
    except Exception as e:
        members, tar_ok, tar_bytes = [], False, b""
    return {
        "fields": fields, "gz": gz, "tar": tar_bytes,
        "members": members, "tar_ok": tar_ok,
        "ok_size": ok_size, "ok_crc": ok_crc, "real_crc": real_crc,
    }


def cmd_info(a):
    r = read_nr(a.infile)
    f = r["fields"]
    print(f"文件        : {a.infile}")
    print(f"name        : {f['name']}")
    print(f"type        : {f['type']}")
    print(f"size 声称    : {f['size']}   实际 gzip: {len(r['gz'])}   "
          f"{'OK' if r['ok_size'] else 'MISMATCH'}")
    print(f"crc  声称    : {f['crc']}")
    print(f"crc  实算    : {r['real_crc']}   "
          f"{'OK (签名/盐校验通过)' if r['ok_crc'] else 'MISMATCH'}")
    print(f"tar 完整性   : {'OK' if r['tar_ok'] else '损坏'}")
    print(f"包内文件数   : {len(r['members'])}")
    for m in r["members"]:
        kind = "d" if m.isdir() else ("l" if m.issym() else "f")
        print(f"  [{kind}] {oct(m.mode)[2:]:>4} {m.size:6d}  {m.name}")


def cmd_verify(a):
    r = read_nr(a.infile)
    bad = []
    if not r["ok_size"]: bad.append("size 字段不匹配")
    if not r["ok_crc"]:  bad.append("crc 不匹配 (文件被修改后未用本工具重打包?)")
    if not r["tar_ok"]:  bad.append("tar/gzip 损坏")
    if bad:
        for x in bad: print("FAIL:", x)
        sys.exit(1)
    print("PASS: 头部 / crc(盐 nradio_security_akxo1f) / tar 全部合法, "
          "设备 sysupgrade --valid-tag 可接受")


# ---------------------------------------------------------------- 解包
def cmd_unpack(a):
    r = read_nr(a.infile)
    if not r["tar_ok"]:
        raise NrError("tar 损坏, 拒绝解包")
    outdir = a.dir
    if not outdir:
        base = os.path.splitext(os.path.basename(a.infile))[0]
        outdir = os.path.join(os.path.dirname(os.path.abspath(a.infile)),
                              base + "_unpacked")
    tf = tarfile.open(fileobj=io.BytesIO(r["tar"]))
    if os.path.isdir(outdir) and os.listdir(outdir):
        raise NrError(f"目录非空, 请换空目录: {outdir}")
    tf.extractall(outdir, filter="data")
    print(f"已解包 {len(r['members'])} 个文件 -> {outdir}")
    print("可直接修改其中文件; 完成后用 pack 子命令重新打包。")


# ---------------------------------------------------------------- 打包
EXEC_HINTS = ("/etc/uci-defaults/", "/etc/init.d/", "/etc/rc.common",
              "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")


def is_exec_path(rel: str) -> bool:
    if "/init.d/" in "/" + rel or rel.startswith("etc/uci-defaults/"):
        return True
    if rel in ("etc/rc.local",):
        return True
    return rel.endswith(".sh") and any(("/" + rel).startswith(h.rstrip("/"))
                                       for h in ("/bin", "/sbin", "/usr/bin",
                                                 "/usr/sbin"))


def build_tar(srcdir: str) -> bytes:
    """复刻设备 tar: 仅文件/符号链接, 相对 POSIX 路径, root:root。"""
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
    srcdir = os.path.abspath(srcdir)
    for root, dirs, files in os.walk(srcdir):
        dirs.sort(); files.sort()
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, srcdir).replace(os.sep, "/")
            if rel.startswith("./"):
                rel = rel[2:]
            if os.path.islink(full):
                ti = tarfile.TarInfo(rel)
                ti.type = tarfile.SYMTYPE
                ti.linkname = os.readlink(full)
                ti.mode = 0o777
            else:
                st = os.stat(full)
                ti = tarfile.TarInfo(rel)
                ti.size = st.st_size
                ti.mode = 0o755 if is_exec_path(rel) else 0o644
                ti.mtime = int(st.st_mtime)
                with open(full, "rb") as fp:
                    tf.addfile(ti, fp)
                continue
            ti.mtime = 0
            ti.uid = ti.gid = 0
            tf.addfile(ti)
    tf.close()
    return buf.getvalue()


def write_nr(tar_bytes: bytes, outpath: str) -> None:
    gz = make_gzip(tar_bytes)
    crc = calc_crc(gz)
    head = (f"name=- size={len(gz)} crc={crc} type=config\n").encode()
    tmp = outpath + ".tmp"
    with open(tmp, "wb") as fp:
        fp.write(b"\x00" + head + gz)
    os.replace(tmp, outpath)


def cmd_pack(a):
    if not os.path.isdir(a.srcdir):
        raise NrError(f"不是目录: {a.srcdir}")
    tar_bytes = build_tar(a.srcdir)
    write_nr(tar_bytes, a.outfile)
    gz_len = len(make_gzip(tar_bytes))
    print(f"已打包 -> {a.outfile}  (gzip {gz_len} 字节)")
    print("已用设备盐值重算 crc, 可直接在网页[备份/升级]-[恢复备份]上传。")


# ---------------------------------------------------------------- 一键解锁
UNLOCK_SH = """#!/bin/sh
# Injected by nr_tool.py — runs once on next boot via /etc/uci-defaults
# (sourced by /etc/init.d/boot, deleted automatically after success).

# 1) 开启 SSH: 与隐藏安全页等价, 把 firewall 中名为 ssh 的规则置为 ACCEPT
uci -q delete firewall.ssh
uci set firewall.ssh=rule
uci set firewall.ssh.name='Allow-SSH'
uci set firewall.ssh.src='lan'
uci set firewall.ssh.family='ipv4'
uci set firewall.ssh.proto='tcp'
uci set firewall.ssh.dest_port='22'
uci set firewall.ssh.target='ACCEPT'

# 2) 开启 adbd (恢复逻辑会丢弃包内 adbd 配置, 只能在此设置)
uci set adbd.service.enable='1'

# 3) 显示隐藏 AT 指令页 (仅当出厂 oem 标记为 odm 时; 密码仍为 admin@0515)
if [ "$(uci -q get oem.custom.com)" = "odm" ]; then
	uci set oem.custom.com=' '
fi

exit 0
"""


def inject_unlock(srcdir: str, at: bool):
    p = os.path.join(srcdir, *UNLOCK_SCRIPT.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    body = UNLOCK_SH if at else UNLOCK_SH.replace(
        "# 3) 显示隐藏 AT 指令页 (仅当出厂 oem 标记为 odm 时; 密码仍为 admin@0515)\n"
        "if [ \"$(uci -q get oem.custom.com)\" = \"odm\" ]; then\n"
        "\tuci set oem.custom.com=' '\n"
        "fi\n\n", "")
    with open(p, "w", newline="\n", encoding="utf-8") as fp:
        fp.write(body)
    return p


# ---------------------------------------------------------------- 方式二: rc.local 注入
RCLOCAL_PATH = "etc/rc.local"
RC_BEGIN = "# >>> nr-tool-unlock-begin >>>"
RC_END = "# <<< nr-tool-unlock-end <<<"

# rc.local 在开机流程末尾由 procd 执行; 恢复备份时 firewall/adbd 配置会被丢弃,
# 但 rc.local 在其后运行, 因此可在此重建设置。uci-defaults 由系统自动删除,
# rc.local 不会, 故块内最后一条命令用 sed 把整个注入块自删除, 实现"一次性"。
RC_BLOCK = """\
# >>> nr-tool-unlock-begin >>>
# Injected by nr_tool.py — runs once at end of next boot, then removes itself.
{
\tuci -q delete firewall.ssh
\tuci set firewall.ssh=rule
\tuci set firewall.ssh.name='Allow-SSH'
\tuci set firewall.ssh.src='lan'
\tuci set firewall.ssh.family='ipv4'
\tuci set firewall.ssh.proto='tcp'
\tuci set firewall.ssh.dest_port='22'
\tuci set firewall.ssh.target='ACCEPT'
\tuci set adbd.service.enable='1'
\tuci commit firewall
\tuci commit adbd
\t/etc/init.d/firewall reload >/dev/null 2>&1 || /etc/init.d/firewall restart >/dev/null 2>&1
\t/etc/init.d/adbd start >/dev/null 2>&1 || /etc/init.d/adbd restart >/dev/null 2>&1
\tsed -i '/nr-tool-unlock-begin/,/nr-tool-unlock-end/d' /etc/rc.local
}
# <<< nr-tool-unlock-end <<<
"""

_RE_RC_BLOCK = re.compile(
    r"^[ \t]*# >>> nr-tool-unlock-begin >>>.*?# <<< nr-tool-unlock-end <<<[ \t]*\r?\n?",
    re.DOTALL | re.MULTILINE)
_RE_EXIT0 = re.compile(r"^[ \t]*exit[ \t]+0[ \t]*$", re.MULTILINE)


def rclocal_embed(text: str) -> str:
    """把一次性解锁块嵌入 rc.local 文本: 幂等去重、插到 exit 0 之前、保证 shebang。"""
    text = _RE_RC_BLOCK.sub("", text or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    block = RC_BLOCK if text.endswith("\n") else "\n" + RC_BLOCK
    m = None
    for m in _RE_EXIT0.finditer(text):
        pass
    if m:
        text = text[:m.start()] + block + text[m.start():]
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        text += block + "exit 0\n"
    if not text.startswith("#!"):
        text = "#!/bin/sh\n" + text
    return text


def inject_rc_local(srcdir: str):
    p = os.path.join(srcdir, *RCLOCAL_PATH.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    content = ""
    if os.path.isfile(p):
        with open(p, "r", encoding="utf-8", errors="replace") as fp:
            content = fp.read()
    with open(p, "w", newline="\n", encoding="utf-8") as fp:
        fp.write(rclocal_embed(content))
    return p


def cmd_unlock(a):
    import shutil
    import tempfile
    method = getattr(a, "method", None) or "uci"
    if method not in ("uci", "rc"):
        raise NrError(f"未知注入方式: {method}（可选 uci / rc）")
    r = read_nr(a.infile)
    if not r["tar_ok"]:
        raise NrError("源备份损坏")
    work = tempfile.mkdtemp(prefix="nr_unlock_")
    try:
        tarfile.open(fileobj=io.BytesIO(r["tar"])).extractall(work,
                                                              filter="data")
        out = a.outfile or os.path.join(
            os.path.dirname(os.path.abspath(a.infile)) or ".",
            os.path.splitext(os.path.basename(a.infile))[0] + "-unlock.nr")
        print("=" * 60)
        if method == "rc":
            injected = inject_rc_local(work)
            write_nr(build_tar(work), out)
            print("一键解锁备份已生成 (rc.local 注入方式):")
            print("  " + out)
            print("注入文件: " + RCLOCAL_PATH + "  (权限 0755)")
            print("开机效果: 1. 开启 LAN 侧 SSH (dropbear, 端口22, root/admin)")
            print("          2. 开启 adbd (uci commit 后立即生效)")
            print("          3. 注入块仅在开机末尾执行一次, 随后 sed 自删除")
        else:
            injected = inject_unlock(work, at=not a.no_at)
            write_nr(build_tar(work), out)
            print("一键解锁备份已生成 (uci-defaults 注入方式):")
            print("  " + out)
            print("注入脚本: " + UNLOCK_SCRIPT)
            print("开机效果: 1. 开启 LAN 侧 SSH (dropbear, 端口22, root/admin)")
            print("          2. 开启 adbd")
            if not a.no_at:
                print("          3. 取消隐藏 AT 指令页 (二次密码 admin@0515)")
            print("          脚本由 /etc/init.d/boot 执行, 成功后系统自动删除")
        print("上传位置: 网页 [备份/升级] -> [恢复备份] 选择该文件,")
        print("          设备校验 crc 通过后自动重启。")
        print("=" * 60)
        return out
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------- 交互菜单
def ask(prompt, default=None):
    s = input(prompt).strip().strip('"').strip("'")
    return s or default


def menu():
    print("=" * 64)
    print("        NRadio DD-5G  .nr 备份 一键修改/打包工具")
    print("=" * 64)
    while True:
        print("""
  1 - 一键制作解锁备份 (开 SSH + adbd)
  2 - 解包 .nr 到文件夹 (手工修改后再用 3 打包)
  3 - 把文件夹重新打包成 .nr (自动签名/算 crc)
  4 - 查看 .nr 信息并校验
  0 - 退出""")
        c = ask("请选择: ", "0")
        try:
            if c == "1":
                src = ask("拖入或输入设备导出的 .nr 备份路径: ")
                if src and os.path.isfile(src):
                    print("  注入方式: 1=uci-defaults (默认, 含 AT 页开关)")
                    print("            2=rc.local 开机一次性脚本 (仅 SSH+ADB)")
                    m = ask("  请选择 [1]: ", "1")
                    ns = type("A", (), {})()
                    ns.infile, ns.outfile, ns.no_at = src, None, False
                    ns.method = "rc" if m == "2" else "uci"
                    cmd_unlock(ns)
                else:
                    print("文件不存在")
            elif c == "2":
                src = ask("拖入或输入 .nr 文件路径: ")
                if src and os.path.isfile(src):
                    ns = type("A", (), {})()
                    ns.infile, ns.dir = src, None
                    cmd_unpack(ns)
            elif c == "3":
                d = ask("拖入或输入解包后的文件夹路径: ")
                if d and os.path.isdir(d):
                    out = os.path.join(os.path.dirname(d.rstrip("/\\")),
                                       os.path.basename(d.rstrip("/\\")
                                                       ) + "-repacked.nr")
                    ns = type("A", (), {})()
                    ns.srcdir, ns.outfile = d, out
                    cmd_pack(ns)
            elif c == "4":
                src = ask("拖入或输入 .nr 文件路径: ")
                if src and os.path.isfile(src):
                    ns = type("A", (), {})()
                    ns.infile = src
                    cmd_info(ns)
            elif c == "0":
                return
            else:
                print("无效选择")
        except NrError as e:
            print("错误:", e)
        except KeyboardInterrupt:
            print()
        if c in ("1", "2", "3", "4"):
            input("\n回车返回菜单...")


# ---------------------------------------------------------------- 图形界面
def gui_main():
    import contextlib
    import queue
    import threading
    import traceback
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText

    NR_TYPES = [("NR 备份", "*.nr"), ("所有文件", "*.*")]

    class _QStream:
        """把 print 输出按行送到 GUI 日志队列。"""
        def __init__(self, q, sink=None):
            self.q = q
            self.sink = sink

        def write(self, s):
            if self.sink is not None:
                self.sink.write(s)
            for line in str(s).splitlines():
                self.q.put(("log", line))

        def flush(self):
            if self.sink is not None:
                self.sink.flush()

    class App:
        def __init__(self, root):
            self.root = root
            self.q = queue.Queue()
            self.busy = False
            self.action_btns = []
            root.title("NRadio DD-5G  .nr 备份 图形化修改/打包工具")
            root.geometry("880x720")
            root.minsize(780, 620)

            nb = ttk.Notebook(root)
            nb.pack(fill="x", expand=False, padx=10, pady=(10, 4))
            self._tab_unlock(nb)
            self._tab_info(nb)
            self._tab_unpack(nb)
            self._tab_pack(nb)

            lf = ttk.LabelFrame(root, text="运行日志")
            lf.pack(fill="both", expand=True, padx=10, pady=4)
            self.log = ScrolledText(lf, height=10, wrap="word",
                                    font=("Consolas", 9))
            self.log.pack(fill="both", expand=True, padx=6, pady=6)
            self.log.tag_config("err", foreground="#c00000")
            self.log.tag_config("ok", foreground="#0a7d28")
            self.log.configure(state="disabled")

            self.status = ttk.Label(root, text="就绪", anchor="w")
            self.status.pack(fill="x", padx=12, pady=(0, 6))
            self.root.after(100, self._poll)
            self._log("提示：双击本程序直接进入图形界面；命令行用法见源码文件头注释。")

        # ------------------------------------------------------------ 各页签
        def _row(self, parent, row, label, var, picker=None, w=62):
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w",
                                               padx=(8, 4), pady=6)
            e = ttk.Entry(parent, textvariable=var, width=w)
            e.grid(row=row, column=1, sticky="ew", padx=4, pady=6)
            if picker:
                b = ttk.Button(parent, text="浏览…", width=8, command=picker)
                b.grid(row=row, column=2, padx=(4, 8), pady=6)
            parent.columnconfigure(1, weight=1)
            return e

        def _action_btn(self, parent, text, fn):
            b = ttk.Button(parent, text=text, command=fn)
            self.action_btns.append(b)
            return b

        def _tab_unlock(self, nb):
            f = ttk.Frame(nb)
            nb.add(f, text=" ① 一键解锁（开 SSH/adbd） ")
            self.un_src = tk.StringVar()
            self.un_out = tk.StringVar()
            self.un_at = tk.BooleanVar(value=True)
            self.un_method = tk.StringVar(value="uci")
            self._row(f, 0, ".nr 备份文件：", self.un_src,
                      lambda: self._pick_nr(self.un_src))
            self._row(f, 1, "输出文件（可空）：", self.un_out,
                      lambda: self._save_nr(self.un_out, self.un_src.get()))

            mf = ttk.LabelFrame(f, text="注入方式（二选一，均为开机执行一次）")
            mf.grid(row=2, column=0, columnspan=3, sticky="ew", padx=10,
                    pady=(6, 2))
            ttk.Radiobutton(
                mf, variable=self.un_method, value="uci",
                text="方式一 uci-defaults（推荐）：写 etc/uci-defaults/99-nr-unlock，"
                     "开机由系统执行，成功后自动删除"
            ).grid(row=0, column=0, sticky="w", padx=10, pady=(6, 2))
            ttk.Radiobutton(
                mf, variable=self.un_method, value="rc",
                text="方式二 rc.local：写入 etc/rc.local，在开机流程末尾执行一次，"
                     "uci commit 后立即生效，随后自动移除注入块（仅 SSH + adbd）"
            ).grid(row=1, column=0, sticky="w", padx=10, pady=2)

            self.at_cb = ttk.Checkbutton(
                f, variable=self.un_at,
                text="方式一可用：同时取消隐藏 AT 指令页"
                     "（仅出厂 oem 标记为 odm 的设备生效；该页二次密码 admin@0515）")
            self.at_cb.grid(row=3, column=0, columnspan=3, sticky="w",
                            padx=14, pady=(4, 2))
            self.un_method.trace_add("write", self._un_method_changed)

            self._action_btn(f, "★ 一键制作解锁备份", self.do_unlock
                             ).grid(row=4, column=0, columnspan=3, pady=8)
            tip = ttk.LabelFrame(f, text="生成后怎么用")
            tip.grid(row=5, column=0, columnspan=3, sticky="ew", padx=10,
                     pady=(8, 10))
            ttk.Label(tip, justify="left", text=(
                "1. 设备网页 [备份/升级] → [恢复备份] 上传生成的 -unlock.nr；\n"
                "2. 设备校验 crc 通过后自动重启，注入内容仅在首次开机执行一次后自动清除；\n"
                "3. 生效后：LAN 侧 SSH（dropbear 22 端口，root/admin）、adbd 开启；"
                "方式一勾选时同时显示 AT 指令页。\n"
                "注意：开放 SSH 后请仅在可信网络使用，并及时改密。"),
                foreground="#444").pack(anchor="w", padx=10, pady=8)

        def _un_method_changed(self, *_):
            self.at_cb.configure(
                state="normal" if self.un_method.get() == "uci"
                else "disabled")

        def _tab_info(self, nb):
            f = ttk.Frame(nb)
            nb.add(f, text=" ② 查看信息 / 严格校验 ")
            self.info_src = tk.StringVar()
            self._row(f, 0, ".nr 备份文件：", self.info_src,
                      lambda: self._pick_nr(self.info_src))
            bar = ttk.Frame(f)
            bar.grid(row=1, column=0, columnspan=3, pady=6)
            self._action_btn(bar, "查看信息", self.do_info
                             ).pack(side="left", padx=8)
            self._action_btn(bar, "严格校验 verify", self.do_verify
                             ).pack(side="left", padx=8)
            self.info_res = ScrolledText(f, height=20, wrap="word",
                                         font=("Consolas", 9))
            self.info_res.grid(row=2, column=0, columnspan=3, sticky="nsew",
                               padx=10, pady=(4, 10))
            f.rowconfigure(2, weight=1)

        def _tab_unpack(self, nb):
            f = ttk.Frame(nb)
            nb.add(f, text=" ③ 解包 .nr ")
            self.up_src = tk.StringVar()
            self.up_dir = tk.StringVar()
            self._row(f, 0, ".nr 备份文件：", self.up_src,
                      lambda: self._pick_nr(self.up_src))
            self._row(f, 1, "解包到目录（可空）：", self.up_dir,
                      self._pick_unpack_dir)
            self._action_btn(f, "解包", self.do_unpack
                             ).grid(row=2, column=0, columnspan=3, pady=8)
            ttk.Label(f, justify="left",
                      text="留空时解到备份同目录的 <备份名>_unpacked；目标目录必须不存在或为空。\n"
                           "解包后可手工修改文件，再到「④ 打包」页重新生成 .nr。",
                      foreground="#444").grid(row=3, column=0, columnspan=3,
                                              sticky="w", padx=12, pady=6)

        def _tab_pack(self, nb):
            f = ttk.Frame(nb)
            nb.add(f, text=" ④ 目录重新打包 ")
            self.pk_dir = tk.StringVar()
            self.pk_out = tk.StringVar()
            self._row(f, 0, "解包后的目录：", self.pk_dir,
                      self._pick_pack_srcdir)
            self._row(f, 1, "输出 .nr 文件：", self.pk_out,
                      lambda: self._save_nr(self.pk_out, self.pk_dir.get(),
                                            is_dir=True))
            self._action_btn(f, "打包为 .nr（自动算 crc）", self.do_pack
                             ).grid(row=2, column=0, columnspan=3, pady=8)
            ttk.Label(f, justify="left",
                      text="按设备风格重打：gzip(tar)、mtime=0、root:root，并用盐 nradio_security_akxo1f 重算 MD5 crc，\n"
                           "产物可直接在网页 [备份/升级] → [恢复备份] 上传。",
                      foreground="#444").grid(row=3, column=0, columnspan=3,
                                              sticky="w", padx=12, pady=6)

        # ------------------------------------------------------------ 文件选择
        def _pick_nr(self, var):
            p = filedialog.askopenfilename(title="选择 .nr 备份",
                                           filetypes=NR_TYPES)
            if p:
                var.set(p)

        def _save_nr(self, var, src, is_dir=False):
            if is_dir and src:
                base = os.path.basename(src.rstrip("/\\")) or "backup"
                ini = base + "-repacked.nr"
            elif src:
                ini = os.path.splitext(os.path.basename(src))[0] + "-unlock.nr"
            else:
                ini = "backup.nr"
            d = os.path.dirname(src) if src else None
            p = filedialog.asksaveasfilename(
                title="选择输出 .nr", initialdir=d, initialfile=ini,
                defaultextension=".nr", filetypes=NR_TYPES)
            if p:
                var.set(p)

        def _pick_unpack_dir(self):
            p = filedialog.askdirectory(title="选择解包目标目录（留空可用默认路径）")
            if p:
                self.up_dir.set(p)

        def _pick_pack_srcdir(self):
            p = filedialog.askdirectory(title="选择解包后的文件目录")
            if p:
                self.pk_dir.set(p)
                if not self.pk_out.get().strip():
                    self.pk_out.set(os.path.join(
                        os.path.dirname(p.rstrip("/\\")),
                        os.path.basename(p.rstrip("/\\")) + "-repacked.nr"))

        # ------------------------------------------------------------ 日志/线程
        def _log(self, s, tag=None):
            self.log.configure(state="normal")
            self.log.insert("end", str(s) + "\n",
                            (tag,) if tag else ())
            self.log.see("end")
            self.log.configure(state="disabled")

        def _poll(self):
            try:
                while True:
                    kind, payload = self.q.get_nowait()
                    if kind == "log":
                        self._log(payload)
                    elif kind == "err":
                        self._log(payload, "err")
                    elif kind == "done":
                        self._on_done(*payload)
            except queue.Empty:
                pass
            self.root.after(100, self._poll)

        def _run(self, title, fn, open_picker=False, silent_ok=False):
            if self.busy:
                return
            self.busy = True
            self.status.config(text=title + " … 运行中")
            for b in self.action_btns:
                b.state(["disabled"])

            def work():
                open_path = None
                extra = None
                ok = True
                try:
                    with contextlib.redirect_stdout(_QStream(self.q)):
                        open_path, extra = fn()
                except SystemExit as e:
                    ok = (e.code == 0)
                    if not ok:
                        self.q.put(("err", "命令返回非零退出码（通常为校验未通过）"))
                except NrError as e:
                    ok = False
                    self.q.put(("err", "错误: " + str(e)))
                except Exception:
                    ok = False
                    self.q.put(("err", traceback.format_exc()))
                self.q.put(("done", (ok, title, open_path, extra,
                                     open_picker, silent_ok)))

            threading.Thread(target=work, daemon=True).start()

        def _on_done(self, ok, title, open_path, extra, open_picker,
                     silent_ok):
            self.busy = False
            for b in self.action_btns:
                b.state(["!disabled"])
            self.status.config(text=title + (" — 完成" if ok else " — 失败"))
            if ok:
                self._log("[完成] " + title, "ok")
            if extra is not None:
                self.info_res.configure(state="normal")
                self.info_res.delete("1.0", "end")
                self.info_res.insert("1.0", extra)
                self.info_res.configure(state="disabled")
            if not ok:
                messagebox.showerror(title, "操作失败，详见日志区红色信息。")
                return
            if silent_ok:
                return
            if open_path and messagebox.askyesno(
                    title, "已生成：\n" + open_path + "\n\n是否打开所在目录？"):
                try:
                    target = (os.path.dirname(open_path)
                              if os.path.isfile(open_path) else open_path)
                    os.startfile(target)
                except Exception:
                    pass

        # ------------------------------------------------------------ 四个动作
        def do_unlock(self):
            src = self.un_src.get().strip()
            if not os.path.isfile(src):
                messagebox.showwarning("提示", "请先选择存在的 .nr 备份文件。")
                return
            out = self.un_out.get().strip() or None
            method = self.un_method.get()
            ns = type("A", (), {})()
            ns.infile, ns.outfile, ns.no_at = src, out, not self.un_at.get()
            ns.method = method
            real_out = out or os.path.join(
                os.path.dirname(os.path.abspath(src)),
                os.path.splitext(os.path.basename(src))[0] + "-unlock.nr")

            def fn():
                cmd_unlock(ns)
                return real_out, None

            self._run("一键制作解锁备份（" +
                      ("rc.local 注入" if method == "rc"
                       else "uci-defaults 注入") + "）", fn)

        def do_info(self):
            src = self.info_src.get().strip()
            if not os.path.isfile(src):
                messagebox.showwarning("提示", "请先选择存在的 .nr 备份文件。")
                return
            ns = type("A", (), {})()
            ns.infile = src
            sink = io.StringIO()

            def fn():
                with contextlib.redirect_stdout(_QStream(self.q, sink)):
                    cmd_info(ns)
                return None, sink.getvalue()

            self._run("查看信息", fn, silent_ok=True)

        def do_verify(self):
            src = self.info_src.get().strip()
            if not os.path.isfile(src):
                messagebox.showwarning("提示", "请先选择存在的 .nr 备份文件。")
                return
            ns = type("A", (), {})()
            ns.infile = src

            def fn():
                cmd_verify(ns)
                return None, None

            self._run("严格校验", fn, silent_ok=True)

        def do_unpack(self):
            src = self.up_src.get().strip()
            if not os.path.isfile(src):
                messagebox.showwarning("提示", "请先选择存在的 .nr 备份文件。")
                return
            d = self.up_dir.get().strip() or None
            ns = type("A", (), {})()
            ns.infile, ns.dir = src, d
            real_dir = d or os.path.join(
                os.path.dirname(os.path.abspath(src)),
                os.path.splitext(os.path.basename(src))[0] + "_unpacked")

            def fn():
                cmd_unpack(ns)
                return real_dir, None

            self._run("解包 .nr", fn)

        def do_pack(self):
            d = self.pk_dir.get().strip()
            out = self.pk_out.get().strip()
            if not os.path.isdir(d):
                messagebox.showwarning("提示", "请先选择解包后的文件目录。")
                return
            if not out:
                messagebox.showwarning("提示", "请先选择输出 .nr 文件路径。")
                return
            ns = type("A", (), {})()
            ns.srcdir, ns.outfile = d, out

            def fn():
                cmd_pack(ns)
                return out, None

            self._run("打包为 .nr", fn)

    root = tk.Tk()
    App(root)
    root.mainloop()


def main():
    ap = argparse.ArgumentParser(
        description="NRadio .nr 备份一键修改与打包工具")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("info"); s.add_argument("infile")
    s = sub.add_parser("verify"); s.add_argument("infile")
    s = sub.add_parser("unpack")
    s.add_argument("infile"); s.add_argument("-d", dest="dir")
    s = sub.add_parser("pack")
    s.add_argument("srcdir"); s.add_argument("-o", dest="outfile",
                                             required=True)
    s = sub.add_parser("unlock")
    s.add_argument("infile"); s.add_argument("-o", dest="outfile")
    s.add_argument("--no-at", action="store_true",
                   help="uci 方式下不取消隐藏 AT 指令页")
    s.add_argument("--method", choices=["uci", "rc"], default="uci",
                   help="注入方式: uci=etc/uci-defaults(默认); "
                        "rc=etc/rc.local 开机一次性脚本(仅 SSH+ADB)")
    sub.add_parser("menu")
    a = ap.parse_args()
    if not a.cmd:
        gui_main(); return
    if a.cmd == "menu":
        menu(); return
    try:
        {"info": cmd_info, "verify": cmd_verify, "unpack": cmd_unpack,
         "pack": cmd_pack, "unlock": cmd_unlock}[a.cmd](a)
    except NrError as e:
        print("错误:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

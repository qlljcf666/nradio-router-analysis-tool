#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenWrt 插件打包工具 (IPK / APK)
=================================
将 luci-app-xxx 插件源码目录打包为:
  - IPK  (opkg 格式, OpenWrt <= 23.05)
  - APK  (apk v2 三段流格式, OpenWrt master/24.10+)

源码目录约定(与 OpenWrt luci.mk 一致):
  Makefile            必选, 解析 PKG_NAME/PKG_VERSION/PKG_RELEASE/LUCI_DEPENDS/conffiles
  root/    (或 files/) -> 打包到 /
  luasrc/             -> 打包到 /usr/lib/lua/luci/
  htdocs/             -> 打包到 /www/

特性:
  - 纯 Python 标准库, tkinter 单文件, 零第三方依赖, Windows/Linux 均可运行
  - USTAR 格式 tar(无 PAX 扩展头), gzip mtime=0 可复现构建
  - 自动识别 etc/init.d 服务与 etc/uci-defaults, 生成 postinst/prerm
  - 中文适配: 提取 luasrc 可翻译字符串生成/更新 po 文件, 编译 lmo
    并打包为独立的 luci-i18n-xxx 语言包 (IPK/APK)
  - 命令行模式: python openwrt_packager_gui.py --cli --src <dir> [--out <dir>] [--ipk] [--apk] [--i18n]
"""
APP_VERSION = '1.1'

import os
import io
import re
import sys
import gzip
import time
import threading

# =====================================================================
#  Makefile 解析
# =====================================================================

def _read_multiline_var(lines, name):
    """读取 Makefile 变量, 支持反斜杠续行"""
    pat = re.compile(r'^%s\s*:?=\s*(.*)$' % re.escape(name))
    out, capture = [], False
    for ln in lines:
        if not capture:
            m = pat.match(ln)
            if m:
                capture = True
                v = m.group(1).rstrip()
                if v.endswith('\\'):
                    out.append(v[:-1])
                else:
                    out.append(v)
                    break
        else:
            v = ln.strip()
            if v.endswith('\\'):
                out.append(v[:-1])
            else:
                out.append(v)
                break
    return ' '.join(out)


def parse_makefile(path):
    """解析 OpenWrt 包 Makefile, 返回 dict"""
    with open(path, encoding='utf-8', errors='ignore') as f:
        text = f.read()
    lines = text.splitlines()
    info = {}
    for key, name in (('name', 'PKG_NAME'), ('version', 'PKG_VERSION'),
                      ('release', 'PKG_RELEASE'), ('license', 'PKG_LICENSE'),
                      ('title', 'LUCI_TITLE'), ('maintainer', 'PKG_MAINTAINER')):
        v = _read_multiline_var(lines, name)
        if v:
            info[key] = v.strip()
    info.setdefault('release', '1')
    info.setdefault('license', 'GPLv3')
    info.setdefault('title', info.get('name', ''))
    info.setdefault('arch', 'all')

    # 依赖: 优先 LUCI_DEPENDS, 回退 DEPENDS
    dep_text = _read_multiline_var(lines, 'LUCI_DEPENDS') or _read_multiline_var(lines, 'DEPENDS')
    deps = []
    for tok in re.split(r'[\s\\]+', dep_text):
        tok = tok.strip()
        if not tok or tok.startswith('$') or tok.startswith('@'):
            continue
        if tok.startswith('+'):
            tok = tok[1:]
        if tok and tok not in deps:
            deps.append(tok)
    info['depends'] = deps

    # conffiles define 块
    info['conffiles'] = []
    m = re.search(r'define\s+Package/[\w.-]+/conffiles\s*\n(.*?)\nendef', text, re.S)
    if m:
        info['conffiles'] = [l.strip() for l in m.group(1).splitlines() if l.strip()]
    return info


# =====================================================================
#  文件收集 (luci.mk 路径映射)
# =====================================================================

def collect_files(src):
    """返回 [(arcname, 源绝对路径, mode)]，arcname 以 ./ 开头"""
    files = []

    def add_tree(sub, prefix):
        base = os.path.join(src, sub)
        if not os.path.isdir(base):
            return
        for root, _dirs, fns in os.walk(base):
            rel = os.path.relpath(root, base)
            for fn in sorted(fns):
                sp = os.path.join(root, fn)
                rp = fn if rel == '.' else os.path.join(rel, fn).replace('\\', '/')
                arc = './%s%s' % (prefix, rp)
                is_exec = fn.endswith('.sh') or rp.startswith('etc/init.d/')
                files.append((arc, sp, 0o755 if is_exec else 0o644))

    add_tree('root', '')
    if not os.path.isdir(os.path.join(src, 'root')):
        add_tree('files', '')          # 标准 OpenWrt package 惯例
    add_tree('luasrc', 'usr/lib/lua/luci/')
    add_tree('htdocs', 'www/')
    return files


# =====================================================================
#  中文适配 (po 提取/更新 + lmo 编译 + luci-i18n-xxx 语言包)
# =====================================================================

def find_i18n_domain(src, pkg_name):
    """i18n 域名 = controller 文件名(优先), 回退包名推导"""
    ctl = os.path.join(src, 'luasrc', 'controller')
    if os.path.isdir(ctl):
        names = sorted(f for f in os.listdir(ctl) if f.endswith('.lua'))
        if names:
            return names[0][:-4]
    return pkg_name.replace('luci-app-', '').replace('-', '_')


def extract_msgids(src):
    """扫描 luasrc 下 lua translate()/htm <%:%>, 返回去重有序的 msgid 列表"""
    out, seen = [], set()

    def add(s):
        s = s.replace('\\"', '"').replace("\\'", "'")
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    base = os.path.join(src, 'luasrc')
    if not os.path.isdir(base):
        return out
    for root, _dirs, fns in os.walk(base):
        for fn in sorted(fns):
            p = os.path.join(root, fn)
            try:
                c = open(p, encoding='utf-8').read()
            except Exception:
                continue
            if fn.endswith('.lua'):
                for m in re.finditer(r'translate(?:f)?\s*\(\s*"((?:[^"\\]|\\.)*)"', c):
                    add(m.group(1))
                for m in re.finditer(r"translate(?:f)?\s*\(\s*'((?:[^'\\]|\\.)*)'", c):
                    add(m.group(1))
            elif fn.endswith('.htm'):
                for m in re.finditer(r'<%:([^%]+)%>', c):
                    add(m.group(1).strip())
    return out


def _po_unescape(s):
    return s.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('\\\\', '\\')


def _po_escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t')


def parse_po(path):
    """解析 po 文件, 返回 [(msgid, msgstr)] (跳过 header)"""
    entries, msgid, msgstr, state = [], None, None, None

    def flush():
        nonlocal msgid, msgstr
        if msgid is not None and msgid != '':
            entries.append((msgid, msgstr if msgstr is not None else ''))
        msgid, msgstr, state = None, None, None

    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                flush()
                continue
            if line.startswith('#'):
                continue
            if line.startswith('msgid "'):
                flush()
                msgid, state = _po_unescape(line[7:-1]), 'id'
            elif line.startswith('msgstr "'):
                msgstr, state = _po_unescape(line[8:-1]), 'str'
            elif line.startswith('"') and line.endswith('"'):
                v = _po_unescape(line[1:-1])
                if state == 'id':
                    msgid = (msgid or '') + v
                elif state == 'str':
                    msgstr = (msgstr or '') + v
    flush()
    return entries


def po_path_of(src, domain):
    return os.path.join(src, 'po', 'zh_Hans', '%s.po' % domain)


# ---- 常用 LuCI 界面字符串内置词典 ----
GLOSSARY = {
    'Save': '保存', 'Save & Apply': '保存并应用', 'Save &amp; Apply': '保存并应用',
    'Apply': '应用', 'Cancel': '取消', 'Reset': '重置', 'Delete': '删除', 'Add': '添加',
    'Edit': '编辑', 'Remove': '移除', 'Close': '关闭', 'OK': '确定', 'Yes': '是', 'No': '否',
    'Enable': '启用', 'Disable': '禁用', 'Enabled': '已启用', 'Disabled': '已禁用',
    'Start': '启动', 'Stop': '停止', 'Restart': '重启', 'Reload': '重新加载',
    'Refresh': '刷新', 'Search': '搜索', 'Filter': '过滤', 'Clear': '清除', 'Clean': '清理',
    'Status': '状态', 'Network': '网络', 'System': '系统', 'Services': '服务',
    'Settings': '设置', 'Configuration': '配置', 'Config': '配置', 'General': '常规',
    'General Settings': '常规设置', 'Advanced': '高级', 'Advanced Settings': '高级设置',
    'Basic': '基本', 'Options': '选项', 'Option': '选项', 'Parameters': '参数',
    'Name': '名称', 'Description': '描述', 'Type': '类型', 'Value': '值', 'Default': '默认',
    'Version': '版本', 'Author': '作者', 'License': '许可证', 'Date': '日期', 'Time': '时间',
    'Username': '用户名', 'Password': '密码', 'Confirm': '确认', 'Login': '登录', 'Logout': '注销',
    'Interface': '接口', 'Interfaces': '接口', 'Device': '设备', 'Devices': '设备',
    'Port': '端口', 'Ports': '端口', 'Address': '地址', 'IP Address': 'IP 地址',
    'MAC Address': 'MAC 地址', 'Gateway': '网关', 'DNS': 'DNS', 'Netmask': '子网掩码',
    'Protocol': '协议', 'Mode': '模式', 'Channel': '信道', 'Bandwidth': '带宽',
    'SSID': 'SSID', 'Wireless': '无线', 'Firewall': '防火墙', 'Routing': '路由',
    'Hostname': '主机名', 'Firmware': '固件', 'Upgrade': '升级', 'Backup': '备份',
    'Restore': '恢复', 'Reboot': '重启', 'Shutdown': '关机', 'Logs': '日志', 'Log': '日志',
    'Actions': '操作', 'Action': '操作', 'Info': '信息', 'Information': '信息',
    'Details': '详情', 'Overview': '总览', 'Statistics': '统计', 'Graphs': '图表',
    'Loading': '加载中', 'Load': '加载', 'Unload': '卸载', 'Loaded': '已加载',
    'Not loaded': '未加载', 'Installed': '已安装', 'Not installed': '未安装',
    'Install': '安装', 'Uninstall': '卸载', 'Update': '更新', 'Check': '检查',
    'Success': '成功', 'Failed': '失败', 'Error': '错误', 'Warning': '警告',
    'Unknown': '未知', 'None': '无', 'All': '全部', 'Auto': '自动', 'Manual': '手动',
    'Yes or No': '是或否', 'On': '开', 'Off': '关', 'Open': '打开', 'Up': '上', 'Down': '下',
    'Send': '发送', 'Receive': '接收', 'Connect': '连接', 'Disconnect': '断开',
    'Connected': '已连接', 'Disconnected': '未连接', 'Connecting': '连接中',
    'Timeout': '超时', 'Retry': '重试', 'Submit': '提交', 'Confirm Delete': '确认删除',
    'Are you sure?': '确定吗？', 'Please wait': '请稍候', 'Done': '完成', 'Skip': '跳过',
    'Previous': '上一步', 'Next': '下一步', 'Finish': '完成', 'Help': '帮助',
    'Index': '序号', 'Count': '数量', 'Total': '总计', 'Size': '大小', 'Path': '路径',
    'File': '文件', 'Directory': '目录', 'Upload': '上传', 'Download': '下载',
    'Select': '选择', 'Choose': '选择', 'All Rights Reserved': '版权所有',
    'Current': '当前', 'New': '新建', 'Old': '旧', 'Target': '目标', 'Source': '来源',
    'Priority': '优先级', 'Order': '顺序', 'Group': '分组', 'User': '用户', 'Users': '用户',
    'Global': '全局', 'Local': '本地', 'Remote': '远程', 'Server': '服务器', 'Client': '客户端',
    'Seconds': '秒', 'Minutes': '分钟', 'Hours': '小时', 'Days': '天',
    'Read': '读取', 'Write': '写入', 'Execute': '执行', 'Run': '运行', 'Running': '运行中',
    'Stopped': '已停止', 'Active': '活动', 'Inactive': '未激活', 'Online': '在线', 'Offline': '离线',
    'Available': '可用', 'Unavailable': '不可用', 'Required': '必填', 'Optional': '可选',
    'Valid': '有效', 'Invalid': '无效', 'Empty': '空', 'Not empty': '非空', 'Not null': '不能为空',
}


def _online_translate(text, log=None):
    """MyMemory 免费翻译 API (en -> zh-CN), 无需密钥"""
    import urllib.parse, urllib.request, json
    url = 'https://api.mymemory.translated.net/get?' + urllib.parse.urlencode(
        {'q': text, 'langpair': 'en|zh-CN'})
    req = urllib.request.Request(url, headers={'User-Agent': 'openwrt-packager/%s' % APP_VERSION})
    d = json.loads(urllib.request.urlopen(req, timeout=15).read().decode('utf-8'))
    t = (d.get('responseData') or {}).get('translatedText')
    if not t or 'MYMEMORY WARNING' in str(t):
        raise RuntimeError('在线翻译不可用')
    return t


def write_po(path, entries, domain):
    """按统一格式写回 po 文件"""
    lines = ['# Chinese (Simplified) translations for %s' % domain,
             'msgid ""', 'msgstr "Content-Type: text/plain; charset=UTF-8\\n"', '']
    for k, v in entries:
        lines += ['msgid "%s"' % _po_escape(k), 'msgstr "%s"' % _po_escape(v), '']
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines))


def auto_translate_po(path, log=print, online=True, max_online=300):
    """自动翻译 po 中的空 msgstr: 先内置词典, 剩余走在线 API, 返回 (词典命中, 在线命中, 仍空)"""
    entries = parse_po(path)
    lower_g = {k.lower(): v for k, v in GLOSSARY.items()}
    n_dict = n_online = 0
    pending = []
    out = []
    for k, v in entries:
        if v or not k:
            out.append((k, v))
            continue
        hit = GLOSSARY.get(k) or lower_g.get(k.lower())
        if hit:
            out.append((k, hit))
            n_dict += 1
        else:
            out.append((k, v))
            pending.append(k)
    log('[翻译] 内置词典命中 %d 条, 剩余 %d 条' % (n_dict, len(pending)))

    if online and pending:
        import time as _t
        failed = []
        for i, k in enumerate(pending[:max_online]):
            try:
                tr = _online_translate(k)
                out = [(kk, tr if kk == k else vv) for kk, vv in out]
                n_online += 1
                log('[在线] (%d/%d) %s -> %s' % (i + 1, min(len(pending), max_online), k, tr))
            except Exception as e:
                failed.append(k)
                log('[在线] (%d/%d) %s 翻译失败: %s' % (i + 1, min(len(pending), max_online), k, e))
            _t.sleep(0.3)
        if len(pending) > max_online:
            failed += pending[max_online:]
            log('[在线] 超出单次上限 %d, 其余 %d 条保持空白' % (max_online, len(pending) - max_online))
        pending = failed
    elif pending:
        log('[翻译] 离线模式, %d 条保持空白' % len(pending))

    domain = os.path.splitext(os.path.basename(path))[0]
    write_po(path, out, domain)
    log('[翻译] 完成: 词典 %d + 在线 %d, 仍空白 %d' % (n_dict, n_online, len(pending)))
    return n_dict, n_online, len(pending)


def update_po(src, domain, log=print):
    """提取 msgid 并合并已有翻译写回 po, 返回 (路径, 总数, 新增, 保留)"""
    msgids = extract_msgids(src)
    path = po_path_of(src, domain)
    old = dict(parse_po(path)) if os.path.isfile(path) else {}
    new_n = len([k for k in msgids if k not in old])
    obsolete = [(k, v) for k, v in old.items() if k not in msgids]

    lines = ['# Chinese (Simplified) translations for %s' % domain,
             'msgid ""', 'msgstr "Content-Type: text/plain; charset=UTF-8\\n"', '']
    for k in msgids:
        lines += ['msgid "%s"' % _po_escape(k), 'msgstr "%s"' % _po_escape(old.get(k, '')), '']
    for k, v in obsolete:  # 无源码引用(动态字符串/手工条目), 原样保留在末尾
        lines += ['# no source reference, kept', 'msgid "%s"' % _po_escape(k), 'msgstr "%s"' % _po_escape(v), '']
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines))
    log('[PO] %s  共 %d 条 (新增 %d, 保留 %d, 无源码引用 %d)' % (path, len(msgids), new_n, len(msgids) - new_n, len(obsolete)))
    return path, len(msgids), new_n


def _sfh_hash(data, init):
    """SuperFastHash (Paul Hsieh), 与 LuCI lmo.c 完全一致 (uint32, signed char 语义)"""
    if not data:
        return 0
    data = bytes(data)
    M = 0xFFFFFFFF
    h = init & M

    def sx(b):  # signed char
        return b - 256 if b >= 128 else b

    rem = len(data) & 3
    i, n = 0, len(data) >> 2
    for _ in range(n):
        g16 = data[i] | (data[i + 1] << 8)
        h = (h + g16) & M
        tmp = ((data[i + 2] | (data[i + 3] << 8)) << 11) ^ h
        h = ((h << 16) & M) ^ (tmp & M)
        i += 4
        h = (h + (h >> 11)) & M
    if rem == 3:
        h = (h + (data[i] | (data[i + 1] << 8))) & M
        h ^= (h << 16) & M
        h ^= (sx(data[i + 2]) << 18) & M
        h = (h + (h >> 11)) & M
    elif rem == 2:
        h = (h + (data[i] | (data[i + 1] << 8))) & M
        h ^= (h << 11) & M
        h = (h + (h >> 17)) & M
    elif rem == 1:
        h = (h + sx(data[i])) & M
        h ^= (h << 10) & M
        h = (h + (h >> 1)) & M
    h ^= (h << 3) & M
    h = (h + (h >> 5)) & M
    h ^= (h << 4) & M
    h = (h + (h >> 17)) & M
    h ^= (h << 25) & M
    h = (h + (h >> 6)) & M
    return h & M


def _canon(s):
    """lmo_canon_hash 的空白规范化: 连续空白折叠为单空格, 去尾部空格"""
    out, prev_space = [], True
    for ch in s:
        if ch in ' \t\n\v\f\r':
            if not prev_space:
                out.append(' ')
            prev_space = True
        else:
            out.append(ch)
            prev_space = False
    if out and out[-1] == ' ':
        out.pop()
    return ''.join(out)


def build_lmo(entries):
    """po 条目 -> lmo 二进制 (官方 po2lmo.c 格式):
    [值字符串区(4 字节对齐)] + [索引 N*16B 大端 (key_id,val_id,offset,length) 按 key_id 排序] + [uint32 大端 索引起始偏移]
    key_id = sfh_hash(规范化 msgid); 跳过空翻译与 key/value 哈希相同的条目"""
    import struct
    items = []
    for k, v in entries:
        if not k or not v:
            continue
        kb, vb = _canon(k).encode('utf-8'), v.encode('utf-8')
        kid = _sfh_hash(kb, len(kb))
        if kid == _sfh_hash(vb, len(vb)):
            continue
        items.append((kid, vb))
    items.sort(key=lambda kv: kv[0])
    blob = bytearray()
    ents = []
    for kid, vb in items:
        ents.append(struct.pack('>IIII', kid, 1, len(blob), len(vb)))
        blob += vb
        blob += b'\0' * ((4 - (len(vb) % 4)) % 4)
    return bytes(blob) + b''.join(ents) + struct.pack('>I', len(blob))


def build_i18n(info, src, out_dir, do_ipk=True, do_apk=True, log=print):
    """编译 po -> lmo, 打包 luci-i18n-<app> 语言包 (IPK/APK), 返回输出路径列表"""
    domain = find_i18n_domain(src, info['name'])
    path = po_path_of(src, domain)
    if not os.path.isfile(path):
        raise RuntimeError('未找到 po 文件: %s (请先提取)' % path)
    lmo = build_lmo(parse_po(path))
    app = info['name'].replace('luci-app-', '')
    name = 'luci-i18n-%s' % app
    ver, rel, arch = info['version'], info['release'], info['arch']
    # 同时放置 zh-cn 与 zh-hans 两个文件名, 兼容不同版本 LuCI 的语言代码
    arcs = ['./usr/lib/lua/luci/i18n/%s.zh-cn.lmo' % domain,
            './usr/lib/lua/luci/i18n/%s.zh-hans.lmo' % domain]
    post = (b'#!/bin/sh\nif [ -z "${IPKG_INSTROOT}${APK_INSTROOT}" ]; then\n'
            b'\trm -f /tmp/luci-indexcache /tmp/luci-modulecache/*\n\texit 0\nfi\n')
    outs = []

    # data.tar.gz
    tw = TarWriter()
    for arc in arcs:
        tw.add_parent_dirs(arc)
        tw.add_file(arc, lmo)
    data_gz = _gz(tw.finish())
    lmo_size = len(lmo) * len(arcs)

    if do_ipk:
        ctl = ('Package: %s\nVersion: %s-%s\nDepends: %s\nLicense: %s\nSection: luci\n'
               'Architecture: %s\nInstalled-Size: %d\nDescription: Chinese (Simplified) translation for %s\n'
               % (name, ver, rel, info['name'], info['license'], arch, lmo_size, info['title'])).encode()
        tw = TarWriter()
        tw.add_file('./control', ctl)
        tw.add_file('./postinst', post, 0o755)
        ctl_gz = _gz(tw.finish())
        tw = TarWriter()
        tw.add_file('./control.tar.gz', ctl_gz)
        tw.add_file('./data.tar.gz', data_gz)
        out_path = os.path.join(out_dir, '%s_%s-%s_%s.ipk' % (name, ver, rel, arch))
        with open(out_path, 'wb') as f:
            f.write(_gz(tw.finish()))
        log('[IPK] %s  (%d 字节, lmo %d 字节)' % (out_path, os.path.getsize(out_path), lmo_size))
        outs.append(out_path)

    if do_apk:
        pkg_lines = ['pkgname = %s' % name, 'pkgver = %s-r%s' % (ver, rel),
                     'pkgdesc = Chinese (Simplified) translation for %s' % info['title'], 'url = ',
                     'builddate = %d' % int(time.time()), 'packager = openwrt-packager-gui',
                     'size = %d' % lmo_size, 'arch = %s' % arch, 'origin = %s' % name,
                     'license = %s' % info['license'], 'depend = %s' % info['name']]
        tw = TarWriter()
        tw.add_file('.PKGINFO', ('\n'.join(pkg_lines) + '\n').encode())
        tw.add_file('.post-install', post, 0o755)
        out_path = os.path.join(out_dir, '%s-%s-r%s.apk' % (name, ver, rel))
        with open(out_path, 'wb') as f:
            f.write(_gz(tw.finish()) + data_gz)
        log('[APK] %s  (%d 字节, lmo %d 字节)' % (out_path, os.path.getsize(out_path), len(lmo)))
        outs.append(out_path)
    log('[语言包] 域名=%s  包名=%s  有效翻译=%d 条' % (domain, name, sum(1 for _, v in parse_po(path) if v)))
    return outs


# =====================================================================
#  安装脚本生成 (同时兼容 opkg IPKG_INSTROOT 与 apk)
# =====================================================================

def gen_scripts(files):
    svcs = sorted({a.split('/')[-1] for a, _, _ in files if a.startswith('./etc/init.d/')})
    ucid = sorted({a.split('/')[-1] for a, _, _ in files if a.startswith('./etc/uci-defaults/')})

    post = ['#!/bin/sh', 'if [ -z "${IPKG_INSTROOT}${APK_INSTROOT}" ]; then']
    for u in ucid:
        post.append('\t[ -f /etc/uci-defaults/%s ] && . /etc/uci-defaults/%s && rm -f /etc/uci-defaults/%s' % (u, u, u))
    post.append('\trm -f /tmp/luci-indexcache /tmp/luci-modulecache/*')
    for s in svcs:
        post.append('\t/etc/init.d/%s enable 2>/dev/null' % s)
    post.append('\texit 0')
    post.append('fi')

    pre = ['#!/bin/sh', 'if [ -z "${IPKG_INSTROOT}${APK_INSTROOT}" ]; then']
    for s in svcs:
        pre.append('\t/etc/init.d/%s stop 2>/dev/null' % s)
        pre.append('\t/etc/init.d/%s disable 2>/dev/null' % s)
    pre.append('\trm -f /tmp/luci-indexcache /tmp/luci-modulecache/*')
    pre.append('\texit 0')
    pre.append('fi')
    return ('\n'.join(post) + '\n').encode(), ('\n'.join(pre) + '\n').encode()


# =====================================================================
#  tar/gzip 底层工具 (手写 USTAR, 无 PAX, mtime=0)
#
#  为什么不用 Python tarfile 写入:
#  tarfile 构造 tar 头时会把 mode 强制掩码到 0o7777 (丢弃 S_IFDIR/S_IFREG
#  文件类型位), 而 opkg 的 tar 解析器依据 mode & S_IFMT 判断目录/文件。
#  缺少 S_IFDIR 的目录条目会被 opkg 当普通文件 wfopen, 报
#  "Is a directory" / "No such file or directory" 并导致全部文件安装失败。
#  GNU tar 写入的是完整 st_mode (如目录 040755), 此处手写 tar 头保持一致。
# =====================================================================

_S_IFDIR = 0o040000
_S_IFREG = 0o100000


def _tar_split_name(name):
    """USTAR name(100)/prefix(155) 拆分, 返回 (prefix, name) 字节串"""
    raw = name.encode('utf-8')
    if len(raw) <= 100:
        return b'', raw
    parts = name.split('/')
    for i in range(len(parts) - 1, 0, -1):
        nm = '/'.join(parts[i:])
        pf = '/'.join(parts[:i])
        if len(nm.encode('utf-8')) <= 100 and len(pf.encode('utf-8')) <= 155:
            return pf.encode('utf-8'), nm.encode('utf-8')
    raise ValueError('tar 路径过长无法编码: %s' % name)


def _tar_header(name, mode, size, typeflag, mtime=0):
    """构造 512 字节 USTAR 头, mode 为完整 st_mode (含文件类型位)"""
    prefix, nm = _tar_split_name(name)
    h = bytearray(512)
    h[0:len(nm)] = nm
    h[100:108] = b'%07o\0' % (mode & 0o777777)      # mode (含类型位)
    h[108:116] = b'%07o\0' % 0                       # uid
    h[116:124] = b'%07o\0' % 0                       # gid
    h[124:136] = b'%011o\0' % size                   # size
    h[136:148] = b'%011o\0' % mtime                  # mtime
    h[148:156] = b'        '                         # chksum 占位
    h[156:157] = typeflag                            # typeflag
    h[257:263] = b'ustar\0'                          # magic
    h[263:265] = b'00'                               # version
    h[265:269] = b'root'                             # uname
    h[297:301] = b'root'                             # gname
    if prefix:
        h[345:345 + len(prefix)] = prefix            # prefix
    h[148:156] = b'%06o\0 ' % sum(h)                 # chksum
    return bytes(h)


class TarWriter:
    """手写 USTAR writer: 目录条目 mode 带 S_IFDIR, 文件带 S_IFREG"""

    def __init__(self):
        self.buf = io.BytesIO()
        self._dirs = set()

    def _write_entry(self, name, mode, size, typeflag, payload=b''):
        self.buf.write(_tar_header(name, mode, size, typeflag))
        if payload:
            self.buf.write(payload)
            pad = (-len(payload)) % 512
            if pad:
                self.buf.write(b'\0' * pad)

    def add_file(self, name, data, mode=0o644):
        self._write_entry(name, mode | _S_IFREG, len(data), b'0', data)

    def add_dir(self, name, mode=0o755):
        if name in self._dirs:
            return
        self._dirs.add(name)
        if not name.endswith('/'):
            name += '/'
        self._write_entry(name, mode | _S_IFDIR, 0, b'5')

    def add_parent_dirs(self, arcname):
        parts = [p for p in arcname.strip('/').split('/') if p not in ('', '.')][:-1]
        for i in range(1, len(parts) + 1):
            self.add_dir('./' + '/'.join(parts[:i]) + '/')

    def finish(self):
        self.buf.write(b'\0' * 1024)
        return self.buf.getvalue()


def _gz(data):
    return gzip.compress(data, compresslevel=9, mtime=0)


# =====================================================================
#  IPK 构建 (opkg)
# =====================================================================

def build_ipk(info, files, out_dir, log=print):
    name = info['name']
    ver = '%s-%s' % (info['version'], info['release'])
    out_path = os.path.join(out_dir, '%s_%s_%s.ipk' % (name, ver, info['arch']))
    post, pre = gen_scripts(files)
    size = sum(os.path.getsize(sp) for _, sp, _ in files)

    ctl_lines = [
        'Package: %s' % name,
        'Version: %s' % ver,
        'Depends: %s' % ', '.join(info['depends']),
        'License: %s' % info['license'],
        'Section: luci',
        'Architecture: %s' % info['arch'],
        'Installed-Size: %d' % size,
        'Maintainer: %s' % info.get('maintainer', 'unknown'),
        'Description: %s' % info['title'],
    ]
    conff = (''.join(c + '\n' for c in info['conffiles'])).encode()

    # control.tar.gz
    tw = TarWriter()
    tw.add_file('./control', ('\n'.join(ctl_lines) + '\n').encode())
    if conff:
        tw.add_file('./conffiles', conff)
    tw.add_file('./postinst', post, 0o755)
    tw.add_file('./prerm', pre, 0o755)
    ctl_gz = _gz(tw.finish())

    # data.tar.gz (含显式目录条目, opkg 依赖其创建父目录)
    tw = TarWriter()
    for arc, sp, mode in files:
        tw.add_parent_dirs(arc)
        with open(sp, 'rb') as f:
            tw.add_file(arc, f.read(), mode)
    data_gz = _gz(tw.finish())

    # 外层 tar.gz
    tw = TarWriter()
    tw.add_file('./control.tar.gz', ctl_gz)
    tw.add_file('./data.tar.gz', data_gz)
    with open(out_path, 'wb') as f:
        f.write(_gz(tw.finish()))
    log('[IPK] %s  (%d 字节, %d 个文件)' % (out_path, os.path.getsize(out_path), len(files)))
    return out_path


# =====================================================================
#  APK 构建 (apk v2 三段流: [签名段]+控制段+数据段, 本工具无签名)
# =====================================================================

def build_apk(info, files, out_dir, log=print):
    name = info['name']
    ver = '%s-r%s' % (info['version'], info['release'])
    out_path = os.path.join(out_dir, '%s-%s.apk' % (name, ver))
    post, pre = gen_scripts(files)
    size = sum(os.path.getsize(sp) for _, sp, _ in files)

    pkg_lines = [
        'pkgname = %s' % name,
        'pkgver = %s' % ver,
        'pkgdesc = %s' % info['title'],
        'url = ',
        'builddate = %d' % int(time.time()),
        'packager = openwrt-packager-gui',
        'size = %d' % size,
        'arch = %s' % info['arch'],
        'origin = %s' % name,
        'license = %s' % info['license'],
    ]
    for d in info['depends']:
        pkg_lines.append('depend = %s' % d)
    pkginfo = ('\n'.join(pkg_lines) + '\n').encode()

    # 控制段: .PKGINFO + 安装脚本
    tw = TarWriter()
    tw.add_file('.PKGINFO', pkginfo)
    tw.add_file('.post-install', post, 0o755)
    tw.add_file('.pre-deinstall', pre, 0o755)
    ctl_gz = _gz(tw.finish())

    # 数据段
    tw = TarWriter()
    for arc, sp, mode in files:
        tw.add_parent_dirs(arc)
        with open(sp, 'rb') as f:
            tw.add_file(arc, f.read(), mode)
    data_gz = _gz(tw.finish())

    with open(out_path, 'wb') as f:
        f.write(ctl_gz + data_gz)   # apk v2: gzip 流直接拼接
    log('[APK] %s  (%d 字节, %d 个文件)' % (out_path, os.path.getsize(out_path), len(files)))
    return out_path


# =====================================================================
#  GUI
# =====================================================================

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext, messagebox

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title('OpenWrt 插件打包工具 (IPK / APK)  v%s' % APP_VERSION)
            self.geometry('760x640')
            self.minsize(700, 560)
            self.info = None
            self._build_ui()

        def _build_ui(self):
            pad = dict(padx=6, pady=4)

            # --- 源码目录 ---
            fr = ttk.LabelFrame(self, text='源码目录 (含 Makefile 的 luci-app-xxx 项目根目录)')
            fr.pack(fill='x', **pad)
            self.var_src = tk.StringVar()
            ttk.Entry(fr, textvariable=self.var_src).pack(side='left', fill='x', expand=True, padx=4, pady=4)
            ttk.Button(fr, text='浏览...', command=self.on_browse_src).pack(side='left', padx=4)
            ttk.Button(fr, text='解析 Makefile', command=self.on_parse).pack(side='left', padx=4)

            # --- 输出目录 ---
            fr = ttk.LabelFrame(self, text='输出目录 (留空 = 源码目录的上一级)')
            fr.pack(fill='x', **pad)
            self.var_out = tk.StringVar()
            ttk.Entry(fr, textvariable=self.var_out).pack(side='left', fill='x', expand=True, padx=4, pady=4)
            ttk.Button(fr, text='浏览...', command=self.on_browse_out).pack(side='left', padx=4)

            # --- 包信息 ---
            fr = ttk.LabelFrame(self, text='包信息 (解析 Makefile 后可编辑)')
            fr.pack(fill='x', **pad)
            self.vars = {}
            fields = [('name', '包名'), ('version', '版本'), ('release', 'Release'),
                      ('arch', '架构'), ('title', '描述'), ('license', '许可证')]
            for i, (k, label) in enumerate(fields):
                ttk.Label(fr, text=label, width=8).grid(row=i // 3, column=(i % 3) * 2, sticky='e', padx=2, pady=2)
                v = tk.StringVar()
                self.vars[k] = v
                ttk.Entry(fr, textvariable=v, width=22).grid(row=i // 3, column=(i % 3) * 2 + 1, sticky='w', padx=2, pady=2)

            fr2 = ttk.LabelFrame(self, text='依赖 / 配置文件 (只读)')
            fr2.pack(fill='x', **pad)
            self.var_deps = tk.StringVar()
            self.var_conf = tk.StringVar()
            ttk.Label(fr2, text='Depends:').grid(row=0, column=0, sticky='e', padx=2)
            ttk.Entry(fr2, textvariable=self.var_deps, state='readonly').grid(row=0, column=1, sticky='we', padx=2, pady=2)
            ttk.Label(fr2, text='conffiles:').grid(row=1, column=0, sticky='e', padx=2)
            ttk.Entry(fr2, textvariable=self.var_conf, state='readonly').grid(row=1, column=1, sticky='we', padx=2, pady=2)
            fr2.columnconfigure(1, weight=1)

            # --- 选项与操作 ---
            fr = ttk.Frame(self)
            fr.pack(fill='x', **pad)
            self.var_ipk = tk.BooleanVar(value=True)
            self.var_apk = tk.BooleanVar(value=True)
            ttk.Checkbutton(fr, text='生成 IPK (opkg)', variable=self.var_ipk).pack(side='left', padx=6)
            ttk.Checkbutton(fr, text='生成 APK (apk v2)', variable=self.var_apk).pack(side='left', padx=6)
            ttk.Button(fr, text='开始打包', command=self.on_build).pack(side='right', padx=6)
            ttk.Button(fr, text='打开输出目录', command=self.on_open_out).pack(side='right', padx=6)

            # --- 中文语言包 ---
            fr = ttk.LabelFrame(self, text='中文语言包 (提取 po -> 翻译 -> 打包为独立 luci-i18n-xxx)')
            fr.pack(fill='x', **pad)
            ttk.Label(fr, text='域名').pack(side='left', padx=2)
            self.var_domain = tk.StringVar()
            ttk.Entry(fr, textvariable=self.var_domain, width=18).pack(side='left', padx=2)
            ttk.Button(fr, text='1. 提取/更新 po', command=self.on_extract_po).pack(side='left', padx=4)
            ttk.Button(fr, text='译中文po', command=self.on_translate_po).pack(side='left', padx=4)
            self.var_online = tk.BooleanVar(value=True)
            ttk.Checkbutton(fr, text='在线', variable=self.var_online).pack(side='left')
            ttk.Button(fr, text='编辑 po', command=self.on_edit_po).pack(side='left', padx=4)
            ttk.Button(fr, text='3. 打包语言包', command=self.on_build_i18n).pack(side='left', padx=4)
            self.var_po_status = tk.StringVar(value='(未提取)')
            ttk.Label(fr, textvariable=self.var_po_status, foreground='#666').pack(side='left', padx=8)

            # --- 日志 ---
            fr = ttk.LabelFrame(self, text='日志')
            fr.pack(fill='both', expand=True, **pad)
            self.log_text = scrolledtext.ScrolledText(fr, height=14, font=('Consolas', 9))
            self.log_text.pack(fill='both', expand=True, padx=4, pady=4)

        # ---------- 事件 ----------
        def log(self, msg):
            self.log_text.insert('end', msg + '\n')
            self.log_text.see('end')
            self.update_idletasks()

        def on_browse_src(self):
            d = filedialog.askdirectory(title='选择插件源码目录')
            if d:
                self.var_src.set(d)
                self.on_parse()

        def on_browse_out(self):
            d = filedialog.askdirectory(title='选择输出目录')
            if d:
                self.var_out.set(d)

        def on_open_out(self):
            out = self.var_out.get().strip() or os.path.dirname(os.path.abspath(self.var_src.get().strip()))
            if os.path.isdir(out):
                if sys.platform == 'win32':
                    os.startfile(out)
                elif sys.platform == 'darwin':
                    os.system('open "%s"' % out)
                else:
                    os.system('xdg-open "%s" &' % out)
            else:
                messagebox.showwarning('提示', '输出目录不存在')

        def on_parse(self):
            src = self.var_src.get().strip()
            mk = os.path.join(src, 'Makefile')
            if not os.path.isfile(mk):
                messagebox.showerror('错误', '未找到 Makefile:\n%s' % mk)
                return
            try:
                info = parse_makefile(mk)
            except Exception as e:
                messagebox.showerror('解析失败', str(e))
                return
            if 'name' not in info:
                messagebox.showerror('解析失败', 'Makefile 中未找到 PKG_NAME')
                return
            self.info = info
            for k in ('name', 'version', 'release', 'arch', 'title', 'license'):
                self.vars[k].set(info.get(k, ''))
            self.var_deps.set(', '.join(info['depends']) or '(无)')
            self.var_conf.set(', '.join(info['conffiles']) or '(无)')
            files = collect_files(src)
            self.log('[解析] 包名=%s 版本=%s-%s 依赖=%d 个, 待打包文件=%d 个'
                     % (info['name'], info['version'], info['release'], len(info['depends']), len(files)))
            # 语言包状态
            domain = find_i18n_domain(src, info['name'])
            self.var_domain.set(domain)
            self._refresh_po_status()

        def _refresh_po_status(self):
            src = self.var_src.get().strip()
            domain = self.var_domain.get().strip()
            path = po_path_of(src, domain) if domain else ''
            if path and os.path.isfile(path):
                ents = parse_po(path)
                done = sum(1 for _, v in ents if v)
                self.var_po_status.set('po: %d 条, 已翻译 %d 条' % (len(ents), done))
            else:
                self.var_po_status.set('(未提取)')

        def on_extract_po(self):
            src = self.var_src.get().strip()
            if not self.info:
                messagebox.showwarning('提示', '请先解析 Makefile')
                return
            domain = self.var_domain.get().strip() or find_i18n_domain(src, self.info['name'])
            self.var_domain.set(domain)
            try:
                update_po(src, domain, log=self.log)
            except Exception as e:
                messagebox.showerror('提取失败', str(e))
                return
            self._refresh_po_status()
            self.log('[提示] 请点击「编辑 po」为新增 msgid 填写 msgstr 中文翻译, 再打包语言包')

        def on_edit_po(self):
            src = self.var_src.get().strip()
            domain = self.var_domain.get().strip()
            path = po_path_of(src, domain)
            if not os.path.isfile(path):
                messagebox.showwarning('提示', 'po 文件不存在, 请先「提取/更新 po」')
                return
            if sys.platform == 'win32':
                os.startfile(path)
            elif sys.platform == 'darwin':
                os.system('open "%s"' % path)
            else:
                os.system('xdg-open "%s" &' % path)

        def on_translate_po(self):
            src = self.var_src.get().strip()
            domain = self.var_domain.get().strip()
            path = po_path_of(src, domain)
            if not os.path.isfile(path):
                messagebox.showwarning('提示', 'po 文件不存在, 请先「提取/更新 po」')
                return
            online = self.var_online.get()
            if online and not messagebox.askyesno('译中文po', '将先用内置词典翻译, 剩余条目调用免费在线 API (MyMemory) 翻译。\n翻译结果建议再经「编辑 po」人工校对。是否继续？'):
                return

            def work():
                try:
                    auto_translate_po(path, log=self.log, online=online)
                    self.log('[提示] 自动翻译完成, 建议点击「编辑 po」校对后再打包语言包')
                except Exception as e:
                    import traceback
                    self.log('[异常] %s' % e)
                    self.log(traceback.format_exc())
                self._refresh_po_status()

            threading.Thread(target=work, daemon=True).start()

        def on_build_i18n(self):
            src = self.var_src.get().strip()
            if not self.info:
                messagebox.showwarning('提示', '请先解析 Makefile')
                return
            if not (self.var_ipk.get() or self.var_apk.get()):
                messagebox.showwarning('提示', '请至少勾选一种输出格式')
                return
            for k in ('name', 'version', 'release', 'arch', 'title', 'license'):
                self.info[k] = self.vars[k].get().strip() or self.info.get(k, '')
            out = self.var_out.get().strip() or os.path.dirname(os.path.abspath(src))
            os.makedirs(out, exist_ok=True)
            info = dict(self.info)
            do_ipk, do_apk = self.var_ipk.get(), self.var_apk.get()

            def work():
                try:
                    build_i18n(info, src, out, do_ipk=do_ipk, do_apk=do_apk, log=self.log)
                    self.log('[完成] 语言包打包结束')
                except Exception as e:
                    import traceback
                    self.log('[异常] %s' % e)
                    self.log(traceback.format_exc())

            threading.Thread(target=work, daemon=True).start()

        def on_build(self):
            src = self.var_src.get().strip()
            if not self.info:
                messagebox.showwarning('提示', '请先解析 Makefile')
                return
            if not (self.var_ipk.get() or self.var_apk.get()):
                messagebox.showwarning('提示', '请至少勾选一种输出格式')
                return
            # 应用编辑后的字段
            for k in ('name', 'version', 'release', 'arch', 'title', 'license'):
                self.info[k] = self.vars[k].get().strip() or self.info.get(k, '')
            out = self.var_out.get().strip() or os.path.dirname(os.path.abspath(src))
            os.makedirs(out, exist_ok=True)
            info = dict(self.info)
            do_ipk, do_apk = self.var_ipk.get(), self.var_apk.get()

            def work():
                try:
                    files = collect_files(src)
                    if not files:
                        self.log('[错误] 未收集到任何文件 (需要 root/ 或 luasrc/ 或 htdocs/ 目录)')
                        return
                    self.log('[开始] %s -> %s' % (src, out))
                    if do_ipk:
                        build_ipk(info, files, out, log=self.log)
                    if do_apk:
                        build_apk(info, files, out, log=self.log)
                    self.log('[完成] 打包结束')
                except Exception as e:
                    import traceback
                    self.log('[异常] %s' % e)
                    self.log(traceback.format_exc())

            threading.Thread(target=work, daemon=True).start()

    App().mainloop()


# =====================================================================
#  CLI 模式
# =====================================================================

def run_cli(argv):
    import argparse
    ap = argparse.ArgumentParser(description='OpenWrt 插件打包工具 (IPK/APK) v%s' % APP_VERSION)
    ap.add_argument('--version', action='version', version='%%(prog)s v%s' % APP_VERSION)
    ap.add_argument('--cli', action='store_true')
    ap.add_argument('--src', required=True, help='插件源码目录')
    ap.add_argument('--out', default=None, help='输出目录 (默认: 源码目录上一级)')
    ap.add_argument('--ipk', action='store_true', help='生成 IPK')
    ap.add_argument('--apk', action='store_true', help='生成 APK')
    ap.add_argument('--extract-po', action='store_true', help='提取/更新 po 翻译文件')
    ap.add_argument('--translate', action='store_true', help='自动翻译 po 空条目 (内置词典+在线)')
    ap.add_argument('--no-online', action='store_true', help='翻译时禁用在线 API (仅内置词典)')
    ap.add_argument('--i18n', action='store_true', help='生成 luci-i18n-xxx 中文语言包')
    args = ap.parse_args(argv)

    src = os.path.abspath(args.src)
    info = parse_makefile(os.path.join(src, 'Makefile'))
    files = collect_files(src)
    out = os.path.abspath(args.out) if args.out else os.path.dirname(src)
    os.makedirs(out, exist_ok=True)
    print('包名: %s 版本: %s-%s 架构: %s 文件: %d 个' %
          (info['name'], info['version'], info['release'], info['arch'], len(files)))
    domain = find_i18n_domain(src, info['name'])
    if args.extract_po:
        update_po(src, domain)
    if args.translate:
        auto_translate_po(po_path_of(src, domain), online=not args.no_online)
    if not args.ipk and not args.apk and not args.i18n:
        args.ipk = args.apk = True
    if args.ipk:
        build_ipk(info, files, out)
    if args.apk:
        build_apk(info, files, out)
    if args.i18n:
        build_i18n(info, src, out)


if __name__ == '__main__':
    if '--cli' in sys.argv:
        run_cli(sys.argv[1:])
    else:
        run_gui()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NV文件读取工具
根据udx710刷机程序源码分析编写
用于读取和提取NV文件中的nvitem数据

文件格式:
1. MULTI_CORE_NV_HEADER_T - 文件头部
   - dwMagic: 0x58444E49 ("INDX")
   - wVersion: 版本号
   - wCountCore: NV核心数量
2. NV_CORE_INFO_T数组 - 每个核心的信息
   - szCoreName[16]: 核心名称
   - dwDataOffset: 数据偏移
   - dwDataSize: 数据大小
3. NVItem数据 - 每个item包含ID和数据
"""

import struct
import sys
import os
import xml.etree.ElementTree as ET
from collections import OrderedDict

# 设置标准输出编码为UTF-8（Windows兼容性）
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 常量定义
INDEX_MAGIC = 0x58444E49  # "INDX"
UBI_NV_MAGIC = 0x00004E56  # "VN" (UBI格式)
INDEX_NV_ID = 0x0
PADDING_NV_ID = 0xFFFE
MAX_NV_CORE_NAME = 16
UBI_HEADER_SIZE = 0x200  # UBI格式头部大小

class NVHeader:
    """NV文件头部结构"""
    SIZE = 8  # DWORD + WORD + WORD
    
    def __init__(self, data):
        """解析头部"""
        self.magic, self.version, self.count_core = struct.unpack('<IHH', data[:self.SIZE])
        
    def is_valid(self):
        """检查magic是否有效"""
        return self.magic == INDEX_MAGIC
    
    def __repr__(self):
        return f"NVHeader(magic=0x{self.magic:08X}, version={self.version}, cores={self.count_core})"

class NVCoreInfo:
    """NV核心信息结构"""
    SIZE = 16 + 4 + 4  # char[16] + DWORD + DWORD
    
    def __init__(self, data):
        """解析核心信息"""
        # 解析核心名称(去除空字符)
        name_bytes = data[:16]
        self.core_name = name_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
        # 解析偏移和大小
        self.data_offset, self.data_size = struct.unpack('<II', data[16:24])
    
    def __repr__(self):
        return f"NVCore(name='{self.core_name}', offset=0x{self.data_offset:08X}, size=0x{self.data_size:08X})"

class NVItem:
    """NV Item结构"""
    
    def __init__(self, item_id, data, offset=0):
        """创建NV Item"""
        self.id = item_id
        self.data = data
        self.size = len(data)
        self.offset = offset  # 该item在文件中的偏移位置
    
    def __repr__(self):
        return f"NVItem(id=0x{self.id:04X}, size={self.size} bytes, offset=0x{self.offset:08X})"

class NVFile:
    """NV文件解析器"""
    
    def __init__(self, filepath):
        """初始化并读取NV文件"""
        self.filepath = filepath
        self.header = None
        self.cores = []
        self.items = OrderedDict()  # {core_name: {item_id: NVItem}}
        self._read_file()
    
    def _read_file(self):
        """读取并解析NV文件"""
        with open(self.filepath, 'rb') as f:
            # 读取文件头
            header_data = f.read(NVHeader.SIZE)
            self.header = NVHeader(header_data)
            
            # 检查是否是UBI格式
            if self.header.magic == UBI_NV_MAGIC:
                print(f"✓ 检测到UBI格式NV文件")
                self._read_ubi_format(f)
                return
            
            if not self.header.is_valid():
                raise ValueError(f"无效的NV文件: magic=0x{self.header.magic:08X}, 期望=0x{INDEX_MAGIC:08X}或0x{UBI_NV_MAGIC:08X}")
            
            print(f"✓ 文件头: {self.header}")
            
            # 读取核心信息
            for i in range(self.header.count_core):
                core_data = f.read(NVCoreInfo.SIZE)
                core = NVCoreInfo(core_data)
                self.cores.append(core)
                print(f"  核心 {i}: {core}")
            
            # 读取每个核心的NV items
            for core in self.cores:
                if core.data_size == 0:
                    continue
                
                # 定位到核心数据位置
                f.seek(core.data_offset)
                core_data = f.read(core.data_size)
                
                # 解析核心中的items，传入核心数据的偏移
                items = self._parse_core_items(core_data, core.data_offset)
                self.items[core.core_name] = items
                print(f"  ✓ 核心 '{core.core_name}' 包含 {len(items)} 个NV items")
    
    def _read_ubi_format(self, f):
        """读取UBI格式的NV文件"""
        # UBI格式: 头部0x200字节后是INDX结构，然后是数据
        f.seek(0)
        ubi_header = f.read(16)
        magic, total_size, data_size, item_count = struct.unpack('<IIII', ubi_header)
        
        print(f"  UBI头部: 总大小=0x{total_size:X}, 数据大小=0x{data_size:X}, Item数={item_count}")
        
        # 跳到0x200处查找INDX
        f.seek(UBI_HEADER_SIZE)
        # 先读一些数据查找INDX位置
        search_data = f.read(256)
        indx_offset = search_data.find(b'INDX')
        
        if indx_offset != -1:
            print(f"  ✓ 找到INDX at 0x{UBI_HEADER_SIZE + indx_offset:X}")
            f.seek(UBI_HEADER_SIZE + indx_offset)
            
            # 读取INDX header
            indx_data = f.read(NVHeader.SIZE)
            temp_header = NVHeader(indx_data)
            
            if temp_header.is_valid():
                print(f"  ✓ INDX头部: {temp_header}")
                self.header = temp_header
                
                # 读取核心信息
                for i in range(temp_header.count_core):
                    core_data = f.read(NVCoreInfo.SIZE)
                    core = NVCoreInfo(core_data)
                    self.cores.append(core)
                    print(f"    核心 {i}: {core}")
                
                # 读取每个核心的items
                for core in self.cores:
                    if core.data_size == 0:
                        continue
                    
                    f.seek(core.data_offset)
                    core_data = f.read(core.data_size)
                    items = self._parse_core_items(core_data, core.data_offset)
                    self.items[core.core_name] = items
                    print(f"    ✓ 核心 '{core.core_name}' 包含 {len(items)} 个NV items")
                return
        
        # 如果没有INDX，尝试直接解析items（简单格式）
        print(f"  警告: 未找到INDX结构，尝试简单格式解析")
        # 假设数据从0x800开始（根据分析结果）
        f.seek(0x800)
        all_data = f.read()
        items = self._parse_core_items(all_data, 0x800)
        self.items["default"] = items
        print(f"  ✓ 解析到 {len(items)} 个NV items")
        
        # 创建虚拟header
        self.header = NVHeader(struct.pack('<IHH', INDEX_MAGIC, 0, 1))
    
    def _parse_core_items(self, data, base_offset=0):
        """解析核心数据中的NV items
        
        NV item格式(从源码推断):
        - WORD: item ID
        - WORD: item length
        - BYTE[]: item data
        
        Args:
            data: 核心数据
            base_offset: 该核心数据在文件中的起始偏移
        """
        items = OrderedDict()
        offset = 0
        
        while offset + 4 <= len(data):
            # 记录当前item在文件中的绝对偏移
            item_file_offset = base_offset + offset
            
            # 读取item头部: ID (2字节) + Length (2字节)
            item_id, item_len = struct.unpack('<HH', data[offset:offset+4])
            offset += 4
            
            # 检查是否是结束标记或填充
            if item_id == PADDING_NV_ID or item_id == 0xFFFF:
                break
            
            # 读取item数据
            if offset + item_len <= len(data):
                item_data = data[offset:offset+item_len]
                offset += item_len
                
                # 可能有对齐填充
                # 对齐到4字节边界
                align = (4 - (item_len % 4)) % 4
                offset += align
                
                items[item_id] = NVItem(item_id, item_data, item_file_offset)
            else:
                print(f"  警告: Item 0x{item_id:04X} 数据长度超出范围")
                break
        
        return items
    
    def get_item(self, core_name, item_id):
        """获取指定核心的指定ID的NV item"""
        if core_name not in self.items:
            return None
        return self.items[core_name].get(item_id)
    
    def get_item_by_id(self, item_id):
        """在所有核心中查找指定ID的NV item"""
        for core_name, items in self.items.items():
            if item_id in items:
                return core_name, items[item_id]
        return None, None
    
    def list_all_items(self):
        """列出所有NV items"""
        print("\n" + "="*80)
        print("所有NV Items列表:")
        print("="*80)
        
        for core_name, items in self.items.items():
            print(f"\n核心: {core_name}")
            print("-" * 80)
            for item_id, item in items.items():
                print(f"  ID: 0x{item_id:04X} ({item_id:5d})  大小: {item.size:6d} 字节")
    
    def export_item(self, item_id, output_path):
        """导出指定ID的NV item到文件"""
        core_name, item = self.get_item_by_id(item_id)
        if item is None:
            print(f"错误: 未找到ID为 0x{item_id:04X} 的NV item")
            return False
        
        with open(output_path, 'wb') as f:
            f.write(item.data)
        
        print(f"✓ 已导出 NV item 0x{item_id:04X} (核心: {core_name}, 大小: {item.size} 字节)")
        print(f"  输出文件: {output_path}")
        return True
    
    def export_all_items(self, output_dir):
        """导出所有NV items到目录"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        total = 0
        for core_name, items in self.items.items():
            core_dir = os.path.join(output_dir, core_name)
            if not os.path.exists(core_dir):
                os.makedirs(core_dir)
            
            for item_id, item in items.items():
                filename = f"nvitem_0x{item_id:04X}_{item_id}.bin"
                filepath = os.path.join(core_dir, filename)
                with open(filepath, 'wb') as f:
                    f.write(item.data)
                total += 1
        
        print(f"✓ 已导出 {total} 个NV items 到目录: {output_dir}")
    
    def show_item_hex(self, item_id):
        """显示指定ID的NV item的十六进制内容"""
        core_name, item = self.get_item_by_id(item_id)
        if item is None:
            print(f"错误: 未找到ID为 0x{item_id:04X} 的NV item")
            return False
        
        print("\n" + "="*80)
        print(f"NV Item 详细信息:")
        print("="*80)
        print(f"ID:       0x{item_id:04X} ({item_id})")
        print(f"核心:     {core_name}")
        print(f"大小:     {item.size} 字节 (0x{item.size:X})")
        print(f"偏移:     0x{item.offset:08X} ({item.offset} 字节)")
        print(f"数据范围: 0x{item.offset:08X} - 0x{item.offset + 4 + item.size - 1:08X} (含头部4字节)")
        print("-"*80)
        print("十六进制内容:")
        print("-"*80)
        
        # 以16字节一行的格式显示十六进制
        data = item.data
        for i in range(0, len(data), 16):
            # 地址
            line = f"{i:08X}  "
            
            # 十六进制部分
            hex_part = ""
            ascii_part = ""
            for j in range(16):
                if i + j < len(data):
                    byte = data[i + j]
                    hex_part += f"{byte:02X} "
                    # ASCII显示(可打印字符)
                    if 32 <= byte <= 126:
                        ascii_part += chr(byte)
                    else:
                        ascii_part += "."
                else:
                    hex_part += "   "
                    ascii_part += " "
                
                # 每8字节加一个额外空格
                if j == 7:
                    hex_part += " "
            
            line += hex_part + " |" + ascii_part + "|"
            print(line)
        
        print("="*80)
        return True

class NVItemDefinition:
    """NV Item定义(从XML加载)"""
    
    def __init__(self, xml_path):
        """从XML文件加载NV item定义"""
        self.items = {}  # {item_id: item_name}
        self._load_xml(xml_path)
    
    def _load_xml(self, xml_path):
        """解析XML文件获取NV item定义"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # 查找NVBackup节点
            for nvbackup in root.findall('.//NVBackup'):
                for nvitem in nvbackup.findall('NVItem'):
                    name = nvitem.get('name', 'Unknown')
                    id_elem = nvitem.find('ID')
                    if id_elem is not None and id_elem.text:
                        # 解析ID(可能是十六进制)
                        id_text = id_elem.text.strip()
                        if id_text.startswith('0x') or id_text.startswith('0X'):
                            item_id = int(id_text, 16)
                        else:
                            item_id = int(id_text)
                        
                        self.items[item_id] = name
            
            print(f"✓ 从XML加载了 {len(self.items)} 个NV item定义")
        except Exception as e:
            print(f"警告: 加载XML文件失败: {e}")
    
    def get_name(self, item_id):
        """获取item名称"""
        return self.items.get(item_id, f"Unknown_0x{item_id:04X}")

def print_usage():
    """打印使用说明"""
    print("""
NV文件读取工具 - 基于udx710刷机程序源码分析

用法:
    python read_nvitem.py <nv_file> [选项]

选项:
    -l, --list              列出所有NV items
    -s, --show <id>         显示指定ID的NV item的十六进制内容 (例如: -s 0x9C4)
    -e, --export <id>       导出指定ID的NV item到文件 (例如: -e 0x9C4)
    -o, --output <path>     指定导出文件路径
    -a, --export-all <dir>  导出所有NV items到目录
    -x, --xml <xml_file>    指定XML配置文件(用于显示item名称)
    -h, --help              显示此帮助信息

示例:
    # 列出所有NV items
    python read_nvitem.py nvitem.bin -l
    
    # 显示指定ID的item的十六进制内容
    python read_nvitem.py nvitem.bin -s 0x9C4
    
    # 导出指定ID的item到文件
    python read_nvitem.py nvitem.bin -e 0x9C4 -o lte_cali.bin
    
    # 导出所有items
    python read_nvitem.py nvitem.bin -a output_dir
    
    # 使用XML配置显示item名称
    python read_nvitem.py nvitem.bin -l -x udx710-module.xml
""")

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print_usage()
        return 1
    
    # 检查是否是帮助参数
    if sys.argv[1] in ['-h', '--help']:
        print_usage()
        return 0
    
    nv_file = sys.argv[1]
    
    # 检查文件是否存在
    if not os.path.exists(nv_file):
        print(f"错误: 文件不存在: {nv_file}")
        return 1
    
    # 解析命令行参数
    args = sys.argv[2:]
    action = None
    export_id = None
    show_id = None
    output_path = None
    export_all_dir = None
    xml_file = None
    
    i = 0
    while i < len(args):
        arg = args[i]
        
        if arg in ['-h', '--help']:
            print_usage()
            return 0
        elif arg in ['-l', '--list']:
            action = 'list'
        elif arg in ['-s', '--show']:
            action = 'show'
            if i + 1 < len(args):
                id_str = args[i + 1]
                if id_str.startswith('0x') or id_str.startswith('0X'):
                    show_id = int(id_str, 16)
                else:
                    show_id = int(id_str)
                i += 1
        elif arg in ['-e', '--export']:
            action = 'export'
            if i + 1 < len(args):
                id_str = args[i + 1]
                if id_str.startswith('0x') or id_str.startswith('0X'):
                    export_id = int(id_str, 16)
                else:
                    export_id = int(id_str)
                i += 1
        elif arg in ['-o', '--output']:
            if i + 1 < len(args):
                output_path = args[i + 1]
                i += 1
        elif arg in ['-a', '--export-all']:
            action = 'export_all'
            if i + 1 < len(args):
                export_all_dir = args[i + 1]
                i += 1
        elif arg in ['-x', '--xml']:
            if i + 1 < len(args):
                xml_file = args[i + 1]
                i += 1
        i += 1
    
    # 解析NV文件
    print(f"读取NV文件: {nv_file}")
    print("="*80)
    
    try:
        nv = NVFile(nv_file)
        
        # 加载XML定义(如果提供)
        nv_defs = None
        if xml_file and os.path.exists(xml_file):
            print(f"\n加载XML配置: {xml_file}")
            nv_defs = NVItemDefinition(xml_file)
        
        # 执行操作
        if action == 'list':
            nv.list_all_items()
            
            # 如果有XML定义,显示名称映射
            if nv_defs:
                print("\n" + "="*80)
                print("NV Item名称映射 (来自XML):")
                print("="*80)
                for core_name, items in nv.items.items():
                    print(f"\n核心: {core_name}")
                    print("-" * 80)
                    for item_id in items.keys():
                        name = nv_defs.get_name(item_id)
                        print(f"  ID: 0x{item_id:04X} ({item_id:5d})  名称: {name}")
        
        elif action == 'show':
            if show_id is None:
                print("错误: 请指定要显示的item ID")
                return 1
            
            nv.show_item_hex(show_id)
            
            # 如果有XML定义,显示名称
            if nv_defs:
                name = nv_defs.get_name(show_id)
                print(f"名称: {name}")
        
        elif action == 'export':
            if export_id is None:
                print("错误: 请指定要导出的item ID")
                return 1
            
            if output_path is None:
                output_path = f"nvitem_0x{export_id:04X}.bin"
            
            nv.export_item(export_id, output_path)
        
        elif action == 'export_all':
            if export_all_dir is None:
                export_all_dir = 'nvitems_output'
            
            nv.export_all_items(export_all_dir)
        
        else:
            # 默认显示概要信息
            print("\n" + "="*80)
            print("NV文件概要:")
            print("="*80)
            print(f"文件路径: {nv_file}")
            print(f"文件大小: {os.path.getsize(nv_file)} 字节")
            print(f"核心数量: {len(nv.cores)}")
            total_items = sum(len(items) for items in nv.items.values())
            print(f"NV Items总数: {total_items}")
            print("\n提示: 使用 -l 参数列出所有items, 或 -h 查看帮助")
    
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

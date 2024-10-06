import pefile
from capstone import *

def get_function_ranges(pe):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    text_section = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    code = text_section.get_data()
    start_addr = text_section.VirtualAddress
    end_addr = start_addr + text_section.Misc_VirtualSize

    functions = []
    current_func = None

    insn_list = list(md.disasm(code, start_addr))

    i = 0
    while i < len(insn_list):
        insn = insn_list[i]
        if insn.mnemonic == 'push' and insn.op_str == 'rbp':
            # 向上搜索连续的push指令
            j = i - 1
            while j >= 0 and insn_list[j].mnemonic == 'push':
                j -= 1
            if current_func:
                functions.append(current_func)
            current_func = {'start': insn_list[j + 1].address, 'end': None}
        elif insn.mnemonic == 'mov' and insn.op_str == 'rbp, rsp':
            if current_func:
                functions.append(current_func)
            current_func = {'start': insn.address, 'end': None}
        if current_func:
            current_func['end'] = insn.address + insn.size
        i += 1

    if current_func:
        functions.append(current_func)

    return functions

def find_function_containing_address(functions, address):
    for func in functions:
        if func['start'] <= address < func['end']:
            return func
    return None

# 限定范围
def get_section_range_rva(pe, section_name):
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == section_name:
            return section.VirtualAddress, section.VirtualAddress + section.SizeOfRawData
    return None, None

def get_section_range_real(pe, section_name):
    (start,end) = get_section_range_rva(pe, section_name)
    if start and end:
        start += pe.OPTIONAL_HEADER.ImageBase
        end += pe.OPTIONAL_HEADER.ImageBase
        return start, end
    return None, None

def search_bytes(pe, start, end, bytes):
    for i in range(start, end+1):
        if pe.get_data(i, len(bytes)) == bytes:
            return i
    return None

# 暴力引用查找 汇编分析？不存在的

def search_data_maybe_xref_all(pe, string_rva, start, end):
    rva_list = []
    for i in range(start, end+1):
        if int.from_bytes(pe.get_data(i, 4), 'little',signed=True) + i + 4 == string_rva:
                rva_list.append(i)
    return rva_list

def search_data_maybe_xref(pe, string_rva, start, end):
    for i in range(start, end+1):
        if int.from_bytes(pe.get_data(i, 4), 'little',signed=True) + i + 4 == string_rva:
            return i
    return None

# search_data_maybe_xref和search_data_maybe_xref_all 忘记兼容上跳的情况了 已兼容
def search_call_maybe_xref(pe, string_rva, start, end):
    for i in range(start, end+1):
        if int.from_bytes(pe.get_data(i, 4), 'little',signed=True) + i + 4 == string_rva:
            return i
    return None

def search_data_pattern_all(pe, pattern, start, end):
    rva_list = []
    pattern = pattern.replace(' ', '').replace('0x', '').lower()
    for i in range(start, end+1):
        hex_data = ''.join(['%02x' % x for x in pe.get_data(i, len(pattern) // 2)])
        for j in range(0, len(pattern)):
            if pattern[j] != '?' and pattern[j] != hex_data[j]:
                break
        else:
            rva_list.append(i)
    return rva_list

def search_data_pattern(pe, pattern, start, end):
    pattern = pattern.replace(' ', '').replace('0x', '').lower()
    for i in range(start, end+1):
        hex_data = ''.join(['%02x' % x for x in pe.get_data(i, len(pattern) // 2)])
        for j in range(0, len(pattern)):
            if pattern[j] != '?' and pattern[j] != hex_data[j]:
                break
        else:
            return i
    return None

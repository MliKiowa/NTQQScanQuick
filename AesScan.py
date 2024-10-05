import pefile
from capstone import *

def get_function_ranges(pe):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    text_section = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    code = text_section.get_data()
    start_addr = text_section.VirtualAddress
    end_addr = start_addr + text_section.Misc_VirtualSize

    functions = []
    current_func = None

    for insn in md.disasm(code, start_addr):
        if insn.mnemonic == 'push' and insn.op_str == 'rbp':
            if current_func:
                functions.append(current_func)
            current_func = {'start': insn.address, 'end': None}
        if current_func:
            current_func['end'] = insn.address + insn.size

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
        if int.from_bytes(pe.get_data(i, 4), 'little') + i + 4 == string_rva:
                rva_list.append(i)
    return rva_list

def search_data_maybe_xref(pe, string_rva, start, end):
    for i in range(start, end+1):
        if int.from_bytes(pe.get_data(i, 4), 'little') + i + 4 == string_rva:
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
    return None

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

pe = pefile.PE("F:\\wrapper\\wrapper.28418.node")
pe_image_base = pe.OPTIONAL_HEADER.ImageBase
# 加载段区
section_rdata_range = get_section_range_rva(pe, '.rdata')
rdata_start, rdata_end = section_rdata_range

section_text_range = get_section_range_rva(pe, '.text')
text_start, text_end = section_text_range

# 分析AES Encrypt Function
offset_text_aes_encrypt = search_bytes(pe, rdata_start, rdata_end, b'AES_gcm_256_encrypt')
print('[debug] Maybe AES Encrypt Text: ',hex(offset_text_aes_encrypt+pe_image_base))

list_offset_aes_encrypt_xref = search_data_maybe_xref_all(pe, offset_text_aes_encrypt ,text_start,text_end)
list_offset_aes_encrypt_func = []
for offset_aes_encrypt in list_offset_aes_encrypt_xref:
    rva = find_function_containing_address(get_function_ranges(pe), offset_aes_encrypt)
    if rva:
        print('[debug] AES Encrypt Function: ',hex(rva['start']+pe_image_base))
        if rva['start'] in list_offset_aes_encrypt_func:
            continue
        list_offset_aes_encrypt_func.append(rva['start'])
print('[result] AES Encrypt Function: ',hex(list_offset_aes_encrypt_func[len(list_offset_aes_encrypt_func)-1]+pe_image_base))

# 分析AES Decrypt Function
offset_text_aes_decrypt = search_bytes(pe, rdata_start, rdata_end, b'AES_gcm_256_decrypt')
print('[debug] Maybe AES Decrypt Text: ',hex(offset_text_aes_decrypt+pe_image_base))

list_offset_aes_decrypt_xref = search_data_maybe_xref_all(pe, offset_text_aes_decrypt ,text_start,text_end)
list_offset_aes_decrypt_func = []
for offset_aes_decrypt in list_offset_aes_decrypt_xref:
    rva = find_function_containing_address(get_function_ranges(pe), offset_aes_decrypt)
    if rva:
        print('[debug] AES Decrypt Function: ',hex(rva['start']+pe_image_base))
        if rva['start'] in list_offset_aes_decrypt_func:
            continue
        list_offset_aes_decrypt_func.append(rva['start'])
print('[result] AES Decrypt Function: ',hex(list_offset_aes_decrypt_func[len(list_offset_aes_decrypt_func)-1]+pe_image_base))
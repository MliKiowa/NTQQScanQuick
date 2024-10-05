from quickScan import *

pe = pefile.PE("F:\\wrapper\\wrapper.28418.node")
pe_image_base = pe.OPTIONAL_HEADER.ImageBase
# 加载段区
section_rdata_range = get_section_range_rva(pe, '.rdata')
rdata_start, rdata_end = section_rdata_range

section_text_range = get_section_range_rva(pe, '.text')
text_start, text_end = section_text_range
# 分析函数
list_func_ranges = get_function_ranges(pe)

# delta = 0x9E3779B9 小端序
list_tea_detal = search_data_pattern_all(pe, 'B9 79 37 9E', text_start, text_end)
list_inner_crypt = []
for tea_detal in list_tea_detal:
    tea_crypt_inner = find_function_containing_address(list_func_ranges, tea_detal)
    if tea_crypt_inner:
        if tea_crypt_inner['start'] in list_inner_crypt:
            continue
        list_inner_crypt.append(tea_crypt_inner['start'])
        print('[debug] Maybe TEA Crypt Inner: ', hex(tea_crypt_inner['start']+pe_image_base))
        tea_crypt_outer = search_data_maybe_xref(pe, tea_crypt_inner['start'], text_start, text_end)
        print('[debug] Maybe TEA Crypt Outer: ', hex(tea_crypt_outer+pe_image_base))
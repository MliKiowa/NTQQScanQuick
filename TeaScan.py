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
list_pair_tea_detal = []
for index_detal in range(len(list_tea_detal)):
    offset_tea_detal = list_tea_detal[index_detal]
    next_offset_tea_detal = list_tea_detal[index_detal + 1 if index_detal + 1 < len(list_tea_detal) else index_detal]
    prev_offset_tea_detal = list_tea_detal[index_detal - 1 if index_detal - 1 >= 0 else index_detal]
    if next_offset_tea_detal - offset_tea_detal < 500 and offset_tea_detal - prev_offset_tea_detal != 0:
        list_pair_tea_detal.append((offset_tea_detal, next_offset_tea_detal))
    if offset_tea_detal - prev_offset_tea_detal < 500 and offset_tea_detal - next_offset_tea_detal != 0:
        list_pair_tea_detal.append((prev_offset_tea_detal, offset_tea_detal))

for pair_tea_detal in list_pair_tea_detal:
    print('[debug] TEA: ', hex(pair_tea_detal[0] + pe_image_base), hex(pair_tea_detal[1] + pe_image_base))


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

list_tea_detal.sort()
paired_list = [(list_tea_detal[i], list_tea_detal[i+1]) for i in range(0, len(list_tea_detal)-1, 2)]

max_distance = 500  # 设定一个最大允许的地址差距
filtered_paired_list = [pair for pair in paired_list if abs(pair[1] - pair[0]) <= max_distance]

# 按照地址差距从小到大排序
filtered_paired_list.sort(key=lambda pair: abs(pair[1] - pair[0]))

# 输出结果
print(filtered_paired_list)
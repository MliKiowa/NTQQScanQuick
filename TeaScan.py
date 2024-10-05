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

# 下面对地址预处理，找到最接近的两个地址
list_tea_detal_pair = []
for i in range(len(list_tea_detal)):
    min_diff = float('inf')
    closest_value = None
    for j in range(len(list_tea_detal)):
        if i != j:
            diff = abs(list_tea_detal[i] - list_tea_detal[j])
            if diff < min_diff:
                min_diff = diff
                closest_value = list_tea_detal[j]
    if min_diff <= 500:
        list_tea_detal_pair.append((list_tea_detal[i], closest_value))

# 去重
for i in range(len(list_tea_detal_pair)):
    for j in range(i+1, len(list_tea_detal_pair)):
        if list_tea_detal_pair[i][0] == list_tea_detal_pair[j][1] and list_tea_detal_pair[i][1] == list_tea_detal_pair[j][0]:
            list_tea_detal_pair[j] = (0, 0)

list_tea_detal_xref_func = []
for tea_detal_pair in list_tea_detal_pair:
    if tea_detal_pair[1] < tea_detal_pair[0]:
        tea_detal_pair = (tea_detal_pair[1], tea_detal_pair[0])
    # if tea_detal_pair[0] < 0x1000000 or tea_detal_pair[1] < 0x1000000:
    #     continue
    tea_encrypt = find_function_containing_address(list_func_ranges, tea_detal_pair[0])
    tea_decrypt = find_function_containing_address(list_func_ranges, tea_detal_pair[1])
    # 这里搜索到的是代码块 再来一次xref搜索
    if tea_encrypt and tea_decrypt:
        list_xref_encrypt_inner = search_data_maybe_xref_all(pe, tea_encrypt['start'], text_start, text_end)
        list_xref_decrypt_inner= search_data_maybe_xref_all(pe, tea_decrypt['start'], text_start, text_end)
        print('[debug] TEA Encrypt Function: ', hex(tea_encrypt['start']+pe_image_base))
        print('[debug] TEA Decrypt Function: ', hex(tea_decrypt['start']+pe_image_base))
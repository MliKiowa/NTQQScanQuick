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
    

# 分析AES Encrypt Function
offset_text_aes_encrypt = search_bytes(pe, rdata_start, rdata_end, b'AES_gcm_256_encrypt')
print('[debug] Maybe AES Encrypt Text: ',hex(offset_text_aes_encrypt+pe_image_base))

list_offset_aes_encrypt_xref = search_data_maybe_xref_all(pe, offset_text_aes_encrypt ,text_start,text_end)
list_offset_aes_encrypt_func = []
for offset_aes_encrypt in list_offset_aes_encrypt_xref:
    rva = find_function_containing_address(list_func_ranges, offset_aes_encrypt)
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
    rva = find_function_containing_address(list_func_ranges, offset_aes_decrypt)
    if rva:
        print('[debug] AES Decrypt Function: ',hex(rva['start']+pe_image_base))
        if rva['start'] in list_offset_aes_decrypt_func:
            continue
        list_offset_aes_decrypt_func.append(rva['start'])
print('[result] AES Decrypt Function: ',hex(list_offset_aes_decrypt_func[len(list_offset_aes_decrypt_func)-1]+pe_image_base))
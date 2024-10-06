# NTQQScanQuick
快速对NTQQ进行Scan分析Offset

## 特点
- [x] 几乎不受版本约束？
- [x] 速度遥遥领先IDA！
- [x] 暴力的方法就是豪.

## 进度
- [x] Aes Scan
- [x] 业务Tea Scan
- [x] 登录Tea Scan

## 运行
修改 pe 文件地址即刻分析

## 存在的小问题
-[x] 已修复: 由于get_function_ranges实现 导致部分函数定位的是push rbp位置 距离目标函数还有几字节

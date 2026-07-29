# DevEnv
coreLib for multi-purpose use


# Benchmark
> Single-thread | Intel i5-11300H @ 4.0GHz (3.0 GHz base frequence) | MSVC /O2

Run on(8 X 3110 MHz CPU s)
CPU Caches :
L1 Data 48 KiB(x4)
L1 Instruction 32 KiB(x4)
L2 Unified 1280 KiB(x4)
L3 Unified 8192 KiB(x1)


Run on(8 X 3110 MHz CPU s)
CPU Caches :
L1 Data 48 KiB(x4)
L1 Instruction 32 KiB(x4)
L2 Unified 1280 KiB(x4)
L3 Unified 8192 KiB(x1)

| Benchmark | Time | CPU | Iterations
| -----------|------|----|---------------------------------------------------------------------|
| ECB_AES_128_Encrypt 16_mean | 9.30 ns | 9.29 ns | bytes_per_second = 1.60385Gi / s|
| ECB_AES_128_Encrypt 16_median | 9.26 ns | 9.24 ns | bytes_per_second = 1.61225Gi / s|
| ECB_AES_128_Encrypt 16_stddev | 0.201 ns | 0.202 ns | bytes_per_second = 35.5318Mi / s|
| ECB_AES_128_Encrypt 16_cv | 2.16 % | 2.18 % | bytes_per_second = 2.16 % |
| ECB_AES_128_Encrypt 256_mean | 14.7 ns | 14.6 ns | bytes_per_second = 16.6705Gi / s|
| ECB_AES_128_Encrypt 256_median | 13.7 ns | 13.7 ns | bytes_per_second = 17.4632Gi / s|
| ECB_AES_128_Encrypt 256_stddev | 2.88 ns | 2.75 ns | bytes_per_second = 2.20738Gi / s|
| ECB_AES_128_Encrypt 256_cv | 19.58 % | 18.80 % | bytes_per_second = 13.24 % |
| ECB_AES_128_Encrypt 4096_mean | 156 ns | 156 ns | bytes_per_second = 24.4807Gi / s|
| ECB_AES_128_Encrypt 4096_median | 155 ns | 153 ns | bytes_per_second = 24.858Gi / s|
| ECB_AES_128_Encrypt 4096_stddev | 2.80 ns | 3.69 ns | bytes_per_second = 578.551Mi / s|
| ECB_AES_128_Encrypt 4096_cv | 1.80 % | 2.37 % | bytes_per_second = 2.31 % |
| ECB_AES_128_Encrypt 65536_mean | 2441 ns | 2433 ns | bytes_per_second = 25.0971Gi / s|
| ECB_AES_128_Encrypt 65536_median | 2431 ns | 2427 ns | bytes_per_second = 25.147Gi / s|
| ECB_AES_128_Encrypt 65536_stddev | 29.9 ns | 53.9 ns | bytes_per_second = 568.748Mi / s|
| ECB_AES_128_Encrypt 65536_cv | 1.22 % | 2.22 % | bytes_per_second = 2.21 % |
| ECB_AES_128_Encrypt 1048576_mean | 38963 ns | 38801 ns | bytes_per_second = 25.1768Gi / s|
| ECB_AES_128_Encrypt 1048576_median | 38823 ns | 38801 ns | bytes_per_second = 25.1717Gi / s|
| ECB_AES_128_Encrypt 1048576_stddev | 417 ns | 741 ns | bytes_per_second = 492.72Mi / s|
| ECB_AES_128_Encrypt 1048576_cv | 1.07 % | 1.91 % | bytes_per_second = 1.91 % |
| ECB_AES_128_Encrypt 33554432_mean | 3343656 ns | 3315728 ns | bytes_per_second = 9.4371Gi / s|
| ECB_AES_128_Encrypt 33554432_median | 3316370 ns | 3301056 ns | bytes_per_second = 9.46667Gi / s|
| ECB_AES_128_Encrypt 33554432_stddev | 106948 ns | 128462 ns | bytes_per_second = 362.173Mi / s|
| ECB_AES_128_Encrypt 33554432_cv | 3.20 % | 3.87 % | bytes_per_second = 3.75 % |

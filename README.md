# DevEnv
coreLib for multi-purpose use


# Benchmark
> Single-thread | Intel i5-11300H @ 4.0GHz (3.0 GHz base frequence) | MSVC /O2
> Comparison: OpenSSL 4.0.0 AES-256-ECB ~9.68 GB/s (AES-NI, no VAES)

| Variant        | Buffer   | Throughput |
|----------------|----------|------------|
| ECB_AES<256>   | >8192 B  | 18 GB/s    |
| ECB_AES<128>   | >8192 B  | 25 GB/s    |
| ECB_AES<256>   | 2048 B   | 17 GB/s    |
| ECB_AES<128>   | 2048 B   | 24 GB/s    |

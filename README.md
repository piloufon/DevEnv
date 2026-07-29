# DevEnv

**coreLib for multi-purpose use** — a C++ core library with low-level system utilities and cryptography

## Contents
- [Benchmarks](#benchmarks)
  - [ECB_AES\<128\>](#ecb_aes128)
- [License](#license)

## Benchmarks

> Single-thread | Intel i5-11300H @ 4.0 GHz turbo (3.0 GHz base) | Clang `/O2`

### ECB_AES\<128\>

| Plaintext size | Mean time  | Debit        |
|----------------:|-----------:|-------------:|
| 16 B            | 9.32 ns    | 1.60 GiB/s   |
| 256 B           | 13.4 ns    | 17.82 GiB/s  |
| 4 KB            | 155 ns     | 24.64 GiB/s  |
| 64 KB           | 2.45 µs    | 25.06 GiB/s  |
| 1 MB            | 39.35 µs   | 24.96 GiB/s  |
| 32 MB           | 3.20 ms    | 9.83 GiB/s   |

<details>
<summary>Full statistics (time/CPU mean ± stddev, throughput, cv)</summary>

> Google Benchmark with 35 iterations and a crappy warm up

| Plaintext size | Time (mean ± stddev)    | CPU (mean ± stddev)     | Throughput (mean ± stddev) | cv     |
|----------------:|-------------------------:|-------------------------:|----------------------------:|-------:|
| 16 B            | 9.32 ns ± 0.318 ns       | 9.30 ns ± 0.342 ns       | 1.605 GiB/s ± 56.79 MiB/s   | 3.46 % |
| 256 B           | 13.4 ns ± 0.389 ns       | 13.4 ns ± 0.430 ns       | 17.82 GiB/s ± 538.7 MiB/s   | 2.95 % |
| 4 KB            | 155 ns ± 1.84 ns         | 155 ns ± 2.42 ns         | 24.64 GiB/s ± 392.7 MiB/s   | 1.56 % |
| 64 KB           | 2448 ns ± 42.2 ns        | 2436 ns ± 54.3 ns        | 25.06 GiB/s ± 561.7 MiB/s   | 2.19 % |
| 1 MB            | 39354 ns ± 856 ns        | 39137 ns ± 891 ns        | 24.96 GiB/s ± 574.0 MiB/s   | 2.25 % |
| 32 MB           | 3202660 ns ± 183707 ns   | 3187877 ns ± 178221 ns   | 9.829 GiB/s ± 496.1 MiB/s   | 4.93 % |

</details>


## License

**All right reserved**

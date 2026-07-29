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
| 16 B            | 9.30 ns    | 1.60 GiB/s   |
| 256 B           | 14.7 ns    | 16.67 GiB/s  |
| 4 KB            | 156 ns     | 24.48 GiB/s  |
| 64 KB           | 2.44 µs    | 25.10 GiB/s  |
| 1 MB            | 38.96 µs   | 25.18 GiB/s  |
| 32 MB           | 3.34 ms    | 9.44 GiB/s   |

<details>
<summary>Full statistics (time/CPU mean ± stddev, throughput, cv)</summary>

| Plaintext size | Time (mean ± stddev)   | CPU (mean ± stddev)    | Throughput (mean ± stddev) | cv      |
|----------------:|------------------------:|------------------------:|----------------------------:|--------:|
| 16 B            | 9.30 ns ± 0.201 ns      | 9.29 ns ± 0.202 ns      | 1.604 GiB/s ± 35.53 MiB/s   | 2.16 %  |
| 256 B           | 14.7 ns ± 2.88 ns       | 14.6 ns ± 2.75 ns       | 16.67 GiB/s ± 2.207 GiB/s   | 19.58 % |
| 4 KB            | 156 ns ± 2.80 ns        | 156 ns ± 3.69 ns        | 24.48 GiB/s ± 578.6 MiB/s   | 1.80 %  |
| 64 KB           | 2441 ns ± 29.9 ns       | 2433 ns ± 53.9 ns       | 25.10 GiB/s ± 568.7 MiB/s   | 1.22 %  |
| 1 MB            | 38963 ns ± 417 ns       | 38801 ns ± 741 ns       | 25.18 GiB/s ± 492.7 MiB/s   | 1.07 %  |
| 32 MB           | 3343656 ns ± 106948 ns  | 3315728 ns ± 128462 ns  | 9.437 GiB/s ± 362.2 MiB/s   | 3.20 %  |

</details>


## License

**All right reserved**

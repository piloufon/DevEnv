#pragma once
#include <cstdint>

class CPUFeatures {
public:
    static uint32_t physical_cores() { return m_cpu.physical_cores; }
    static uint32_t logical_cores() { return m_cpu.logical_cores; }

    static bool has_aes_ni() { return m_cpu.aes_ni; }
    static bool has_pclmul() { return m_cpu.pclmul; }

    static bool has_sse() { return m_cpu.sse; }
    static bool has_sse2() { return m_cpu.sse2; }
    static bool has_sse3() { return m_cpu.sse3; }
    static bool has_sse4_1() { return m_cpu.sse4_1; }
    static bool has_sse4_2() { return m_cpu.sse4_2; }
    static bool has_fma() { return m_cpu.fma; }
    static bool has_avx() { return m_cpu.avx; }
    static bool has_avx2() { return m_cpu.avx2; }
    static bool has_avx512f() { return m_cpu.avx512f; }
    static bool has_avx512bw() { return m_cpu.avx512bw; }
    static bool has_avx512dq() { return m_cpu.avx512dq; }

private:
    struct CPU {
        uint32_t physical_cores = 0;
        uint32_t logical_cores = 0;

        bool aes_ni = false;
        bool pclmul = false;

        bool sse = false;
        bool sse2 = false;
        bool sse3 = false;
        bool sse4_1 = false;
        bool sse4_2 = false;
        bool fma = false;
        bool avx = false;
        bool avx2 = false;
        bool avx512f = false;
        bool avx512bw = false;
        bool avx512dq = false;
    };

    static CPU detect();
    static const CPU m_cpu;
};

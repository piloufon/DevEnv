#include "../../include/utils/CPUFeatures.h"
#include <thread>

#ifdef _MSC_VER
#include <intrin.h>
static void cpuid(int info[4], int leaf) { __cpuid(info, leaf); }
static void cpuidex(int info[4], int leaf, int sub) { __cpuidex(info, leaf, sub); }
#else
#include <cpuid.h>
static void cpuid(int info[4], int leaf) {
    __cpuid(leaf, info[0], info[1], info[2], info[3]);
}
static void cpuidex(int info[4], int leaf, int sub) {
    __cpuid_count(leaf, sub, info[0], info[1], info[2], info[3]);
}
#endif

const CPUFeatures::CPU CPUFeatures::m_cpu = CPUFeatures::detect();

CPUFeatures::CPU CPUFeatures::detect() {
    CPU f{};
    int info[4] = {};

    cpuid(info, 0);
    int max_leaf = info[0];

    if (max_leaf < 1)
        return f;

    cpuid(info, 1);
    f.sse = (info[3] & (1 << 25)) != 0;
    f.sse2 = (info[3] & (1 << 26)) != 0;
    f.sse3 = (info[2] & (1 << 0)) != 0;
    f.pclmul = (info[2] & (1 << 1)) != 0;
    f.sse4_1 = (info[2] & (1 << 19)) != 0;
    f.sse4_2 = (info[2] & (1 << 20)) != 0;
    f.aes_ni = (info[2] & (1 << 25)) != 0;
    f.avx = (info[2] & (1 << 28)) != 0;
    f.fma = (info[2] & (1 << 12)) != 0;

    if (max_leaf >= 7) {
        cpuidex(info, 7, 0);
        f.avx2 = (info[1] & (1 << 5)) != 0;
        f.avx512f = (info[1] & (1 << 16)) != 0;
        f.avx512dq = (info[1] & (1 << 17)) != 0;
        f.avx512bw = (info[1] & (1 << 30)) != 0;
        f.vaes = (info[2] & (1 << 9)) != 0;
    }

    f.logical_cores = std::thread::hardware_concurrency();

    if (max_leaf >= 0xB) {
        cpuidex(info, 0xB, 1);
        uint32_t logical_per_package = info[1] & 0xFFFF;
        if (logical_per_package > 0)
            f.physical_cores = f.logical_cores / 2;
        else
            f.physical_cores = f.logical_cores;
    }
    else {
        f.physical_cores = f.logical_cores;
    }

    return f;
}

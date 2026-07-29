#include "../../include/crypto/CTR_AES.h"
#include "../../include/utils/CPUFeatures.h"
#include "AES_helper.h"
#include <memory>
#include <bit>
#include <immintrin.h>

// Uses pshufb and paddd (2 more reg, so 2 more movdqu)
// Cost 2 xmm registers, but have a 2 Go/s diff over a pinsrd in general reg (with aes-ni on an i5-11300, but should be pretty consistant on every CPU)
// Also there is no pipelining because the gain isn't that useful (and CTR isn't used a lot, the ECB version was just for understanding)
template <size_t NR>
inline void aes_encrypt(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size, std::span<const uint8_t, 16> nonce) {
    alignas(16) static constexpr uint8_t bswap_mask[16] = { 0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12 };
    alignas(16) static constexpr uint32_t inc_vec[4] = { 0, 0, 0, 1 };
    
    if constexpr (NR == 10) {
        __asm__ volatile (
            "movdqu (%[p_nonce]), %%xmm1\n\t"
            "movdqu (%[p_bswap]), %%xmm2\n\t"
            "movdqu (%[p_inc]),   %%xmm3\n\t"


            "movdqu    (%[p_rk]), %%xmm4\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"
            "movdqu  32(%[p_rk]), %%xmm6\n\t"
            "movdqu  48(%[p_rk]), %%xmm7\n\t"
            "movdqu  64(%[p_rk]), %%xmm8\n\t"
            "movdqu  80(%[p_rk]), %%xmm9\n\t"
            "movdqu  96(%[p_rk]), %%xmm10\n\t"
            "movdqu 112(%[p_rk]), %%xmm11\n\t"
            "movdqu 128(%[p_rk]), %%xmm12\n\t"
            "movdqu 144(%[p_rk]), %%xmm13\n\t"
            "movdqu 160(%[p_rk]), %%xmm14\n\t"

            "0:\n\t"
            "movdqa  %%xmm1, %%xmm0\n\t"
            "pshufb  %%xmm2, %%xmm0\n\t" 

            "pxor    %%xmm4,  %%xmm0\n\t"
            "aesenc  %%xmm5,  %%xmm0\n\t"
            "aesenc  %%xmm6,  %%xmm0\n\t"
            "aesenc  %%xmm7,  %%xmm0\n\t"
            "aesenc  %%xmm8,  %%xmm0\n\t"
            "aesenc  %%xmm9,  %%xmm0\n\t"
            "aesenc  %%xmm10,  %%xmm0\n\t"
            "aesenc  %%xmm11,  %%xmm0\n\t"
            "aesenc  %%xmm12,  %%xmm0\n\t"
            "aesenc  %%xmm13, %%xmm0\n\t"
            "aesenclast %%xmm14, %%xmm0\n\t"

            "pxor    (%[p_in]), %%xmm0\n\t"
            "movdqu  %%xmm0, (%[p_out])\n\t"

            "paddd   %%xmm3, %%xmm1\n\t"
            "addq    $16, %[p_in]\n\t"
            "addq    $16, %[p_out]\n\t"
            "subq    $16, %[size]\n\t"
            "jnz     0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "movdqu (%[p_nonce]), %%xmm1\n\t"
            "movdqu (%[p_bswap]), %%xmm2\n\t"
            "movdqu (%[p_inc]),   %%xmm3\n\t"


            "movdqu    (%[p_rk]), %%xmm4\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"
            "movdqu  32(%[p_rk]), %%xmm6\n\t"
            "movdqu  48(%[p_rk]), %%xmm7\n\t"
            "movdqu  64(%[p_rk]), %%xmm8\n\t"
            "movdqu  80(%[p_rk]), %%xmm9\n\t"
            "movdqu  96(%[p_rk]), %%xmm10\n\t"
            "movdqu 112(%[p_rk]), %%xmm11\n\t"
            "movdqu 128(%[p_rk]), %%xmm12\n\t"
            "movdqu 144(%[p_rk]), %%xmm13\n\t"
            "movdqu 160(%[p_rk]), %%xmm14\n\t"
            "movdqu 176(%[p_rk]), %%xmm15\n\t"

            "0:\n\t"
            "movdqa  %%xmm1, %%xmm0\n\t"
            "pshufb  %%xmm2, %%xmm0\n\t"

            "pxor    %%xmm4,  %%xmm0\n\t"
            "aesenc  %%xmm5,  %%xmm0\n\t"
            "aesenc  %%xmm6,  %%xmm0\n\t"
            "aesenc  %%xmm7,  %%xmm0\n\t"
            "aesenc  %%xmm8,  %%xmm0\n\t"
            "aesenc  %%xmm9,  %%xmm0\n\t"
            "movdqu  192(%[p_rk]), %%xmm5\n\t"
            "aesenc  %%xmm10,  %%xmm0\n\t"
            "aesenc  %%xmm11,  %%xmm0\n\t"
            "aesenc  %%xmm12,  %%xmm0\n\t"
            "aesenc  %%xmm13, %%xmm0\n\t"
            "aesenc  %%xmm14, %%xmm0\n\t"
            "aesenc  %%xmm15, %%xmm0\n\t"
            "aesenclast %%xmm5, %%xmm0\n\t"

            "pxor    (%[p_in]), %%xmm0\n\t"
            "movdqu  %%xmm0, (%[p_out])\n\t"

            "paddd   %%xmm3, %%xmm1\n\t"
            "addq    $16, %[p_in]\n\t"
            "addq    $16, %[p_out]\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"

            "subq    $16, %[size]\n\t"
            "jnz     0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14", "xmm15",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "movdqu (%[p_nonce]), %%xmm1\n\t"
            "movdqu (%[p_bswap]), %%xmm2\n\t"
            "movdqu (%[p_inc]),   %%xmm3\n\t"

            "movdqu    (%[p_rk]), %%xmm4\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"
            "movdqu  32(%[p_rk]), %%xmm6\n\t"
            "movdqu  48(%[p_rk]), %%xmm7\n\t"
            "movdqu  64(%[p_rk]), %%xmm8\n\t"
            "movdqu  80(%[p_rk]), %%xmm9\n\t"
            "movdqu  96(%[p_rk]), %%xmm10\n\t"
            "movdqu 112(%[p_rk]), %%xmm11\n\t"
            "movdqu 128(%[p_rk]), %%xmm12\n\t"
            "movdqu 144(%[p_rk]), %%xmm13\n\t"
            "movdqu 160(%[p_rk]), %%xmm14\n\t"
            "movdqu 176(%[p_rk]), %%xmm15\n\t"

            "0:\n\t"
            "movdqa  %%xmm1, %%xmm0\n\t"
            "pshufb  %%xmm2, %%xmm0\n\t"

            "pxor    %%xmm4,  %%xmm0\n\t"
            "aesenc  %%xmm5,  %%xmm0\n\t"
            "movdqu 192(%[p_rk]), %%xmm4\n\t"
            "aesenc  %%xmm6,  %%xmm0\n\t"
            "aesenc  %%xmm7,  %%xmm0\n\t"
            "movdqu 208(%[p_rk]), %%xmm5\n\t"
            "aesenc  %%xmm8,  %%xmm0\n\t"
            "aesenc  %%xmm9,  %%xmm0\n\t"
            "movdqu 224(%[p_rk]), %%xmm6\n\t"
            "aesenc  %%xmm10, %%xmm0\n\t"
            "aesenc  %%xmm11, %%xmm0\n\t"
            "aesenc  %%xmm12, %%xmm0\n\t"
            "aesenc  %%xmm13, %%xmm0\n\t"
            "aesenc  %%xmm14, %%xmm0\n\t"
            "aesenc  %%xmm15, %%xmm0\n\t"
            "aesenc  %%xmm4,  %%xmm0\n\t"
            "aesenc  %%xmm5,  %%xmm0\n\t"
            "aesenclast %%xmm6, %%xmm0\n\t"
            "movdqu    (%[p_rk]), %%xmm4\n\t"

            "pxor    (%[p_in]), %%xmm0\n\t"
            "movdqu  %%xmm0, (%[p_out])\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"

            "paddd   %%xmm3, %%xmm1\n\t"
            "addq    $16, %[p_in]\n\t"
            "addq    $16, %[p_out]\n\t"

            "movdqu  32(%[p_rk]), %%xmm6\n\t"

            "subq    $16, %[size]\n\t"
            "jnz     0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14", "xmm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void vaes256_encrypt(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size, std::span<const uint8_t, 16> nonce) {
    alignas(16) static constexpr uint8_t bswap_mask[16] = { 0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12 };
    alignas(16) static constexpr uint32_t init_off[4] = { 0, 0, 0, 1 };
    alignas(16) static constexpr uint32_t inc_vec[8] = { 0, 0, 0, 2, 0, 0, 0, 2 };

    if constexpr (NR == 10) {
        __asm__ volatile (
            "vbroadcasti128 (%[p_nonce]), %%ymm1\n\t"
            "vbroadcasti128 (%[p_bswap]), %%ymm2\n\t"
            "vmovdqu (%[p_inc]), %%ymm3\n\t"

            "vpaddd (%[p_init_off]), %%xmm1, %%xmm5\n\t"
            "vinserti128 $1, %%xmm5, %%ymm1, %%ymm1\n\t"

            "vbroadcasti128 (%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm14\n\t"

            "0:\n\t"
            "vmovdqa %%ymm1, %%ymm0\n\t"
            "vpshufb %%ymm2, %%ymm0, %%ymm0\n\t"

            "vpxor %%ymm4,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm5,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm6,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm7,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm8,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm9,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm14, %%ymm0, %%ymm0\n\t"

            "vpxor (%[p_in]), %%ymm0, %%ymm0\n\t"
            "vmovdqu %%ymm0, (%[p_out])\n\t"

            "vpaddd %%ymm3, %%ymm1, %%ymm1\n\t"
            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"
            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec),
            [p_init_off] "r"(init_off)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti128 (%[p_nonce]), %%ymm1\n\t"
            "vbroadcasti128 (%[p_bswap]), %%ymm2\n\t"
            "vmovdqu (%[p_inc]), %%ymm3\n\t"

            "vpaddd (%[p_init_off]), %%xmm1, %%xmm5\n\t"
            "vinserti128 $1, %%xmm5, %%ymm1, %%ymm1\n\t"

            "vbroadcasti128    (%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm14\n\t"
            "vbroadcasti128 176(%[p_rk]), %%ymm15\n\t"

            "0:\n\t"
            "vmovdqa %%ymm1, %%ymm0\n\t"
            "vpshufb %%ymm2, %%ymm0, %%ymm0\n\t"

            "vpxor   %%ymm4,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm5,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm6,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm7,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm8,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm9,  %%ymm0, %%ymm0\n\t"

            "vbroadcasti128 192(%[p_rk]), %%ymm4\n\t"

            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm15, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm4, %%ymm0, %%ymm0\n\t"

            "vpxor (%[p_in]), %%ymm0, %%ymm0\n\t"
            "vmovdqu %%ymm0, (%[p_out])\n\t"

            "vpaddd %%ymm3, %%ymm1, %%ymm1\n\t"
            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"

            "vbroadcasti128 (%[p_rk]), %%ymm4\n\t"

            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec),
            [p_init_off] "r"(init_off)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14", "ymm15",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti128 (%[p_nonce]), %%ymm1\n\t"
            "vbroadcasti128 (%[p_bswap]), %%ymm2\n\t"
            "vmovdqu (%[p_inc]), %%ymm3\n\t"

            "vpaddd (%[p_init_off]), %%xmm1, %%xmm5\n\t"
            "vinserti128 $1, %%xmm5, %%ymm1, %%ymm1\n\t"

            "vbroadcasti128    (%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm14\n\t"
            "vbroadcasti128 176(%[p_rk]), %%ymm15\n\t"

            "0:\n\t"
            "vmovdqa %%ymm1, %%ymm0\n\t"
            "vpshufb %%ymm2, %%ymm0, %%ymm0\n\t"

            "vpxor   %%ymm4,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm5,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm6,  %%ymm0, %%ymm0\n\t"

            "vbroadcasti128 192(%[p_rk]), %%ymm4\n\t"

            "vaesenc %%ymm7,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm8,  %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm9,  %%ymm0, %%ymm0\n\t"

            "vbroadcasti128 208(%[p_rk]), %%ymm5\n\t"

            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm12, %%ymm0, %%ymm0\n\t"

            "vbroadcasti128 224(%[p_rk]), %%ymm6\n\t"

            "vaesenc %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm15, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm4, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm6, %%ymm0, %%ymm0\n\t"

            "vpxor (%[p_in]), %%ymm0, %%ymm0\n\t"
            "vmovdqu %%ymm0, (%[p_out])\n\t"

            "vbroadcasti128 (%[p_rk]), %%ymm4\n\t"

            "vpaddd %%ymm3, %%ymm1, %%ymm1\n\t"

            "vbroadcasti128  16(%[p_rk]), %%ymm5\n\t"

            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"

            "vbroadcasti128  32(%[p_rk]), %%ymm6\n\t"

            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec),
            [p_init_off] "r"(init_off)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14", "ymm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void vaes512_encrypt(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size, std::span<const uint8_t, 16> nonce) {
    alignas(16) static constexpr uint8_t bswap_mask[16] = { 0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12 };
    alignas(16) static constexpr uint32_t init_off[16] = { 0,0,0,0, 0,0,0,1, 0,0,0,2, 0,0,0,3 };
    alignas(16) static constexpr uint32_t inc_vec[16] = { 0,0,0,4, 0,0,0,4, 0,0,0,4, 0,0,0,4 };

    if constexpr (NR == 10) {
        __asm__ volatile (
            "vbroadcasti32x4 (%[p_nonce]), %%zmm1\n\t"
            "vbroadcasti32x4 (%[p_bswap]), %%zmm2\n\t"
            "vmovdqu64 (%[p_inc]), %%zmm3\n\t"
            "vpaddd (%[p_init_off]), %%zmm1, %%zmm1\n\t"

            "vbroadcasti32x4    (%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm14\n\t"

            "0:\n\t"
            "vmovdqa64 %%zmm1, %%zmm0\n\t"
            "vpshufb %%zmm2, %%zmm0, %%zmm0\n\t"

            "vpxord %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm14, %%zmm0, %%zmm0\n\t"

            "vpxord (%[p_in]), %%zmm0, %%zmm0\n\t"
            "vmovdqu64 %%zmm0, (%[p_out])\n\t"

            "vpaddd %%zmm3, %%zmm1, %%zmm1\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec),
            [p_init_off] "r"(init_off)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti32x4 (%[p_nonce]), %%zmm1\n\t"
            "vbroadcasti32x4 (%[p_bswap]), %%zmm2\n\t"
            "vmovdqu64 (%[p_inc]), %%zmm3\n\t"
            "vpaddd (%[p_init_off]), %%zmm1, %%zmm1\n\t"

            "vbroadcasti32x4    (%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm14\n\t"
            "vbroadcasti32x4 176(%[p_rk]), %%zmm15\n\t"
            "vbroadcasti32x4 192(%[p_rk]), %%zmm16\n\t"

            "0:\n\t"
            "vmovdqa64 %%zmm1, %%zmm0\n\t"
            "vpshufb %%zmm2, %%zmm0, %%zmm0\n\t"

            "vpxord %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm15, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm16, %%zmm0, %%zmm0\n\t"

            "vpxord (%[p_in]), %%zmm0, %%zmm0\n\t"
            "vmovdqu64 %%zmm0, (%[p_out])\n\t"

            "vpaddd %%zmm3, %%zmm1, %%zmm1\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec),
            [p_init_off] "r"(init_off)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14", "zmm15",
            "zmm16",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti32x4 (%[p_nonce]), %%zmm1\n\t"
            "vbroadcasti32x4 (%[p_bswap]), %%zmm2\n\t"
            "vmovdqu64 (%[p_inc]), %%zmm3\n\t"
            "vpaddd (%[p_init_off]), %%zmm1, %%zmm1\n\t"

            "vbroadcasti32x4    (%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm14\n\t"
            "vbroadcasti32x4 176(%[p_rk]), %%zmm15\n\t"
            "vbroadcasti32x4 192(%[p_rk]), %%zmm16\n\t"
            "vbroadcasti32x4 208(%[p_rk]), %%zmm17\n\t"
            "vbroadcasti32x4 224(%[p_rk]), %%zmm18\n\t"

            "0:\n\t"
            "vmovdqa64 %%zmm1, %%zmm0\n\t"
            "vpshufb %%zmm2, %%zmm0, %%zmm0\n\t"

            "vpxord %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm15, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm16, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm17, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm18, %%zmm0, %%zmm0\n\t"

            "vpxord (%[p_in]), %%zmm0, %%zmm0\n\t"
            "vmovdqu64 %%zmm0, (%[p_out])\n\t"

            "vpaddd %%zmm3, %%zmm1, %%zmm1\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey), [p_nonce] "r"(nonce.data()),
            [p_bswap] "r"(bswap_mask), [p_inc] "r"(inc_vec),
            [p_init_off] "r"(init_off)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14", "zmm15",
            "zmm16", "zmm17", "zmm18",
            "memory", "cc"
            );
    }
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
CTR_AES<N>::CTR_AES(const Key& key) {
    expand_key<N>(key, m_rkey);
    // No need for m_rkey_inv
}

enum ReturnValue : size_t {
    Success = 0,
    CounterOverflow = 1,
    InvalidOutputSize = 2,
};

template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
const char* CTR_AES<N>::get_error_message(size_t err) {
    switch (err) {
        case Success:
            return "Success";
        case InvalidOutputSize:
            return "InvalidOutputSize";
        case CounterOverflow:
            return "CounterOverflow";
        default:
            return "Unkown";
    }
}

using caes_fn = void(*)(const uint8_t*, uint8_t*, const uint8_t*, size_t, std::span<const uint8_t, 16>);
template <caes_fn func>
inline void process_chunk(const uint8_t* in, uint8_t* out, const uint8_t* rkey, std::span<uint8_t, 16> base, size_t& i, size_t numBlocks, size_t multiple, uint32_t counter_start) {
    size_t blocks = ((numBlocks - i) / multiple) * multiple;
    if (blocks > 0) {
        uint32_t temp = static_cast<uint32_t>(i) + counter_start;
        std::memcpy(base.data() + 12, &temp, 4); // Cast to bytes then offset to lowerbound of a uint64_t
        func(in + i * 16, out + i * 16, rkey, blocks * 16, base);
        i += blocks;
    }
}

template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
inline size_t CTR_AES<N>::encrypt(std::span<const uint8_t> in, std::span<uint8_t> out, std::span<const uint8_t, 12> nonce, uint32_t counter_start) const {
    size_t num_blocks = in.size() / 16;
    size_t remainder = in.size() % 16;

    if (((in.size() + 15) / 16) > (uint64_t)((UINT32_MAX)-counter_start) + 1) {
        return CounterOverflow;
    }

    alignas(16) std::array<uint8_t, 16> base = { 0 };
    std::memcpy(base.data(), nonce.data(), 12);
    if (in.size() > out.size()) {
        return InvalidOutputSize;
    }
    
    size_t i = 0;

    if (CPUFeatures::has_vaes512()) {
        process_chunk<vaes512_encrypt<NR>>(in.data(), out.data(), m_rkey.data(), base, i, num_blocks, 4, counter_start);
    }
    if (CPUFeatures::has_vaes()) {
        process_chunk<vaes256_encrypt<NR>>(in.data(), out.data(), m_rkey.data(), base, i, num_blocks, 2, counter_start);
    }
    if (CPUFeatures::has_aes_ni()) {
        process_chunk<aes_encrypt<NR>>(in.data(), out.data(), m_rkey.data(), base, i, num_blocks, 1, counter_start);
    }
    else if (i < num_blocks) {
        for (; i < num_blocks; i++) {
            alignas(16) std::array<uint8_t, 16> counter_block = { 0 };
            std::memcpy(counter_block.data(), nonce.data(), 12);
            uint32_t ctr = std::byteswap(counter_start + static_cast<uint32_t>(i));
            std::memcpy(counter_block.data() + 12, &ctr, 4);

            for (uint8_t j = 0; j < 16; j++)
                counter_block[j] ^= m_rkey[j];

            for (size_t round = 1; round < NR; ++round) {
                sub_bytes(counter_block);
                shift_rows(counter_block);
                mix_columns(counter_block);
                for (uint8_t j = 0; j < 16; j++)
                    counter_block[j] ^= m_rkey[round * 16 + j];
            }

            sub_bytes(counter_block);
            shift_rows(counter_block);
            for (uint8_t j = 0; j < 16; j++)
                counter_block[j] ^= m_rkey[NR * 16 + j];

            for (uint8_t j = 0; j < 16; j++)
                out[i * 16 + j] = counter_block[j] ^ in[i * 16 + j];
        }
    }

    if (remainder > 0) {
        alignas(16) std::array<uint8_t, 16> counter_block = { 0 };
        std::memcpy(counter_block.data(), nonce.data(), 12);
        uint32_t ctr = std::byteswap(counter_start + static_cast<uint32_t>(num_blocks));
        std::memcpy(counter_block.data() + 12, &ctr, 4);

        for (uint8_t j = 0; j < 16; j++)
            counter_block[j] ^= m_rkey[j];

        for (size_t round = 1; round < NR; ++round) {
            sub_bytes(counter_block);
            shift_rows(counter_block);
            mix_columns(counter_block);
            for (uint8_t j = 0; j < 16; j++)
                counter_block[j] ^= m_rkey[round * 16 + j];
        }

        sub_bytes(counter_block);
        shift_rows(counter_block);
        for (uint8_t j = 0; j < 16; j++)
            counter_block[j] ^= m_rkey[NR * 16 + j];

        for (size_t j = 0; j < remainder; j++)
            out[num_blocks * 16 + j] = counter_block[j] ^ in[num_blocks * 16 + j];
    }

    return Success;
}

template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
inline size_t CTR_AES<N>::encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counter_start) const {
    if (in.size() > out.size()) {
        out.resize(in.size());
    }
    return encrypt(in, std::span<uint8_t>(out), nonce, counter_start);
}


template class CTR_AES<128>;
template class CTR_AES<192>;
template class CTR_AES<256>;
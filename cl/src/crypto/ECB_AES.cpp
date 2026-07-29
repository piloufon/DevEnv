//#include <immintrin.h>
#include <memory>
#include <span>
#include <array>
#include "AES_helper.h"
#include "../../include/crypto/ECB_AES.h"
#include "../../include/utils/CPUFeatures.h"

template <size_t NR>
inline void aes_encrypt(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm1\n\t"
            "movdqu  16(%[p_rk]), %%xmm2\n\t"
            "movdqu  32(%[p_rk]), %%xmm3\n\t"
            "movdqu  48(%[p_rk]), %%xmm4\n\t"
            "movdqu  64(%[p_rk]), %%xmm5\n\t"
            "movdqu  80(%[p_rk]), %%xmm6\n\t"
            "movdqu  96(%[p_rk]), %%xmm7\n\t"
            "movdqu 112(%[p_rk]), %%xmm8\n\t"
            "movdqu 128(%[p_rk]), %%xmm9\n\t"
            "movdqu 144(%[p_rk]), %%xmm10\n\t"
            "movdqu 160(%[p_rk]), %%xmm11\n\t"

            // Loadu pt
            "0:"
            "movdqu (%[p_in]), %%xmm0\n\t"

            // Encrypt
            "pxor   %%xmm1,  %%xmm0\n\t"
            "aesenc %%xmm2,  %%xmm0\n\t"
            "aesenc %%xmm3,  %%xmm0\n\t"
            "aesenc %%xmm4,  %%xmm0\n\t"
            "aesenc %%xmm5,  %%xmm0\n\t"
            "aesenc %%xmm6,  %%xmm0\n\t"
            "aesenc %%xmm7,  %%xmm0\n\t"
            "aesenc %%xmm8,  %%xmm0\n\t"
            "aesenc %%xmm9,  %%xmm0\n\t"
            "aesenc %%xmm10, %%xmm0\n\t"

            "aesenclast %%xmm11, %%xmm0\n\t"

            // Storeu ct
            "movdqu %%xmm0, (%[p_out])\n\t"
            "addq $16, %[p_in]\n\t"
            "addq $16, %[p_out]\n\t"

            "subq $16, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm1\n\t"
            "movdqu  16(%[p_rk]), %%xmm2\n\t"
            "movdqu  32(%[p_rk]), %%xmm3\n\t"
            "movdqu  48(%[p_rk]), %%xmm4\n\t"
            "movdqu  64(%[p_rk]), %%xmm5\n\t"
            "movdqu  80(%[p_rk]), %%xmm6\n\t"
            "movdqu  96(%[p_rk]), %%xmm7\n\t"
            "movdqu 112(%[p_rk]), %%xmm8\n\t"
            "movdqu 128(%[p_rk]), %%xmm9\n\t"
            "movdqu 144(%[p_rk]), %%xmm10\n\t"
            "movdqu 160(%[p_rk]), %%xmm11\n\t"
            "movdqu 176(%[p_rk]), %%xmm12\n\t"
            "movdqu 192(%[p_rk]), %%xmm13\n\t"

            // Loadu pt
            "0:"
            "movdqu (%[p_in]), %%xmm0\n\t"

            // Encrypt
            "pxor   %%xmm1,  %%xmm0\n\t"
            "aesenc %%xmm2,  %%xmm0\n\t"
            "aesenc %%xmm3,  %%xmm0\n\t"
            "aesenc %%xmm4,  %%xmm0\n\t"
            "aesenc %%xmm5,  %%xmm0\n\t"
            "aesenc %%xmm6,  %%xmm0\n\t"
            "aesenc %%xmm7,  %%xmm0\n\t"
            "aesenc %%xmm8,  %%xmm0\n\t"
            "aesenc %%xmm9,  %%xmm0\n\t"
            "aesenc %%xmm10, %%xmm0\n\t"
            "aesenc %%xmm11, %%xmm0\n\t"
            "aesenc %%xmm12, %%xmm0\n\t"


            "aesenclast %%xmm13, %%xmm0\n\t"

            // Storeu ct
            "movdqu %%xmm0, (%[p_out])\n\t"
            "addq $16, %[p_in]\n\t"
            "addq $16, %[p_out]\n\t"

            "subq $16, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm1\n\t"
            "movdqu  16(%[p_rk]), %%xmm2\n\t"
            "movdqu  32(%[p_rk]), %%xmm3\n\t"
            "movdqu  48(%[p_rk]), %%xmm4\n\t"
            "movdqu  64(%[p_rk]), %%xmm5\n\t"
            "movdqu  80(%[p_rk]), %%xmm6\n\t"
            "movdqu  96(%[p_rk]), %%xmm7\n\t"
            "movdqu 112(%[p_rk]), %%xmm8\n\t"
            "movdqu 128(%[p_rk]), %%xmm9\n\t"
            "movdqu 144(%[p_rk]), %%xmm10\n\t"
            "movdqu 160(%[p_rk]), %%xmm11\n\t"
            "movdqu 176(%[p_rk]), %%xmm12\n\t"
            "movdqu 192(%[p_rk]), %%xmm13\n\t"
            "movdqu 208(%[p_rk]), %%xmm14\n\t"
            "movdqu 224(%[p_rk]), %%xmm15\n\t"

            // Loadu pt
            "0:"
            "movdqu (%[p_in]), %%xmm0\n\t"

            // Encrypt
            "pxor   %%xmm1,  %%xmm0\n\t"
            "aesenc %%xmm2,  %%xmm0\n\t"
            "aesenc %%xmm3,  %%xmm0\n\t"
            "aesenc %%xmm4,  %%xmm0\n\t"
            "aesenc %%xmm5,  %%xmm0\n\t"
            "aesenc %%xmm6,  %%xmm0\n\t"
            "aesenc %%xmm7,  %%xmm0\n\t"
            "aesenc %%xmm8,  %%xmm0\n\t"
            "aesenc %%xmm9,  %%xmm0\n\t"
            "aesenc %%xmm10, %%xmm0\n\t"
            "aesenc %%xmm11, %%xmm0\n\t"
            "aesenc %%xmm12, %%xmm0\n\t"
            "aesenc %%xmm13, %%xmm0\n\t"
            "aesenc %%xmm14, %%xmm0\n\t"


            "aesenclast %%xmm15, %%xmm0\n\t"

            // Storeu ct
            "movdqu %%xmm0, (%[p_out])\n\t"
            "addq $16, %[p_in]\n\t"
            "addq $16, %[p_out]\n\t"

            "subq $16, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14", "xmm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void aes_encryptx4(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
            // Loadu rkey
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

            // Loadu pt
            "0:"
            "movdqu   (%[p_in]), %%xmm0\n\t"
            "movdqu 16(%[p_in]), %%xmm1\n\t"
            "movdqu 32(%[p_in]), %%xmm2\n\t"
            "movdqu 48(%[p_in]), %%xmm3\n\t"

            // Encrypt
            "pxor   %%xmm4,  %%xmm0\n\t"
            "pxor   %%xmm4,  %%xmm1\n\t"
            "pxor   %%xmm4,  %%xmm2\n\t"
            "pxor   %%xmm4,  %%xmm3\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"

            "aesenc %%xmm6, %%xmm0\n\t"
            "aesenc %%xmm6, %%xmm1\n\t"
            "aesenc %%xmm6, %%xmm2\n\t"
            "aesenc %%xmm6, %%xmm3\n\t"

            "aesenc %%xmm7, %%xmm0\n\t"
            "aesenc %%xmm7, %%xmm1\n\t"
            "aesenc %%xmm7, %%xmm2\n\t"
            "aesenc %%xmm7, %%xmm3\n\t"

            "aesenc %%xmm8, %%xmm0\n\t"
            "aesenc %%xmm8, %%xmm1\n\t"
            "aesenc %%xmm8, %%xmm2\n\t"
            "aesenc %%xmm8, %%xmm3\n\t"

            "aesenc %%xmm9, %%xmm0\n\t"
            "aesenc %%xmm9, %%xmm1\n\t"
            "aesenc %%xmm9, %%xmm2\n\t"
            "aesenc %%xmm9, %%xmm3\n\t"

            "aesenc %%xmm10, %%xmm0\n\t"
            "aesenc %%xmm10, %%xmm1\n\t"
            "aesenc %%xmm10, %%xmm2\n\t"
            "aesenc %%xmm10, %%xmm3\n\t"

            "aesenc %%xmm11, %%xmm0\n\t"
            "aesenc %%xmm11, %%xmm1\n\t"
            "aesenc %%xmm11, %%xmm2\n\t"
            "aesenc %%xmm11, %%xmm3\n\t"

            "aesenc %%xmm12, %%xmm0\n\t"
            "aesenc %%xmm12, %%xmm1\n\t"
            "aesenc %%xmm12, %%xmm2\n\t"
            "aesenc %%xmm12, %%xmm3\n\t"

            "aesenc %%xmm13, %%xmm0\n\t"
            "aesenc %%xmm13, %%xmm1\n\t"
            "aesenc %%xmm13, %%xmm2\n\t"
            "aesenc %%xmm13, %%xmm3\n\t"

            "aesenclast %%xmm14, %%xmm0\n\t"
            "aesenclast %%xmm14, %%xmm1\n\t"
            "aesenclast %%xmm14, %%xmm2\n\t"
            "aesenclast %%xmm14, %%xmm3\n\t"

            // Storeu ct
            "movdqu %%xmm0,   (%[p_out])\n\t"
            "movdqu %%xmm1, 16(%[p_out])\n\t"
            "movdqu %%xmm2, 32(%[p_out])\n\t"
            "movdqu %%xmm3, 48(%[p_out])\n\t"

            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"

            "subq $64, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm4\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"
            "movdqu  32(%[p_rk]), %%xmm6\n\t"
            "movdqu  48(%[p_rk]), %%xmm7\n\t"
            "movdqu  64(%[p_rk]), %%xmm8\n\t"
            "movdqu  80(%[p_rk]), %%xmm9\n\t"
            "movdqu 112(%[p_rk]), %%xmm11\n\t"
            "movdqu 128(%[p_rk]), %%xmm12\n\t"
            "movdqu 144(%[p_rk]), %%xmm13\n\t"
            "movdqu 160(%[p_rk]), %%xmm14\n\t"
            "movdqu 176(%[p_rk]), %%xmm15\n\t"

            // Loadu pt
            "0:"
            "movdqu   (%[p_in]), %%xmm0\n\t"
            "movdqu 16(%[p_in]), %%xmm1\n\t"
            "movdqu 32(%[p_in]), %%xmm2\n\t"
            "movdqu 48(%[p_in]), %%xmm3\n\t"

            // Encrypt
            "pxor   %%xmm4,  %%xmm0\n\t"
            "pxor   %%xmm4,  %%xmm1\n\t"
            "pxor   %%xmm4,  %%xmm2\n\t"
            "pxor   %%xmm4,  %%xmm3\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"

            "movdqu  96(%[p_rk]), %%xmm10\n\t"

            "aesenc %%xmm6, %%xmm0\n\t"
            "aesenc %%xmm6, %%xmm1\n\t"
            "aesenc %%xmm6, %%xmm2\n\t"
            "aesenc %%xmm6, %%xmm3\n\t"

            "aesenc %%xmm7, %%xmm0\n\t"
            "aesenc %%xmm7, %%xmm1\n\t"
            "aesenc %%xmm7, %%xmm2\n\t"
            "aesenc %%xmm7, %%xmm3\n\t"

            "aesenc %%xmm8, %%xmm0\n\t"
            "aesenc %%xmm8, %%xmm1\n\t"
            "aesenc %%xmm8, %%xmm2\n\t"
            "aesenc %%xmm8, %%xmm3\n\t"

            "aesenc %%xmm9, %%xmm0\n\t"
            "aesenc %%xmm9, %%xmm1\n\t"
            "aesenc %%xmm9, %%xmm2\n\t"
            "aesenc %%xmm9, %%xmm3\n\t"

            "aesenc %%xmm10, %%xmm0\n\t"
            "aesenc %%xmm10, %%xmm1\n\t"
            "aesenc %%xmm10, %%xmm2\n\t"
            "aesenc %%xmm10, %%xmm3\n\t"

            "movdqu  192(%[p_rk]), %%xmm10\n\t"

            "aesenc %%xmm11, %%xmm0\n\t"
            "aesenc %%xmm11, %%xmm1\n\t"
            "aesenc %%xmm11, %%xmm2\n\t"
            "aesenc %%xmm11, %%xmm3\n\t"

            "aesenc %%xmm12, %%xmm0\n\t"
            "aesenc %%xmm12, %%xmm1\n\t"
            "aesenc %%xmm12, %%xmm2\n\t"
            "aesenc %%xmm12, %%xmm3\n\t"

            "aesenc %%xmm13, %%xmm0\n\t"
            "aesenc %%xmm13, %%xmm1\n\t"
            "aesenc %%xmm13, %%xmm2\n\t"
            "aesenc %%xmm13, %%xmm3\n\t"

            "aesenc %%xmm14, %%xmm0\n\t"
            "aesenc %%xmm14, %%xmm1\n\t"
            "aesenc %%xmm14, %%xmm2\n\t"
            "aesenc %%xmm14, %%xmm3\n\t"

            "aesenc %%xmm15, %%xmm0\n\t"
            "aesenc %%xmm15, %%xmm1\n\t"
            "aesenc %%xmm15, %%xmm2\n\t"
            "aesenc %%xmm15, %%xmm3\n\t"

            "aesenclast %%xmm10, %%xmm0\n\t"
            "aesenclast %%xmm10, %%xmm1\n\t"
            "aesenclast %%xmm10, %%xmm2\n\t"
            "aesenclast %%xmm10, %%xmm3\n\t"

            // Storeu ct
            "movdqu %%xmm0,   (%[p_out])\n\t"
            "movdqu %%xmm1, 16(%[p_out])\n\t"
            "movdqu %%xmm2, 32(%[p_out])\n\t"
            "movdqu %%xmm3, 48(%[p_out])\n\t"

            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"

            "subq $64, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14", "xmm15",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm4\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"
            "movdqu  32(%[p_rk]), %%xmm6\n\t"
            "movdqu  64(%[p_rk]), %%xmm8\n\t"
            "movdqu  96(%[p_rk]), %%xmm10\n\t"
            "movdqu 112(%[p_rk]), %%xmm11\n\t"
            "movdqu 128(%[p_rk]), %%xmm12\n\t"
            "movdqu 144(%[p_rk]), %%xmm13\n\t"
            "movdqu 160(%[p_rk]), %%xmm14\n\t"

            // Loadu pt
            "0:"
            "movdqu   (%[p_in]), %%xmm0\n\t"
            "movdqu 16(%[p_in]), %%xmm1\n\t"
            "movdqu 32(%[p_in]), %%xmm2\n\t"
            "movdqu 48(%[p_in]), %%xmm3\n\t"

            // Encrypt
            "pxor   %%xmm4,  %%xmm0\n\t"
            "pxor   %%xmm4,  %%xmm1\n\t"
            "pxor   %%xmm4,  %%xmm2\n\t"
            "pxor   %%xmm4,  %%xmm3\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"

            "movdqu  48(%[p_rk]), %%xmm7\n\t"

            "aesenc %%xmm6, %%xmm0\n\t"
            "aesenc %%xmm6, %%xmm1\n\t"
            "aesenc %%xmm6, %%xmm2\n\t"
            "aesenc %%xmm6, %%xmm3\n\t"

            "aesenc %%xmm7, %%xmm0\n\t"
            "aesenc %%xmm7, %%xmm1\n\t"
            "aesenc %%xmm7, %%xmm2\n\t"
            "aesenc %%xmm7, %%xmm3\n\t"

            "movdqu  80(%[p_rk]), %%xmm9\n\t"

            "aesenc %%xmm8, %%xmm0\n\t"
            "aesenc %%xmm8, %%xmm1\n\t"
            "aesenc %%xmm8, %%xmm2\n\t"
            "aesenc %%xmm8, %%xmm3\n\t"

            "aesenc %%xmm9, %%xmm0\n\t"
            "aesenc %%xmm9, %%xmm1\n\t"
            "aesenc %%xmm9, %%xmm2\n\t"
            "aesenc %%xmm9, %%xmm3\n\t"

            "movdqu  192(%[p_rk]), %%xmm7\n\t"

            "aesenc %%xmm10, %%xmm0\n\t"
            "aesenc %%xmm10, %%xmm1\n\t"
            "aesenc %%xmm10, %%xmm2\n\t"
            "aesenc %%xmm10, %%xmm3\n\t"

            "aesenc %%xmm11, %%xmm0\n\t"
            "aesenc %%xmm11, %%xmm1\n\t"
            "aesenc %%xmm11, %%xmm2\n\t"
            "aesenc %%xmm11, %%xmm3\n\t"

            "movdqu  208(%[p_rk]), %%xmm9\n\t"

            "aesenc %%xmm12, %%xmm0\n\t"
            "aesenc %%xmm12, %%xmm1\n\t"
            "aesenc %%xmm12, %%xmm2\n\t"
            "aesenc %%xmm12, %%xmm3\n\t"

            "aesenc %%xmm13, %%xmm0\n\t"
            "aesenc %%xmm13, %%xmm1\n\t"
            "aesenc %%xmm13, %%xmm2\n\t"
            "aesenc %%xmm13, %%xmm3\n\t"

            "movdqu 176(%[p_rk]), %%xmm15\n\t"

            "aesenc %%xmm14, %%xmm0\n\t"
            "aesenc %%xmm14, %%xmm1\n\t"
            "aesenc %%xmm14, %%xmm2\n\t"
            "aesenc %%xmm14, %%xmm3\n\t"

            "aesenc %%xmm15, %%xmm0\n\t"
            "aesenc %%xmm15, %%xmm1\n\t"
            "aesenc %%xmm15, %%xmm2\n\t"
            "aesenc %%xmm15, %%xmm3\n\t"

            "aesenc %%xmm7, %%xmm0\n\t"
            "aesenc %%xmm7, %%xmm1\n\t"
            "aesenc %%xmm7, %%xmm2\n\t"
            "aesenc %%xmm7, %%xmm3\n\t"

            "movdqu 224(%[p_rk]), %%xmm15\n\t"

            "aesenc %%xmm9, %%xmm0\n\t"
            "aesenc %%xmm9, %%xmm1\n\t"
            "aesenc %%xmm9, %%xmm2\n\t"
            "aesenc %%xmm9, %%xmm3\n\t"

            "aesenclast %%xmm15, %%xmm0\n\t"
            "aesenclast %%xmm15, %%xmm1\n\t"
            "aesenclast %%xmm15, %%xmm2\n\t"
            "aesenclast %%xmm15, %%xmm3\n\t"

            // Storeu ct
            "movdqu %%xmm0,   (%[p_out])\n\t"
            "movdqu %%xmm1, 16(%[p_out])\n\t"
            "movdqu %%xmm2, 32(%[p_out])\n\t"
            "movdqu %%xmm3, 48(%[p_out])\n\t"

            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"

            "subq $64, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14", "xmm15",
            "memory", "cc"
            );
    }

}
template <size_t NR>
inline void vaes256_encryptx2(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm1\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm2\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm3\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm11\n\t"

            "0:\n\t"
            "vmovdqu (%[p_in]), %%ymm0\n\t"

            "vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm2, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm3, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm4, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm11, %%ymm0, %%ymm0\n\t"

            "vmovdqu %%ymm0, (%[p_out])\n\t"
            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"
            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm1\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm2\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm3\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 176(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 192(%[p_rk]), %%ymm13\n\t"

            "0:\n\t"
            "vmovdqu (%[p_in]), %%ymm0\n\t"

            "vpxor    %%ymm1, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm2, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm3, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm4, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm13, %%ymm0, %%ymm0\n\t"

            "vmovdqu %%ymm0, (%[p_out])\n\t"
            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"
            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm1\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm2\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm3\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 176(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 192(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 208(%[p_rk]), %%ymm14\n\t"
            "vbroadcasti128 224(%[p_rk]), %%ymm15\n\t"

            "0:\n\t"
            "vmovdqu (%[p_in]), %%ymm0\n\t"

            "vpxor    %%ymm1, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm2, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm3, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm4, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesenc  %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm15, %%ymm0, %%ymm0\n\t"

            "vmovdqu %%ymm0, (%[p_out])\n\t"
            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"
            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14", "ymm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void vaes256_encryptx8(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
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

            "0:\n\t"
            "vmovdqu    (%[p_in]), %%ymm0\n\t"
            "vmovdqu  32(%[p_in]), %%ymm1\n\t"
            "vmovdqu  64(%[p_in]), %%ymm2\n\t"
            "vmovdqu  96(%[p_in]), %%ymm3\n\t"

            "vpxor %%ymm4, %%ymm0, %%ymm0\n\t"
            "vpxor %%ymm4, %%ymm1, %%ymm1\n\t"
            "vpxor %%ymm4, %%ymm2, %%ymm2\n\t"
            "vpxor %%ymm4, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm5, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm5, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm5, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm6, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm6, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm6, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm7, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm7, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm7, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm9, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm9, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm9, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm10, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm10, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm10, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm11, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm11, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm11, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm12, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm12, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm12, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm13, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm13, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm13, %%ymm3, %%ymm3\n\t"

            "vaesenclast %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm14, %%ymm1, %%ymm1\n\t"
            "vaesenclast %%ymm14, %%ymm2, %%ymm2\n\t"
            "vaesenclast %%ymm14, %%ymm3, %%ymm3\n\t"

            "vmovdqu %%ymm0,   (%[p_out])\n\t"
            "vmovdqu %%ymm1, 32(%[p_out])\n\t"
            "vmovdqu %%ymm2, 64(%[p_out])\n\t"
            "vmovdqu %%ymm3, 96(%[p_out])\n\t"

            "addq $128, %[p_in]\n\t"
            "addq $128, %[p_out]\n\t"
            "subq $128, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm14\n\t"
            "vbroadcasti128 176(%[p_rk]), %%ymm15\n\t"

            "0:\n\t"
            "vmovdqu   (%[p_in]), %%ymm0\n\t"
            "vmovdqu 32(%[p_in]), %%ymm1\n\t"
            "vmovdqu 64(%[p_in]), %%ymm2\n\t"
            "vmovdqu 96(%[p_in]), %%ymm3\n\t"

            "vpxor %%ymm4, %%ymm0, %%ymm0\n\t"
            "vpxor %%ymm4, %%ymm1, %%ymm1\n\t"
            "vpxor %%ymm4, %%ymm2, %%ymm2\n\t"
            "vpxor %%ymm4, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm5, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm5, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm5, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128  96(%[p_rk]), %%ymm10\n\t"

            "vaesenc %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm6, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm6, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm6, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm7, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm7, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm7, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm9, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm9, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm9, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm10, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm10, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm10, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 192(%[p_rk]), %%ymm10\n\t"

            "vaesenc %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm11, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm11, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm11, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm12, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm12, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm12, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm13, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm13, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm13, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm14, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm14, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm14, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm15, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm15, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm15, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm15, %%ymm3, %%ymm3\n\t"

            "vaesenclast %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm10, %%ymm1, %%ymm1\n\t"
            "vaesenclast %%ymm10, %%ymm2, %%ymm2\n\t"
            "vaesenclast %%ymm10, %%ymm3, %%ymm3\n\t"

            "vmovdqu %%ymm0,   (%[p_out])\n\t"
            "vmovdqu %%ymm1, 32(%[p_out])\n\t"
            "vmovdqu %%ymm2, 64(%[p_out])\n\t"
            "vmovdqu %%ymm3, 96(%[p_out])\n\t"

            "addq $128, %[p_in]\n\t"
            "addq $128, %[p_out]\n\t"
            "subq $128, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14", "ymm15",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm14\n\t"

            "0:\n\t"
            "vmovdqu   (%[p_in]), %%ymm0\n\t"
            "vmovdqu 32(%[p_in]), %%ymm1\n\t"
            "vmovdqu 64(%[p_in]), %%ymm2\n\t"
            "vmovdqu 96(%[p_in]), %%ymm3\n\t"

            "vpxor %%ymm4, %%ymm0, %%ymm0\n\t"
            "vpxor %%ymm4, %%ymm1, %%ymm1\n\t"
            "vpxor %%ymm4, %%ymm2, %%ymm2\n\t"
            "vpxor %%ymm4, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm5, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm5, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm5, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128  48(%[p_rk]), %%ymm7\n\t"

            "vaesenc %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm6, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm6, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm6, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm7, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm7, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm7, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128  80(%[p_rk]), %%ymm9\n\t"

            "vaesenc %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm8, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm8, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm8, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm9, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm9, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm9, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 192(%[p_rk]), %%ymm7\n\t"

            "vaesenc %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm10, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm10, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm10, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm11, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm11, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm11, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 208(%[p_rk]), %%ymm9\n\t"

            "vaesenc %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm12, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm12, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm12, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm13, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm13, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm13, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 176(%[p_rk]), %%ymm15\n\t"

            "vaesenc %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm14, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm14, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm14, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm15, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm15, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm15, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm15, %%ymm3, %%ymm3\n\t"

            "vaesenc %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm7, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm7, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm7, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 224(%[p_rk]), %%ymm15\n\t"

            "vaesenc %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesenc %%ymm9, %%ymm1, %%ymm1\n\t"
            "vaesenc %%ymm9, %%ymm2, %%ymm2\n\t"
            "vaesenc %%ymm9, %%ymm3, %%ymm3\n\t"

            "vaesenclast %%ymm15, %%ymm0, %%ymm0\n\t"
            "vaesenclast %%ymm15, %%ymm1, %%ymm1\n\t"
            "vaesenclast %%ymm15, %%ymm2, %%ymm2\n\t"
            "vaesenclast %%ymm15, %%ymm3, %%ymm3\n\t"

            "vmovdqu %%ymm0,   (%[p_out])\n\t"
            "vmovdqu %%ymm1, 32(%[p_out])\n\t"
            "vmovdqu %%ymm2, 64(%[p_out])\n\t"
            "vmovdqu %%ymm3, 96(%[p_out])\n\t"

            "addq $128, %[p_in]\n\t"
            "addq $128, %[p_out]\n\t"
            "subq $128, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14", "ymm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void vaes512_encryptx4(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm1\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm2\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm3\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm11\n\t"

            "0:\n\t"
            "vmovdqu64 (%[p_in]), %%zmm0\n\t"

            "vpxord   %%zmm1,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm2,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm3,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm11, %%zmm0, %%zmm0\n\t"

            "vmovdqu64 %%zmm0, (%[p_out])\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm1\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm2\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm3\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 176(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 192(%[p_rk]), %%zmm13\n\t"

            "0:\n\t"
            "vmovdqu64 (%[p_in]), %%zmm0\n\t"

            "vpxord   %%zmm1,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm2,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm3,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm13, %%zmm0, %%zmm0\n\t"

            "vmovdqu64 %%zmm0, (%[p_out])\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm1\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm2\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm3\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 176(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 192(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 208(%[p_rk]), %%zmm14\n\t"
            "vbroadcasti32x4 224(%[p_rk]), %%zmm15\n\t"

            "0:\n\t"
            "vmovdqu64 (%[p_in]), %%zmm0\n\t"

            "vpxord   %%zmm1,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm2,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm3,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesenc  %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm15, %%zmm0, %%zmm0\n\t"

            "vmovdqu64 %%zmm0, (%[p_out])\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14", "zmm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void vaes512_encryptx16(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
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
            "vmovdqu64    (%[p_in]), %%zmm0\n\t"
            "vmovdqu64  64(%[p_in]), %%zmm1\n\t"
            "vmovdqu64 128(%[p_in]), %%zmm2\n\t"
            "vmovdqu64 192(%[p_in]), %%zmm3\n\t"

            "vpxord %%zmm4, %%zmm0, %%zmm0\n\t"
            "vpxord %%zmm4, %%zmm1, %%zmm1\n\t"
            "vpxord %%zmm4, %%zmm2, %%zmm2\n\t"
            "vpxord %%zmm4, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm5, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm5, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm5, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm5, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm6, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm6, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm6, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm6, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm7, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm7, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm7, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm7, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm8, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm8, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm8, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm8, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm9, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm9, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm9, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm9, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm10, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm10, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm10, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm11, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm11, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm11, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm12, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm12, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm12, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm13, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm13, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm13, %%zmm3, %%zmm3\n\t"

            "vaesenclast %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm14, %%zmm1, %%zmm1\n\t"
            "vaesenclast %%zmm14, %%zmm2, %%zmm2\n\t"
            "vaesenclast %%zmm14, %%zmm3, %%zmm3\n\t"

            "vmovdqu64 %%zmm0,    (%[p_out])\n\t"
            "vmovdqu64 %%zmm1,  64(%[p_out])\n\t"
            "vmovdqu64 %%zmm2, 128(%[p_out])\n\t"
            "vmovdqu64 %%zmm3, 192(%[p_out])\n\t"

            "addq $256, %[p_in]\n\t"
            "addq $256, %[p_out]\n\t"
            "subq $256, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        // Don't know why, maybe a consistant fluck, but here if I use zmm16 - zmm31, there is a 500 Mo/s cost, don't know why but it's here so...
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm14\n\t"
            "vbroadcasti32x4 176(%[p_rk]), %%zmm15\n\t"

            "0:\n\t"
            "vmovdqu64    (%[p_in]), %%zmm0\n\t"
            "vmovdqu64  64(%[p_in]), %%zmm1\n\t"
            "vmovdqu64 128(%[p_in]), %%zmm2\n\t"
            "vmovdqu64 192(%[p_in]), %%zmm3\n\t"

            "vpxord %%zmm4, %%zmm0, %%zmm0\n\t"
            "vpxord %%zmm4, %%zmm1, %%zmm1\n\t"
            "vpxord %%zmm4, %%zmm2, %%zmm2\n\t"
            "vpxord %%zmm4, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm5, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm5, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm5, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm5, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4  96(%[p_rk]), %%zmm10\n\t"

            "vaesenc %%zmm6, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm6, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm6, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm6, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm7, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm7, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm7, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm7, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm8, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm8, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm8, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm8, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm9, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm9, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm9, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm9, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm10, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm10, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm10, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 192(%[p_rk]), %%zmm10\n\t"

            "vaesenc %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm11, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm11, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm11, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm12, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm12, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm12, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm13, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm13, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm13, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm14, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm14, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm14, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm15, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm15, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm15, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm15, %%zmm3, %%zmm3\n\t"

            "vaesenclast %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm10, %%zmm1, %%zmm1\n\t"
            "vaesenclast %%zmm10, %%zmm2, %%zmm2\n\t"
            "vaesenclast %%zmm10, %%zmm3, %%zmm3\n\t"

            "vmovdqu64 %%zmm0,    (%[p_out])\n\t"
            "vmovdqu64 %%zmm1,  64(%[p_out])\n\t"
            "vmovdqu64 %%zmm2, 128(%[p_out])\n\t"
            "vmovdqu64 %%zmm3, 192(%[p_out])\n\t"

            "addq $256, %[p_in]\n\t"
            "addq $256, %[p_out]\n\t"
            "subq $256, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14", "zmm15",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm14\n\t"

            "0:\n\t"
            "vmovdqu64    (%[p_in]), %%zmm0\n\t"
            "vmovdqu64  64(%[p_in]), %%zmm1\n\t"
            "vmovdqu64 128(%[p_in]), %%zmm2\n\t"
            "vmovdqu64 192(%[p_in]), %%zmm3\n\t"

            "vpxord %%zmm4, %%zmm0, %%zmm0\n\t"
            "vpxord %%zmm4, %%zmm1, %%zmm1\n\t"
            "vpxord %%zmm4, %%zmm2, %%zmm2\n\t"
            "vpxord %%zmm4, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm5, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm5, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm5, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm5, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4  48(%[p_rk]), %%zmm7\n\t"

            "vaesenc %%zmm6, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm6, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm6, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm6, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm7, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm7, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm7, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm7, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4  80(%[p_rk]), %%zmm9\n\t"

            "vaesenc %%zmm8, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm8, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm8, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm8, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm9, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm9, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm9, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm9, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 192(%[p_rk]), %%zmm7\n\t"

            "vaesenc %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm10, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm10, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm10, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm11, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm11, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm11, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 208(%[p_rk]), %%zmm9\n\t"

            "vaesenc %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm12, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm12, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm12, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm13, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm13, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm13, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 176(%[p_rk]), %%zmm15\n\t"

            "vaesenc %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm14, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm14, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm14, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm15, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm15, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm15, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm15, %%zmm3, %%zmm3\n\t"

            "vaesenc %%zmm7, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm7, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm7, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm7, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 224(%[p_rk]), %%zmm15\n\t"

            "vaesenc %%zmm9, %%zmm0, %%zmm0\n\t"
            "vaesenc %%zmm9, %%zmm1, %%zmm1\n\t"
            "vaesenc %%zmm9, %%zmm2, %%zmm2\n\t"
            "vaesenc %%zmm9, %%zmm3, %%zmm3\n\t"

            "vaesenclast %%zmm15, %%zmm0, %%zmm0\n\t"
            "vaesenclast %%zmm15, %%zmm1, %%zmm1\n\t"
            "vaesenclast %%zmm15, %%zmm2, %%zmm2\n\t"
            "vaesenclast %%zmm15, %%zmm3, %%zmm3\n\t"

            "vmovdqu64 %%zmm0,    (%[p_out])\n\t"
            "vmovdqu64 %%zmm1,  64(%[p_out])\n\t"
            "vmovdqu64 %%zmm2, 128(%[p_out])\n\t"
            "vmovdqu64 %%zmm3, 192(%[p_out])\n\t"

            "addq $256, %[p_in]\n\t"
            "addq $256, %[p_out]\n\t"
            "subq $256, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14", "zmm15",
            "memory", "cc"
            );
    }
}

template <size_t NR>
inline void aes_decrypt(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm1\n\t"
            "movdqu  16(%[p_rk]), %%xmm2\n\t"
            "movdqu  32(%[p_rk]), %%xmm3\n\t"
            "movdqu  48(%[p_rk]), %%xmm4\n\t"
            "movdqu  64(%[p_rk]), %%xmm5\n\t"
            "movdqu  80(%[p_rk]), %%xmm6\n\t"
            "movdqu  96(%[p_rk]), %%xmm7\n\t"
            "movdqu 112(%[p_rk]), %%xmm8\n\t"
            "movdqu 128(%[p_rk]), %%xmm9\n\t"
            "movdqu 144(%[p_rk]), %%xmm10\n\t"
            "movdqu 160(%[p_rk]), %%xmm11\n\t"

            // Loadu pt
            "0:"
            "movdqu (%[p_in]), %%xmm0\n\t"

            // Encrypt
            "pxor   %%xmm1,  %%xmm0\n\t"
            "aesdec %%xmm2,  %%xmm0\n\t"
            "aesdec %%xmm3,  %%xmm0\n\t"
            "aesdec %%xmm4,  %%xmm0\n\t"
            "aesdec %%xmm5,  %%xmm0\n\t"
            "aesdec %%xmm6,  %%xmm0\n\t"
            "aesdec %%xmm7,  %%xmm0\n\t"
            "aesdec %%xmm8,  %%xmm0\n\t"
            "aesdec %%xmm9,  %%xmm0\n\t"
            "aesdec %%xmm10, %%xmm0\n\t"

            "aesdeclast %%xmm11, %%xmm0\n\t"

            // Storeu ct
            "movdqu %%xmm0, (%[p_out])\n\t"
            "addq $16, %[p_in]\n\t"
            "addq $16, %[p_out]\n\t"

            "subq $16, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm1\n\t"
            "movdqu  16(%[p_rk]), %%xmm2\n\t"
            "movdqu  32(%[p_rk]), %%xmm3\n\t"
            "movdqu  48(%[p_rk]), %%xmm4\n\t"
            "movdqu  64(%[p_rk]), %%xmm5\n\t"
            "movdqu  80(%[p_rk]), %%xmm6\n\t"
            "movdqu  96(%[p_rk]), %%xmm7\n\t"
            "movdqu 112(%[p_rk]), %%xmm8\n\t"
            "movdqu 128(%[p_rk]), %%xmm9\n\t"
            "movdqu 144(%[p_rk]), %%xmm10\n\t"
            "movdqu 160(%[p_rk]), %%xmm11\n\t"
            "movdqu 176(%[p_rk]), %%xmm12\n\t"
            "movdqu 192(%[p_rk]), %%xmm13\n\t"

            // Loadu pt
            "0:"
            "movdqu (%[p_in]), %%xmm0\n\t"

            // Encrypt
            "pxor   %%xmm1,  %%xmm0\n\t"
            "aesdec %%xmm2,  %%xmm0\n\t"
            "aesdec %%xmm3,  %%xmm0\n\t"
            "aesdec %%xmm4,  %%xmm0\n\t"
            "aesdec %%xmm5,  %%xmm0\n\t"
            "aesdec %%xmm6,  %%xmm0\n\t"
            "aesdec %%xmm7,  %%xmm0\n\t"
            "aesdec %%xmm8,  %%xmm0\n\t"
            "aesdec %%xmm9,  %%xmm0\n\t"
            "aesdec %%xmm10, %%xmm0\n\t"
            "aesdec %%xmm11, %%xmm0\n\t"
            "aesdec %%xmm12, %%xmm0\n\t"


            "aesdeclast %%xmm13, %%xmm0\n\t"

            // Storeu ct
            "movdqu %%xmm0, (%[p_out])\n\t"
            "addq $16, %[p_in]\n\t"
            "addq $16, %[p_out]\n\t"

            "subq $16, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm1\n\t"
            "movdqu  16(%[p_rk]), %%xmm2\n\t"
            "movdqu  32(%[p_rk]), %%xmm3\n\t"
            "movdqu  48(%[p_rk]), %%xmm4\n\t"
            "movdqu  64(%[p_rk]), %%xmm5\n\t"
            "movdqu  80(%[p_rk]), %%xmm6\n\t"
            "movdqu  96(%[p_rk]), %%xmm7\n\t"
            "movdqu 112(%[p_rk]), %%xmm8\n\t"
            "movdqu 128(%[p_rk]), %%xmm9\n\t"
            "movdqu 144(%[p_rk]), %%xmm10\n\t"
            "movdqu 160(%[p_rk]), %%xmm11\n\t"
            "movdqu 176(%[p_rk]), %%xmm12\n\t"
            "movdqu 192(%[p_rk]), %%xmm13\n\t"
            "movdqu 208(%[p_rk]), %%xmm14\n\t"
            "movdqu 224(%[p_rk]), %%xmm15\n\t"

            // Loadu pt
            "0:"
            "movdqu (%[p_in]), %%xmm0\n\t"

            // Encrypt
            "pxor   %%xmm1,  %%xmm0\n\t"
            "aesdec %%xmm2,  %%xmm0\n\t"
            "aesdec %%xmm3,  %%xmm0\n\t"
            "aesdec %%xmm4,  %%xmm0\n\t"
            "aesdec %%xmm5,  %%xmm0\n\t"
            "aesdec %%xmm6,  %%xmm0\n\t"
            "aesdec %%xmm7,  %%xmm0\n\t"
            "aesdec %%xmm8,  %%xmm0\n\t"
            "aesdec %%xmm9,  %%xmm0\n\t"
            "aesdec %%xmm10, %%xmm0\n\t"
            "aesdec %%xmm11, %%xmm0\n\t"
            "aesdec %%xmm12, %%xmm0\n\t"
            "aesdec %%xmm13, %%xmm0\n\t"
            "aesdec %%xmm14, %%xmm0\n\t"


            "aesdeclast %%xmm15, %%xmm0\n\t"

            // Storeu ct
            "movdqu %%xmm0, (%[p_out])\n\t"
            "addq $16, %[p_in]\n\t"
            "addq $16, %[p_out]\n\t"

            "subq $16, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14", "xmm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void aes_decryptx4(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
            // Loadu rkey
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

            // Loadu pt
            "0:"
            "movdqu   (%[p_in]), %%xmm0\n\t"
            "movdqu 16(%[p_in]), %%xmm1\n\t"
            "movdqu 32(%[p_in]), %%xmm2\n\t"
            "movdqu 48(%[p_in]), %%xmm3\n\t"

            // Encrypt
            "pxor   %%xmm4,  %%xmm0\n\t"
            "pxor   %%xmm4,  %%xmm1\n\t"
            "pxor   %%xmm4,  %%xmm2\n\t"
            "pxor   %%xmm4,  %%xmm3\n\t"

            "aesdec %%xmm5, %%xmm0\n\t"
            "aesdec %%xmm5, %%xmm1\n\t"
            "aesdec %%xmm5, %%xmm2\n\t"
            "aesdec %%xmm5, %%xmm3\n\t"

            "aesdec %%xmm6, %%xmm0\n\t"
            "aesdec %%xmm6, %%xmm1\n\t"
            "aesdec %%xmm6, %%xmm2\n\t"
            "aesdec %%xmm6, %%xmm3\n\t"

            "aesdec %%xmm7, %%xmm0\n\t"
            "aesdec %%xmm7, %%xmm1\n\t"
            "aesdec %%xmm7, %%xmm2\n\t"
            "aesdec %%xmm7, %%xmm3\n\t"

            "aesdec %%xmm8, %%xmm0\n\t"
            "aesdec %%xmm8, %%xmm1\n\t"
            "aesdec %%xmm8, %%xmm2\n\t"
            "aesdec %%xmm8, %%xmm3\n\t"

            "aesdec %%xmm9, %%xmm0\n\t"
            "aesdec %%xmm9, %%xmm1\n\t"
            "aesdec %%xmm9, %%xmm2\n\t"
            "aesdec %%xmm9, %%xmm3\n\t"

            "aesdec %%xmm10, %%xmm0\n\t"
            "aesdec %%xmm10, %%xmm1\n\t"
            "aesdec %%xmm10, %%xmm2\n\t"
            "aesdec %%xmm10, %%xmm3\n\t"

            "aesdec %%xmm11, %%xmm0\n\t"
            "aesdec %%xmm11, %%xmm1\n\t"
            "aesdec %%xmm11, %%xmm2\n\t"
            "aesdec %%xmm11, %%xmm3\n\t"

            "aesdec %%xmm12, %%xmm0\n\t"
            "aesdec %%xmm12, %%xmm1\n\t"
            "aesdec %%xmm12, %%xmm2\n\t"
            "aesdec %%xmm12, %%xmm3\n\t"

            "aesdec %%xmm13, %%xmm0\n\t"
            "aesdec %%xmm13, %%xmm1\n\t"
            "aesdec %%xmm13, %%xmm2\n\t"
            "aesdec %%xmm13, %%xmm3\n\t"

            "aesdeclast %%xmm14, %%xmm0\n\t"
            "aesdeclast %%xmm14, %%xmm1\n\t"
            "aesdeclast %%xmm14, %%xmm2\n\t"
            "aesdeclast %%xmm14, %%xmm3\n\t"

            // Storeu ct
            "movdqu %%xmm0,   (%[p_out])\n\t"
            "movdqu %%xmm1, 16(%[p_out])\n\t"
            "movdqu %%xmm2, 32(%[p_out])\n\t"
            "movdqu %%xmm3, 48(%[p_out])\n\t"

            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"

            "subq $64, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm4\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"
            "movdqu  32(%[p_rk]), %%xmm6\n\t"
            "movdqu  48(%[p_rk]), %%xmm7\n\t"
            "movdqu  64(%[p_rk]), %%xmm8\n\t"
            "movdqu  80(%[p_rk]), %%xmm9\n\t"
            "movdqu 112(%[p_rk]), %%xmm11\n\t"
            "movdqu 128(%[p_rk]), %%xmm12\n\t"
            "movdqu 144(%[p_rk]), %%xmm13\n\t"
            "movdqu 160(%[p_rk]), %%xmm14\n\t"
            "movdqu 176(%[p_rk]), %%xmm15\n\t"

            // Loadu pt
            "0:"
            "movdqu   (%[p_in]), %%xmm0\n\t"
            "movdqu 16(%[p_in]), %%xmm1\n\t"
            "movdqu 32(%[p_in]), %%xmm2\n\t"
            "movdqu 48(%[p_in]), %%xmm3\n\t"

            // Encrypt
            "pxor   %%xmm4,  %%xmm0\n\t"
            "pxor   %%xmm4,  %%xmm1\n\t"
            "pxor   %%xmm4,  %%xmm2\n\t"
            "pxor   %%xmm4,  %%xmm3\n\t"

            "aesdec %%xmm5, %%xmm0\n\t"
            "aesdec %%xmm5, %%xmm1\n\t"
            "aesdec %%xmm5, %%xmm2\n\t"
            "aesdec %%xmm5, %%xmm3\n\t"

            "movdqu  96(%[p_rk]), %%xmm10\n\t"

            "aesdec %%xmm6, %%xmm0\n\t"
            "aesdec %%xmm6, %%xmm1\n\t"
            "aesdec %%xmm6, %%xmm2\n\t"
            "aesdec %%xmm6, %%xmm3\n\t"

            "aesdec %%xmm7, %%xmm0\n\t"
            "aesdec %%xmm7, %%xmm1\n\t"
            "aesdec %%xmm7, %%xmm2\n\t"
            "aesdec %%xmm7, %%xmm3\n\t"

            "aesdec %%xmm8, %%xmm0\n\t"
            "aesdec %%xmm8, %%xmm1\n\t"
            "aesdec %%xmm8, %%xmm2\n\t"
            "aesdec %%xmm8, %%xmm3\n\t"

            "aesdec %%xmm9, %%xmm0\n\t"
            "aesdec %%xmm9, %%xmm1\n\t"
            "aesdec %%xmm9, %%xmm2\n\t"
            "aesdec %%xmm9, %%xmm3\n\t"

            "aesdec %%xmm10, %%xmm0\n\t"
            "aesdec %%xmm10, %%xmm1\n\t"
            "aesdec %%xmm10, %%xmm2\n\t"
            "aesdec %%xmm10, %%xmm3\n\t"

            "movdqu  192(%[p_rk]), %%xmm10\n\t"

            "aesdec %%xmm11, %%xmm0\n\t"
            "aesdec %%xmm11, %%xmm1\n\t"
            "aesdec %%xmm11, %%xmm2\n\t"
            "aesdec %%xmm11, %%xmm3\n\t"

            "aesdec %%xmm12, %%xmm0\n\t"
            "aesdec %%xmm12, %%xmm1\n\t"
            "aesdec %%xmm12, %%xmm2\n\t"
            "aesdec %%xmm12, %%xmm3\n\t"

            "aesdec %%xmm13, %%xmm0\n\t"
            "aesdec %%xmm13, %%xmm1\n\t"
            "aesdec %%xmm13, %%xmm2\n\t"
            "aesdec %%xmm13, %%xmm3\n\t"

            "aesdec %%xmm14, %%xmm0\n\t"
            "aesdec %%xmm14, %%xmm1\n\t"
            "aesdec %%xmm14, %%xmm2\n\t"
            "aesdec %%xmm14, %%xmm3\n\t"

            "aesdec %%xmm15, %%xmm0\n\t"
            "aesdec %%xmm15, %%xmm1\n\t"
            "aesdec %%xmm15, %%xmm2\n\t"
            "aesdec %%xmm15, %%xmm3\n\t"

            "aesdeclast %%xmm10, %%xmm0\n\t"
            "aesdeclast %%xmm10, %%xmm1\n\t"
            "aesdeclast %%xmm10, %%xmm2\n\t"
            "aesdeclast %%xmm10, %%xmm3\n\t"

            // Storeu ct
            "movdqu %%xmm0,   (%[p_out])\n\t"
            "movdqu %%xmm1, 16(%[p_out])\n\t"
            "movdqu %%xmm2, 32(%[p_out])\n\t"
            "movdqu %%xmm3, 48(%[p_out])\n\t"

            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"

            "subq $64, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14", "xmm15",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            // Loadu rkey
            "movdqu    (%[p_rk]), %%xmm4\n\t"
            "movdqu  16(%[p_rk]), %%xmm5\n\t"
            "movdqu  32(%[p_rk]), %%xmm6\n\t"
            "movdqu  64(%[p_rk]), %%xmm8\n\t"
            "movdqu  96(%[p_rk]), %%xmm10\n\t"
            "movdqu 112(%[p_rk]), %%xmm11\n\t"
            "movdqu 128(%[p_rk]), %%xmm12\n\t"
            "movdqu 144(%[p_rk]), %%xmm13\n\t"
            "movdqu 160(%[p_rk]), %%xmm14\n\t"

            // Loadu pt
            "0:"
            "movdqu   (%[p_in]), %%xmm0\n\t"
            "movdqu 16(%[p_in]), %%xmm1\n\t"
            "movdqu 32(%[p_in]), %%xmm2\n\t"
            "movdqu 48(%[p_in]), %%xmm3\n\t"

            // Encrypt
            "pxor   %%xmm4,  %%xmm0\n\t"
            "pxor   %%xmm4,  %%xmm1\n\t"
            "pxor   %%xmm4,  %%xmm2\n\t"
            "pxor   %%xmm4,  %%xmm3\n\t"

            "aesdec %%xmm5, %%xmm0\n\t"
            "aesdec %%xmm5, %%xmm1\n\t"
            "aesdec %%xmm5, %%xmm2\n\t"
            "aesdec %%xmm5, %%xmm3\n\t"

            "movdqu  48(%[p_rk]), %%xmm7\n\t"

            "aesdec %%xmm6, %%xmm0\n\t"
            "aesdec %%xmm6, %%xmm1\n\t"
            "aesdec %%xmm6, %%xmm2\n\t"
            "aesdec %%xmm6, %%xmm3\n\t"

            "aesdec %%xmm7, %%xmm0\n\t"
            "aesdec %%xmm7, %%xmm1\n\t"
            "aesdec %%xmm7, %%xmm2\n\t"
            "aesdec %%xmm7, %%xmm3\n\t"

            "movdqu  80(%[p_rk]), %%xmm9\n\t"

            "aesdec %%xmm8, %%xmm0\n\t"
            "aesdec %%xmm8, %%xmm1\n\t"
            "aesdec %%xmm8, %%xmm2\n\t"
            "aesdec %%xmm8, %%xmm3\n\t"

            "aesdec %%xmm9, %%xmm0\n\t"
            "aesdec %%xmm9, %%xmm1\n\t"
            "aesdec %%xmm9, %%xmm2\n\t"
            "aesdec %%xmm9, %%xmm3\n\t"

            "movdqu  192(%[p_rk]), %%xmm7\n\t"

            "aesdec %%xmm10, %%xmm0\n\t"
            "aesdec %%xmm10, %%xmm1\n\t"
            "aesdec %%xmm10, %%xmm2\n\t"
            "aesdec %%xmm10, %%xmm3\n\t"

            "aesdec %%xmm11, %%xmm0\n\t"
            "aesdec %%xmm11, %%xmm1\n\t"
            "aesdec %%xmm11, %%xmm2\n\t"
            "aesdec %%xmm11, %%xmm3\n\t"

            "movdqu  208(%[p_rk]), %%xmm9\n\t"

            "aesdec %%xmm12, %%xmm0\n\t"
            "aesdec %%xmm12, %%xmm1\n\t"
            "aesdec %%xmm12, %%xmm2\n\t"
            "aesdec %%xmm12, %%xmm3\n\t"

            "aesdec %%xmm13, %%xmm0\n\t"
            "aesdec %%xmm13, %%xmm1\n\t"
            "aesdec %%xmm13, %%xmm2\n\t"
            "aesdec %%xmm13, %%xmm3\n\t"

            "movdqu 176(%[p_rk]), %%xmm15\n\t"

            "aesdec %%xmm14, %%xmm0\n\t"
            "aesdec %%xmm14, %%xmm1\n\t"
            "aesdec %%xmm14, %%xmm2\n\t"
            "aesdec %%xmm14, %%xmm3\n\t"

            "aesdec %%xmm15, %%xmm0\n\t"
            "aesdec %%xmm15, %%xmm1\n\t"
            "aesdec %%xmm15, %%xmm2\n\t"
            "aesdec %%xmm15, %%xmm3\n\t"

            "aesdec %%xmm7, %%xmm0\n\t"
            "aesdec %%xmm7, %%xmm1\n\t"
            "aesdec %%xmm7, %%xmm2\n\t"
            "aesdec %%xmm7, %%xmm3\n\t"

            "movdqu 224(%[p_rk]), %%xmm15\n\t"

            "aesdec %%xmm9, %%xmm0\n\t"
            "aesdec %%xmm9, %%xmm1\n\t"
            "aesdec %%xmm9, %%xmm2\n\t"
            "aesdec %%xmm9, %%xmm3\n\t"

            "aesdeclast %%xmm15, %%xmm0\n\t"
            "aesdeclast %%xmm15, %%xmm1\n\t"
            "aesdeclast %%xmm15, %%xmm2\n\t"
            "aesdeclast %%xmm15, %%xmm3\n\t"

            // Storeu ct
            "movdqu %%xmm0,   (%[p_out])\n\t"
            "movdqu %%xmm1, 16(%[p_out])\n\t"
            "movdqu %%xmm2, 32(%[p_out])\n\t"
            "movdqu %%xmm3, 48(%[p_out])\n\t"

            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"

            "subq $64, %[size]\n\t"
            "jnz 0b"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "xmm0", "xmm1", "xmm2", "xmm3",
            "xmm4", "xmm5", "xmm6", "xmm7",
            "xmm8", "xmm9", "xmm10", "xmm11",
            "xmm12", "xmm13", "xmm14", "xmm15",
            "memory", "cc"
            );
    }

}
template <size_t NR>
inline void vaes256_decryptx2(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm1\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm2\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm3\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm11\n\t"

            "0:\n\t"
            "vmovdqu (%[p_in]), %%ymm0\n\t"

            "vpxor %%ymm1, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm2, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm3, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm4, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesdeclast %%ymm11, %%ymm0, %%ymm0\n\t"

            "vmovdqu %%ymm0, (%[p_out])\n\t"
            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"
            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm1\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm2\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm3\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 176(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 192(%[p_rk]), %%ymm13\n\t"

            "0:\n\t"
            "vmovdqu (%[p_in]), %%ymm0\n\t"

            "vpxor    %%ymm1, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm2, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm3, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm4, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesdeclast %%ymm13, %%ymm0, %%ymm0\n\t"

            "vmovdqu %%ymm0, (%[p_out])\n\t"
            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"
            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm1\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm2\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm3\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 176(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 192(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 208(%[p_rk]), %%ymm14\n\t"
            "vbroadcasti128 224(%[p_rk]), %%ymm15\n\t"

            "0:\n\t"
            "vmovdqu (%[p_in]), %%ymm0\n\t"

            "vpxor    %%ymm1, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm2, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm3, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm4, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesdec  %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesdeclast %%ymm15, %%ymm0, %%ymm0\n\t"

            "vmovdqu %%ymm0, (%[p_out])\n\t"
            "addq $32, %[p_in]\n\t"
            "addq $32, %[p_out]\n\t"
            "subq $32, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14", "ymm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void vaes256_decryptx8(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
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

            "0:\n\t"
            "vmovdqu    (%[p_in]), %%ymm0\n\t"
            "vmovdqu  32(%[p_in]), %%ymm1\n\t"
            "vmovdqu  64(%[p_in]), %%ymm2\n\t"
            "vmovdqu  96(%[p_in]), %%ymm3\n\t"

            "vpxor %%ymm4, %%ymm0, %%ymm0\n\t"
            "vpxor %%ymm4, %%ymm1, %%ymm1\n\t"
            "vpxor %%ymm4, %%ymm2, %%ymm2\n\t"
            "vpxor %%ymm4, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm5, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm5, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm5, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm6, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm6, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm6, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm7, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm7, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm7, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm8, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm8, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm8, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm9, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm9, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm9, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm10, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm10, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm10, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm11, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm11, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm11, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm12, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm12, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm12, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm13, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm13, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm13, %%ymm3, %%ymm3\n\t"

            "vaesdeclast %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesdeclast %%ymm14, %%ymm1, %%ymm1\n\t"
            "vaesdeclast %%ymm14, %%ymm2, %%ymm2\n\t"
            "vaesdeclast %%ymm14, %%ymm3, %%ymm3\n\t"

            "vmovdqu %%ymm0,   (%[p_out])\n\t"
            "vmovdqu %%ymm1, 32(%[p_out])\n\t"
            "vmovdqu %%ymm2, 64(%[p_out])\n\t"
            "vmovdqu %%ymm3, 96(%[p_out])\n\t"

            "addq $128, %[p_in]\n\t"
            "addq $128, %[p_out]\n\t"
            "subq $128, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  48(%[p_rk]), %%ymm7\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128  80(%[p_rk]), %%ymm9\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm14\n\t"
            "vbroadcasti128 176(%[p_rk]), %%ymm15\n\t"

            "0:\n\t"
            "vmovdqu   (%[p_in]), %%ymm0\n\t"
            "vmovdqu 32(%[p_in]), %%ymm1\n\t"
            "vmovdqu 64(%[p_in]), %%ymm2\n\t"
            "vmovdqu 96(%[p_in]), %%ymm3\n\t"

            "vpxor %%ymm4, %%ymm0, %%ymm0\n\t"
            "vpxor %%ymm4, %%ymm1, %%ymm1\n\t"
            "vpxor %%ymm4, %%ymm2, %%ymm2\n\t"
            "vpxor %%ymm4, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm5, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm5, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm5, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128  96(%[p_rk]), %%ymm10\n\t"

            "vaesdec %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm6, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm6, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm6, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm7, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm7, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm7, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm8, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm8, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm8, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm9, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm9, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm9, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm10, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm10, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm10, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 192(%[p_rk]), %%ymm10\n\t"

            "vaesdec %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm11, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm11, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm11, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm12, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm12, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm12, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm13, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm13, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm13, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm14, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm14, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm14, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm15, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm15, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm15, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm15, %%ymm3, %%ymm3\n\t"

            "vaesdeclast %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesdeclast %%ymm10, %%ymm1, %%ymm1\n\t"
            "vaesdeclast %%ymm10, %%ymm2, %%ymm2\n\t"
            "vaesdeclast %%ymm10, %%ymm3, %%ymm3\n\t"

            "vmovdqu %%ymm0,   (%[p_out])\n\t"
            "vmovdqu %%ymm1, 32(%[p_out])\n\t"
            "vmovdqu %%ymm2, 64(%[p_out])\n\t"
            "vmovdqu %%ymm3, 96(%[p_out])\n\t"

            "addq $128, %[p_in]\n\t"
            "addq $128, %[p_out]\n\t"
            "subq $128, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14", "ymm15",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti128    (%[p_rk]), %%ymm4\n\t"
            "vbroadcasti128  16(%[p_rk]), %%ymm5\n\t"
            "vbroadcasti128  32(%[p_rk]), %%ymm6\n\t"
            "vbroadcasti128  64(%[p_rk]), %%ymm8\n\t"
            "vbroadcasti128  96(%[p_rk]), %%ymm10\n\t"
            "vbroadcasti128 112(%[p_rk]), %%ymm11\n\t"
            "vbroadcasti128 128(%[p_rk]), %%ymm12\n\t"
            "vbroadcasti128 144(%[p_rk]), %%ymm13\n\t"
            "vbroadcasti128 160(%[p_rk]), %%ymm14\n\t"

            "0:\n\t"
            "vmovdqu   (%[p_in]), %%ymm0\n\t"
            "vmovdqu 32(%[p_in]), %%ymm1\n\t"
            "vmovdqu 64(%[p_in]), %%ymm2\n\t"
            "vmovdqu 96(%[p_in]), %%ymm3\n\t"

            "vpxor %%ymm4, %%ymm0, %%ymm0\n\t"
            "vpxor %%ymm4, %%ymm1, %%ymm1\n\t"
            "vpxor %%ymm4, %%ymm2, %%ymm2\n\t"
            "vpxor %%ymm4, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm5, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm5, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm5, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm5, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128  48(%[p_rk]), %%ymm7\n\t"

            "vaesdec %%ymm6, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm6, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm6, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm6, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm7, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm7, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm7, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128  80(%[p_rk]), %%ymm9\n\t"

            "vaesdec %%ymm8, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm8, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm8, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm8, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm9, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm9, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm9, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 192(%[p_rk]), %%ymm7\n\t"

            "vaesdec %%ymm10, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm10, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm10, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm10, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm11, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm11, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm11, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm11, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 208(%[p_rk]), %%ymm9\n\t"

            "vaesdec %%ymm12, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm12, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm12, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm12, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm13, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm13, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm13, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm13, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 176(%[p_rk]), %%ymm15\n\t"

            "vaesdec %%ymm14, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm14, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm14, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm14, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm15, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm15, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm15, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm15, %%ymm3, %%ymm3\n\t"

            "vaesdec %%ymm7, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm7, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm7, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm7, %%ymm3, %%ymm3\n\t"

            "vbroadcasti128 224(%[p_rk]), %%ymm15\n\t"

            "vaesdec %%ymm9, %%ymm0, %%ymm0\n\t"
            "vaesdec %%ymm9, %%ymm1, %%ymm1\n\t"
            "vaesdec %%ymm9, %%ymm2, %%ymm2\n\t"
            "vaesdec %%ymm9, %%ymm3, %%ymm3\n\t"

            "vaesdeclast %%ymm15, %%ymm0, %%ymm0\n\t"
            "vaesdeclast %%ymm15, %%ymm1, %%ymm1\n\t"
            "vaesdeclast %%ymm15, %%ymm2, %%ymm2\n\t"
            "vaesdeclast %%ymm15, %%ymm3, %%ymm3\n\t"

            "vmovdqu %%ymm0,   (%[p_out])\n\t"
            "vmovdqu %%ymm1, 32(%[p_out])\n\t"
            "vmovdqu %%ymm2, 64(%[p_out])\n\t"
            "vmovdqu %%ymm3, 96(%[p_out])\n\t"

            "addq $128, %[p_in]\n\t"
            "addq $128, %[p_out]\n\t"
            "subq $128, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "ymm0", "ymm1", "ymm2", "ymm3",
            "ymm4", "ymm5", "ymm6", "ymm7",
            "ymm8", "ymm9", "ymm10", "ymm11",
            "ymm12", "ymm13", "ymm14", "ymm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void vaes512_decryptx4(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm1\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm2\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm3\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm11\n\t"

            "0:\n\t"
            "vmovdqu64 (%[p_in]), %%zmm0\n\t"

            "vpxord   %%zmm1,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm2,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm3,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesdeclast %%zmm11, %%zmm0, %%zmm0\n\t"

            "vmovdqu64 %%zmm0, (%[p_out])\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm1\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm2\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm3\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 176(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 192(%[p_rk]), %%zmm13\n\t"

            "0:\n\t"
            "vmovdqu64 (%[p_in]), %%zmm0\n\t"

            "vpxord   %%zmm1,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm2,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm3,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesdeclast %%zmm13, %%zmm0, %%zmm0\n\t"

            "vmovdqu64 %%zmm0, (%[p_out])\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm1\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm2\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm3\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 176(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 192(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 208(%[p_rk]), %%zmm14\n\t"
            "vbroadcasti32x4 224(%[p_rk]), %%zmm15\n\t"

            "0:\n\t"
            "vmovdqu64 (%[p_in]), %%zmm0\n\t"

            "vpxord   %%zmm1,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm2,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm3,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm4,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm5,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm6,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm7,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm8,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm9,  %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesdec  %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesdeclast %%zmm15, %%zmm0, %%zmm0\n\t"

            "vmovdqu64 %%zmm0, (%[p_out])\n\t"
            "addq $64, %[p_in]\n\t"
            "addq $64, %[p_out]\n\t"
            "subq $64, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14", "zmm15",
            "memory", "cc"
            );
    }
}
template <size_t NR>
inline void vaes512_decryptx16(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t size) {
    if constexpr (NR == 10) {
        __asm__ volatile (
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
            "vmovdqu64    (%[p_in]), %%zmm0\n\t"
            "vmovdqu64  64(%[p_in]), %%zmm1\n\t"
            "vmovdqu64 128(%[p_in]), %%zmm2\n\t"
            "vmovdqu64 192(%[p_in]), %%zmm3\n\t"

            "vpxord %%zmm4, %%zmm0, %%zmm0\n\t"
            "vpxord %%zmm4, %%zmm1, %%zmm1\n\t"
            "vpxord %%zmm4, %%zmm2, %%zmm2\n\t"
            "vpxord %%zmm4, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm5, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm5, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm5, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm5, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm6, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm6, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm6, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm6, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm7, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm7, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm7, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm7, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm8, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm8, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm8, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm8, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm9, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm9, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm9, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm9, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm10, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm10, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm10, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm11, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm11, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm11, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm12, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm12, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm12, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm13, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm13, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm13, %%zmm3, %%zmm3\n\t"

            "vaesdeclast %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesdeclast %%zmm14, %%zmm1, %%zmm1\n\t"
            "vaesdeclast %%zmm14, %%zmm2, %%zmm2\n\t"
            "vaesdeclast %%zmm14, %%zmm3, %%zmm3\n\t"

            "vmovdqu64 %%zmm0,    (%[p_out])\n\t"
            "vmovdqu64 %%zmm1,  64(%[p_out])\n\t"
            "vmovdqu64 %%zmm2, 128(%[p_out])\n\t"
            "vmovdqu64 %%zmm3, 192(%[p_out])\n\t"

            "addq $256, %[p_in]\n\t"
            "addq $256, %[p_out]\n\t"
            "subq $256, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14",
            "memory", "cc"
            );
    }
    if constexpr (NR == 12) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  48(%[p_rk]), %%zmm7\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4  80(%[p_rk]), %%zmm9\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm14\n\t"
            "vbroadcasti32x4 176(%[p_rk]), %%zmm15\n\t"

            "0:\n\t"
            "vmovdqu64    (%[p_in]), %%zmm0\n\t"
            "vmovdqu64  64(%[p_in]), %%zmm1\n\t"
            "vmovdqu64 128(%[p_in]), %%zmm2\n\t"
            "vmovdqu64 192(%[p_in]), %%zmm3\n\t"

            "vpxord %%zmm4, %%zmm0, %%zmm0\n\t"
            "vpxord %%zmm4, %%zmm1, %%zmm1\n\t"
            "vpxord %%zmm4, %%zmm2, %%zmm2\n\t"
            "vpxord %%zmm4, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm5, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm5, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm5, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm5, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4  96(%[p_rk]), %%zmm10\n\t"

            "vaesdec %%zmm6, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm6, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm6, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm6, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm7, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm7, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm7, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm7, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm8, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm8, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm8, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm8, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm9, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm9, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm9, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm9, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm10, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm10, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm10, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 192(%[p_rk]), %%zmm10\n\t"

            "vaesdec %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm11, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm11, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm11, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm12, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm12, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm12, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm13, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm13, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm13, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm14, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm14, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm14, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm15, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm15, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm15, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm15, %%zmm3, %%zmm3\n\t"

            "vaesdeclast %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesdeclast %%zmm10, %%zmm1, %%zmm1\n\t"
            "vaesdeclast %%zmm10, %%zmm2, %%zmm2\n\t"
            "vaesdeclast %%zmm10, %%zmm3, %%zmm3\n\t"

            "vmovdqu64 %%zmm0,    (%[p_out])\n\t"
            "vmovdqu64 %%zmm1,  64(%[p_out])\n\t"
            "vmovdqu64 %%zmm2, 128(%[p_out])\n\t"
            "vmovdqu64 %%zmm3, 192(%[p_out])\n\t"

            "addq $256, %[p_in]\n\t"
            "addq $256, %[p_out]\n\t"
            "subq $256, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14", "zmm15",
            "memory", "cc"
            );
    }
    if constexpr (NR == 14) {
        __asm__ volatile (
            "vbroadcasti32x4    (%[p_rk]), %%zmm4\n\t"
            "vbroadcasti32x4  16(%[p_rk]), %%zmm5\n\t"
            "vbroadcasti32x4  32(%[p_rk]), %%zmm6\n\t"
            "vbroadcasti32x4  64(%[p_rk]), %%zmm8\n\t"
            "vbroadcasti32x4  96(%[p_rk]), %%zmm10\n\t"
            "vbroadcasti32x4 112(%[p_rk]), %%zmm11\n\t"
            "vbroadcasti32x4 128(%[p_rk]), %%zmm12\n\t"
            "vbroadcasti32x4 144(%[p_rk]), %%zmm13\n\t"
            "vbroadcasti32x4 160(%[p_rk]), %%zmm14\n\t"

            "0:\n\t"
            "vmovdqu64    (%[p_in]), %%zmm0\n\t"
            "vmovdqu64  64(%[p_in]), %%zmm1\n\t"
            "vmovdqu64 128(%[p_in]), %%zmm2\n\t"
            "vmovdqu64 192(%[p_in]), %%zmm3\n\t"

            "vpxord %%zmm4, %%zmm0, %%zmm0\n\t"
            "vpxord %%zmm4, %%zmm1, %%zmm1\n\t"
            "vpxord %%zmm4, %%zmm2, %%zmm2\n\t"
            "vpxord %%zmm4, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm5, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm5, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm5, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm5, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4  48(%[p_rk]), %%zmm7\n\t"

            "vaesdec %%zmm6, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm6, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm6, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm6, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm7, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm7, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm7, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm7, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4  80(%[p_rk]), %%zmm9\n\t"

            "vaesdec %%zmm8, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm8, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm8, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm8, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm9, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm9, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm9, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm9, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 192(%[p_rk]), %%zmm7\n\t"

            "vaesdec %%zmm10, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm10, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm10, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm10, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm11, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm11, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm11, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm11, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 208(%[p_rk]), %%zmm9\n\t"

            "vaesdec %%zmm12, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm12, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm12, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm12, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm13, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm13, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm13, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm13, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 176(%[p_rk]), %%zmm15\n\t"

            "vaesdec %%zmm14, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm14, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm14, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm14, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm15, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm15, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm15, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm15, %%zmm3, %%zmm3\n\t"

            "vaesdec %%zmm7, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm7, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm7, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm7, %%zmm3, %%zmm3\n\t"

            "vbroadcasti32x4 224(%[p_rk]), %%zmm15\n\t"

            "vaesdec %%zmm9, %%zmm0, %%zmm0\n\t"
            "vaesdec %%zmm9, %%zmm1, %%zmm1\n\t"
            "vaesdec %%zmm9, %%zmm2, %%zmm2\n\t"
            "vaesdec %%zmm9, %%zmm3, %%zmm3\n\t"

            "vaesdeclast %%zmm15, %%zmm0, %%zmm0\n\t"
            "vaesdeclast %%zmm15, %%zmm1, %%zmm1\n\t"
            "vaesdeclast %%zmm15, %%zmm2, %%zmm2\n\t"
            "vaesdeclast %%zmm15, %%zmm3, %%zmm3\n\t"

            "vmovdqu64 %%zmm0,    (%[p_out])\n\t"
            "vmovdqu64 %%zmm1,  64(%[p_out])\n\t"
            "vmovdqu64 %%zmm2, 128(%[p_out])\n\t"
            "vmovdqu64 %%zmm3, 192(%[p_out])\n\t"

            "addq $256, %[p_in]\n\t"
            "addq $256, %[p_out]\n\t"
            "subq $256, %[size]\n\t"
            "jnz 0b\n\t"

            "vzeroupper\n\t"

            : [p_in] "+r"(in), [p_out] "+r"(out), [size] "+r"(size)
            : [p_rk] "r"(rkey)
            : "zmm0", "zmm1", "zmm2", "zmm3",
            "zmm4", "zmm5", "zmm6", "zmm7",
            "zmm8", "zmm9", "zmm10", "zmm11",
            "zmm12", "zmm13", "zmm14", "zmm15",
            "memory", "cc"
            );
    }
}


enum ReturnValue : size_t {
    Success = 0,
    InvalidInputSize = 1,
    InvalidOutputSize = 2,
    InvalidPadding = 3,
};

template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
const char* ECB_AES<N>::get_error_message(size_t err) {
    switch (err) {
        case Success:
            return "Success";
        case InvalidInputSize:
            return "InvalidInputSize";
        case InvalidOutputSize:
            return "InvalidOutputSize";
        case InvalidPadding:
            return "InvalidPadding";
        default:
            return "Unkown";
    }
}

template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
ECB_AES<N>::ECB_AES(const Key& key) {
    // For key expansion -> m_rkey
    //expand_key<N>(key, m_rkey);
    expand_key<N>(
        std::span<const uint8_t, N / 8>(key.data(), N / 8),
        std::span<uint8_t, ((N / 32) + 7) * 16>(m_rkey.data(), ((N / 32) + 7) * 16)
    );


    // For key expansion inv -> m_rkey_inv
    if (CPUFeatures::has_aes_ni()) [[likely]] {
        _mm_storeu_si128(
            reinterpret_cast<__m128i*>(m_rkey_inv.data() + 0 * 16),
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + NR * 16))
        );
        for (size_t i = 1; i < NR; ++i) {
            __m128i rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + (NR - i) * 16));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(m_rkey_inv.data() + i * 16), _mm_aesimc_si128(rk));
        }
        _mm_storeu_si128(reinterpret_cast<__m128i*>(m_rkey_inv.data() + NR * 16), _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + 0 * 16)));
    }
}


using aes_fn = void(*)(const uint8_t*, uint8_t*, const uint8_t*, size_t);
template <aes_fn func> // Make shit more prettier
inline void process_chunk(const uint8_t* in, uint8_t* out, const uint8_t* rkey, size_t& i, size_t numBlocks, size_t multiple) {
    size_t blocks = ((numBlocks - i) / multiple) * multiple;
    if (blocks > 0) {
        func(in + i * 16, out + i * 16, rkey, blocks * 16);
        i += blocks;
    }
}

template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
size_t ECB_AES<N>::encrypt(std::span<const uint8_t> in, std::span<uint8_t> out) const noexcept  {
    const size_t numBlocks = in.size() / 16;
    const size_t remainder = in.size() % 16;
    const size_t needed = encryption_size_out(in.size());

    if (out.size() < needed) {
        return InvalidOutputSize;
    }

    size_t i = 0;
    
    if (CPUFeatures::has_vaes512()) {
        process_chunk<vaes512_encryptx16<NR>>(in.data(), out.data(), m_rkey.data(), i, numBlocks, 16);
        process_chunk<vaes512_encryptx4<NR>>(in.data(), out.data(), m_rkey.data(), i, numBlocks, 4);
    }
    if (CPUFeatures::has_vaes()) {
        process_chunk<vaes256_encryptx8<NR>>(in.data(), out.data(), m_rkey.data(), i, numBlocks, 8);
        process_chunk<vaes256_encryptx2<NR>>(in.data(), out.data(), m_rkey.data(), i, numBlocks, 2);
    }
    if (CPUFeatures::has_aes_ni()) {
        process_chunk<aes_encryptx4<NR>>(in.data(), out.data(), m_rkey.data(), i, numBlocks, 4);
        process_chunk<aes_encrypt<NR>>(in.data(), out.data(), m_rkey.data(), i, numBlocks, 1);

        std::array<uint8_t, 16> padding;
        size_t off = 16 - remainder;
        std::memset(padding.data(), static_cast<int>(off), 16);
        if (remainder > 0) {
            std::memcpy(padding.data(), in.data() + i * 16, remainder);
        }

        aes_encrypt<NR>(padding.data(), out.data() + i * 16, m_rkey.data(), 16);
    }
    else [[unlikely]] {
        for (; i < numBlocks; ++i) {
            std::array<uint8_t, 16> block;
            std::memcpy(block.data(), in.data() + i * 16, 16);

            for (uint8_t j = 0; j < 16; j++)
                block[j] ^= m_rkey[j];

            for (size_t round = 1; round < NR; ++round) {
                sub_bytes(block);
                shift_rows(block);
                mix_columns(block);
                for (uint8_t j = 0; j < 16; j++)
                    block[j] ^= m_rkey[round * 16 +j];
            }

            sub_bytes(block);
            shift_rows(block);
            for (uint8_t j = 0; j < 16; j++)
                block[j] ^= m_rkey[NR * 16 + j];

            std::memcpy(out.data() + i * 16, block.data(), 16);
        }
        std::array<uint8_t, 16> padding;
        size_t off = 16 - remainder;
        std::memset(padding.data(), static_cast<int>(off), 16);
        if (remainder > 0) {
            std::memcpy(padding.data(), in.data() + i * 16, remainder);
        }
        for (uint8_t j = 0; j < 16; j++)
            padding[j] ^= m_rkey[j];

        for (size_t round = 1; round < NR; ++round) {
            sub_bytes(padding);
            shift_rows(padding);
            mix_columns(padding);
            for (uint8_t j = 0; j < 16; j++)
                padding[j] ^= m_rkey[round * 16 + j];
        }

        sub_bytes(padding);
        shift_rows(padding);
        for (uint8_t j = 0; j < 16; j++)
            padding[j] ^= m_rkey[NR * 16 + j];
        std::memcpy(out.data() + i * 16, padding.data(), 16);
    }

    return Success;
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
std::vector<uint8_t> ECB_AES<N>::encrypt(std::span<const uint8_t> in) const {
    size_t needed = encryption_size_out(in.size());
    std::vector<uint8_t> out(needed);
    encrypt(in, std::span<uint8_t>(out));
    return out;
}

template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
size_t ECB_AES<N>::encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out) const {
    size_t needed = encryption_size_out(in.size());
    out.resize(needed);
    return encrypt(in, std::span<uint8_t>(out));
}


template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
size_t ECB_AES<N>::decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out) const {
    if (in.size() == 0 || in.size() % 16 != 0) {
        return InvalidInputSize;
    }

    size_t numBlocks = in.size() / 16;

    if (out.size() != in.size()) {
        out.resize(in.size());
    }

    size_t i = 0;

    if (CPUFeatures::has_vaes512()) {
        process_chunk<vaes512_decryptx16<NR>>(in.data(), out.data(), m_rkey_inv.data(), i, numBlocks, 16);
        process_chunk<vaes512_decryptx4<NR>>(in.data(), out.data(), m_rkey_inv.data(), i, numBlocks, 4);
    }
    if (CPUFeatures::has_vaes()) {
        process_chunk<vaes256_decryptx8<NR>>(in.data(), out.data(), m_rkey_inv.data(), i, numBlocks, 8);
        process_chunk<vaes256_decryptx2<NR>>(in.data(), out.data(), m_rkey_inv.data(), i, numBlocks, 2);
    }
    if (CPUFeatures::has_aes_ni()) {
        process_chunk<aes_decryptx4<NR>>(in.data(), out.data(), m_rkey_inv.data(), i, numBlocks, 4);
        process_chunk<aes_decrypt<NR>>(in.data(), out.data(), m_rkey_inv.data(), i, numBlocks, 1);
    }
    else {
        for (; i < numBlocks; ++i) {
            std::array<uint8_t, 16> block;
            std::memcpy(block.data(), in.data() + i * 16, 16);

            for (uint8_t j = 0; j < 16; j++)
                block[j] ^= m_rkey[NR * 16 + j];

            for (size_t round = NR - 1; round >= 1; --round) {
                shift_rows_inv(block);
                sub_bytes_inv(block);
                for (uint8_t j = 0; j < 16; j++)
                    block[j] ^= m_rkey[round * 16 + j];

                mix_columns_inv(block);
            }

            shift_rows_inv(block);
            sub_bytes_inv(block);
            for (uint8_t j = 0; j < 16; j++)
                block[j] ^= m_rkey[j];

            std::memcpy(out.data() + i * 16, block.data(), 16);
        }
    }


    uint8_t padValue = out.back();
    if (padValue == 0 || padValue > 16) {
        return InvalidPadding;
    }

    size_t success = Success;
    for (size_t i = out.size() - padValue; i < out.size(); ++i) {
        if (out[i] != padValue) {
            success = InvalidPadding;
        }
    }

    out.resize(out.size() - padValue);
    return success;
}

template class ECB_AES<128>;
template class ECB_AES<192>;
template class ECB_AES<256>;
#include "crypto/AES.h"
#include "../../include/utils/MathsOperation.h"
#include "../../include/utils/CPUFeatures.h"
#include "helper/AES_Helper.h"
#include <memory>
#include <immintrin.h>


template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
AES<N>::AES(const Key& key) {
    // For key expansion -> m_rkey
    expand_key<N>(key, m_rkey);

    
    // For key expansion inv -> m_rkey_inv
    if (CPUFeatures::has_aes_ni()) [[likely]] {
        for (size_t i = 1; i < NR; ++i) {
            __m128i rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + i * 16));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(m_rkey_inv.data() + i * 16), _mm_aesimc_si128(rk));
        }
    }
}

// ==== Scalar =====
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
void AES<N>::cipher(std::span<uint8_t, 16> block) {
    MathsOperation::cl_xor(block, std::span<const uint8_t>(m_rkey).subspan(0).first<16>(), block); // Add round key

    for (size_t round = 1; round < NR; ++round) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        MathsOperation::cl_xor(block, std::span<const uint8_t>(m_rkey).subspan(round * 16).first<16>(), block); // Add round key
    }

    sub_bytes(block);
    shift_rows(block);
    MathsOperation::cl_xor(block, std::span<const uint8_t>(m_rkey).subspan(NR * 16).first<16>(), block); // Add round key
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
void AES<N>::cipher_inv(std::span<uint8_t, 16> block) {
    MathsOperation::cl_xor(block, std::span<const uint8_t>(m_rkey).subspan(NR * 16).first<16>(), block); // Add round key

    for (size_t round = NR - 1; round >= 1; --round) {
        shift_rows_inv(block);
        sub_bytes_inv(block);
        MathsOperation::cl_xor(block, std::span<const uint8_t>(m_rkey).subspan(round * 16).first<16>(), block); // Add round key
        mix_columns_inv(block);
    }

    shift_rows_inv(block);
    sub_bytes_inv(block);
    MathsOperation::cl_xor(block, std::span<const uint8_t>(m_rkey).subspan(0).first<16>(), block); // Add round key
}


// ==== AES-NI =====
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
template<size_t BLOCKS>
    requires (BLOCKS == 1 || BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
void AES<N>::cipher_aesni(const uint8_t* in, uint8_t* out) {
    std::array<__m128i, BLOCKS> states;

    for (size_t b = 0; b < BLOCKS; ++b) {
        states[b] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + b * 16));
    }

    __m128i rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data()));
    for (auto& s : states) {
        s = _mm_xor_si128(s, rk);
    }

    for (size_t i = 1; i < NR; ++i) {
        rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + i * 16));
        for (auto& s : states) {
            s = _mm_aesenc_si128(s, rk);
        }
    }

    rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + NR * 16));
    for (auto& s : states) {
        s = _mm_aesenclast_si128(s, rk);
    }

    for (size_t b = 0; b < BLOCKS; ++b) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + b * 16), states[b]);
    }
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
template<size_t BLOCKS>
    requires (BLOCKS == 1 || BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
void AES<N>::cipher_aesni_inv(const uint8_t* in, uint8_t* out) {
    std::array<__m128i, BLOCKS> states;

    for (size_t b = 0; b < BLOCKS; ++b) {
        states[b] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + b * 16));
    }

    __m128i rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + NR * 16));
    for (auto& s : states) {
        s = _mm_xor_si128(s, rk);
    }

    for (size_t i = NR - 1; i > 0; --i) {
        __m128i rk_dec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey_inv.data() + i * 16));
        for (auto& s : states) {
            s = _mm_aesdec_si128(s, rk_dec);
        }
    }

    rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data()));
    for (auto& s : states) {
        s = _mm_aesdeclast_si128(s, rk);
    }

    for (size_t b = 0; b < BLOCKS; ++b) {
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + b * 16), states[b]);
    }
}


// ===== VAES =====
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
template<size_t BLOCKS>
    requires (BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
void AES<N>::cipher_vaes256(const uint8_t* in, uint8_t* out) {
    constexpr size_t PAIRS = BLOCKS / 2;

    std::array<__m256i, PAIRS> states;

    for (size_t p = 0; p < PAIRS; ++p) {
        states[p] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + p * 32));
    }

    __m256i rk = _mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data())));
    for (auto& s : states) {
        s = _mm256_xor_si256(s, rk);
    }

    for (size_t i = 1; i < NR; ++i) {
        rk = _mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + i * 16)));

        for (auto& s : states) {
            s = _mm256_aesenc_epi128(s, rk);
        }
    }

    rk = _mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + NR * 16)));
    for (auto& s : states) {
        s = _mm256_aesenclast_epi128(s, rk);
    }

    for (size_t p = 0; p < PAIRS; ++p) {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + p * 32), states[p]);
    }
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
template<size_t BLOCKS>
    requires (BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
void AES<N>::cipher_vaes512(const uint8_t* in, uint8_t* out) {
    constexpr size_t QUADS = BLOCKS / 4;

    std::array<__m512i, QUADS> states;

    for (size_t q = 0; q < QUADS; ++q) {
        states[q] = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(in + q * 64));
    }

    __m512i rk = _mm512_broadcast_i32x4(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data())));
    for (auto& s : states) {
        s = _mm512_xor_si512(s, rk);
    }

    for (size_t i = 1; i < NR; ++i) {
        rk = _mm512_broadcast_i32x4(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + i * 16)));
        for (auto& s : states) {
            s = _mm512_aesenc_epi128(s, rk);
        }
    }

    rk = _mm512_broadcast_i32x4(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + NR * 16)));
    for (auto& s : states) {
        s = _mm512_aesenclast_epi128(s, rk);
    }

    for (size_t q = 0; q < QUADS; ++q) {
        _mm512_storeu_si512(reinterpret_cast<__m512i*>(out + q * 64), states[q]);
    }
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
template<size_t BLOCKS>
    requires (BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
void AES<N>::cipher_vaes256_inv(const uint8_t* in, uint8_t* out) {
    constexpr size_t PAIRS = BLOCKS / 2;
    std::array<__m256i, PAIRS> states;

    for (size_t p = 0; p < PAIRS; ++p) {
        states[p] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + p * 32));
    }

    __m256i rk = _mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + NR * 16)));
    for (auto& s : states) {
        s = _mm256_xor_si256(s, rk);
    }

    for (size_t i = NR - 1; i > 0; --i) {
        rk = _mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey_inv.data() + i * 16)));
        for (auto& s : states) {
            s = _mm256_aesdec_epi128(s, rk);
        }
    }

    rk = _mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data())));
    for (auto& s : states) {
        s = _mm256_aesdeclast_epi128(s, rk);
    }

    for (size_t p = 0; p < PAIRS; ++p) {
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + p * 32), states[p]);
    }
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
template<size_t BLOCKS>
    requires (BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
void AES<N>::cipher_vaes512_inv(const uint8_t* in, uint8_t* out) {
    constexpr size_t QUADS = BLOCKS / 4;
    std::array<__m512i, QUADS> states;

    for (size_t q = 0; q < QUADS; ++q) {
        states[q] = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(in + q * 64));
    }

    __m512i rk = _mm512_broadcast_i32x4(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data() + NR * 16)));
    for (auto& s : states) {
        s = _mm512_xor_si512(s, rk);
    }

    for (size_t i = NR - 1; i > 0; --i) {
        rk = _mm512_broadcast_i32x4(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey_inv.data() + i * 16)));
        for (auto& s : states) {
            s = _mm512_aesdec_epi128(s, rk);
        }
    }

    rk = _mm512_broadcast_i32x4(_mm_loadu_si128(reinterpret_cast<const __m128i*>(m_rkey.data())));
    for (auto& s : states) {
        s = _mm512_aesdeclast_epi128(s, rk);
    }

    for (size_t q = 0; q < QUADS; ++q) {
        _mm512_storeu_si512(reinterpret_cast<__m512i*>(out + q * 64), states[q]);
    }
}


// ==== Public ====
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
void AES<N>::encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out) {
    size_t numBlocks = in.size() / 16;
    size_t remainder = in.size() % 16;

    out.clear();
    out.resize(numBlocks * 16 + (remainder ? 16 : 0));
    
    size_t i = 0;

    if (CPUFeatures::has_vaes() && CPUFeatures::has_avx512f()) {
        for (; i + 16 <= numBlocks; i += 16) {
            cipher_vaes512<16>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 8 <= numBlocks; i += 8) {
            cipher_vaes512<8>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 4 <= numBlocks; i += 4) {
            cipher_vaes512<4>(in.data() + i * 16, out.data() + i * 16);
        }
    }
    if (CPUFeatures::has_vaes()) {
        for (; i + 16 <= numBlocks; i += 16) {
            cipher_vaes256<16>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 8 <= numBlocks; i += 8) {
            cipher_vaes256<8>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 4 <= numBlocks; i += 4) {
            cipher_vaes256<4>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 2 <= numBlocks; i += 2) {
            cipher_vaes256<2>(in.data() + i * 16, out.data() + i * 16);
        }
    }

    if (CPUFeatures::has_aes_ni()) [[likely]] {

        for (; i + 8 <= numBlocks; i += 8) {
            cipher_aesni<8>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 4 <= numBlocks; i += 4) {
            cipher_aesni<4>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 2 <= numBlocks; i += 2) {
            cipher_aesni<2>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i < numBlocks; ++i) {
            cipher_aesni<1>(in.data() + i * 16, out.data() + i * 16);
        }

        if (remainder) {
            size_t offset = numBlocks * 16;
            uint8_t padValue = static_cast<uint8_t>(16 - remainder);

            std::array<uint8_t, 16> padBlock = {};
            std::memcpy(padBlock.data(), in.data() + offset, remainder);
            std::memset(padBlock.data() + remainder, padValue, 16 - remainder);
            cipher_aesni<1>(padBlock.data(), out.data() + offset);
        }
        return;
    }
    else {
        for (; i < numBlocks; ++i) {
            std::memcpy(out.data() + i * 16, in.data() + i * 16, 16);
            cipher(std::span<uint8_t, 16>(out.data() + i * 16, 16));
        }
        if (remainder) {
            size_t offset = numBlocks * 16;
            uint8_t padValue = static_cast<uint8_t>(16 - remainder);

            std::memcpy(out.data() + offset, in.data() + offset, remainder);
            std::memset(out.data() + offset + remainder, padValue, 16 - remainder);

            cipher(std::span<uint8_t, 16>(out.data() + offset, 16));
        }
    }
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
bool AES<N>::decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out) {
    if (in.size() == 0 || in.size() % 16 != 0) {
        return false;
    }

    size_t numBlocks = in.size() / 16;

    out.clear();
    out.resize(in.size());
    size_t i = 0;

    if (CPUFeatures::has_vaes() && CPUFeatures::has_avx512f()) {
        for (; i + 16 <= numBlocks; i += 16) {
            cipher_vaes512_inv<16>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 8 <= numBlocks; i += 8) {
            cipher_vaes512_inv<8>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 4 <= numBlocks; i += 4) {
            cipher_vaes512_inv<4>(in.data() + i * 16, out.data() + i * 16);
        }
    }
    if (CPUFeatures::has_vaes()) {
        for (; i + 16 <= numBlocks; i += 16) {
            cipher_vaes256_inv<16>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 8 <= numBlocks; i += 8) {
            cipher_vaes256_inv<8>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 4 <= numBlocks; i += 4) {
            cipher_vaes256_inv<4>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 2 <= numBlocks; i += 2) {
            cipher_vaes256_inv<2>(in.data() + i * 16, out.data() + i * 16);
        }
    }
    if (CPUFeatures::has_aes_ni()) [[likely]] {

        for (; i + 8 <= numBlocks; i += 8) {
            cipher_aesni_inv<8>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 4 <= numBlocks; i += 4) {
            cipher_aesni_inv<4>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i + 2 <= numBlocks; i += 2) {
            cipher_aesni_inv<2>(in.data() + i * 16, out.data() + i * 16);
        }
        for (; i < numBlocks; ++i) {
            cipher_aesni_inv<1>(in.data() + i * 16, out.data() + i * 16);
        }
    }
    else [[unlikely]] {
        for (; i < numBlocks; ++i) {
            std::array<uint8_t, 16> block;
            std::memcpy(block.data(), in.data() + i * 16, 16);
            cipher_inv(block);
            std::memcpy(out.data() + i * 16, block.data(), 16);
        }
    }


    uint8_t padValue = out.back();
    if (padValue == 0 || padValue > 16)
        return false;

    for (size_t i = out.size() - padValue; i < out.size(); ++i) {
        if (out[i] != padValue)
            return false;
    }

    out.resize(out.size() - padValue);
    return true;
}

template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
template<size_t BLOCKS>
    requires (BLOCKS == 1 || BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
void AES<N>::encrypt_block(std::span<uint8_t, BLOCKS * 16> block) {
    if constexpr (BLOCKS >= 4) {
        if (CPUFeatures::has_vaes() && CPUFeatures::has_avx512f()) {
            cipher_vaes512<BLOCKS>(block.data(), block.data());
            return;
        }
    }
    if constexpr (BLOCKS >= 2) {
        if (CPUFeatures::has_vaes()) {
            cipher_vaes256<BLOCKS>(block.data(), block.data());
            return;
        }
    }
    if (CPUFeatures::has_aes_ni()) [[likely]] {
        cipher_aesni<BLOCKS>(block.data(), block.data());
        return;
    }
    else [[unlikely]] {
        for (uint8_t i = 0; i < BLOCKS; i++) {
            cipher(block.subspan(16 * i).first<16>());
        }
    }
}
template<size_t N>
    requires(N == 128 || N == 192 || N == 256)
template<size_t BLOCKS>
    requires (BLOCKS == 1 || BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
void AES<N>::decrypt_block(std::span<uint8_t, BLOCKS * 16> block) {
    if constexpr (BLOCKS >= 4) {
        if (CPUFeatures::has_vaes() && CPUFeatures::has_avx512f()) {
            cipher_vaes512_inv<BLOCKS>(block.data(), block.data());
            return;
        }
    }
    if constexpr (BLOCKS >= 2) {
        if (CPUFeatures::has_vaes()) {
            cipher_vaes256_inv<BLOCKS>(block.data(), block.data());
            return;
        }
    }
    if (CPUFeatures::has_aes_ni()) [[likely]] {
        cipher_aesni_inv<BLOCKS>(block.data(), block.data());
        return;
    }
    else [[unlikely]] {
        for (uint8_t i = 0; i < BLOCKS; i++) {
            cipher_inv(block.subspan(16 * i).first<16>());
        }
    }
}





template class AES<128>;
template class AES<192>;
template class AES<256>;


template void AES<128>::encrypt_block<1>(std::span<uint8_t, 1 * 16> block);
template void AES<128>::encrypt_block<2>(std::span<uint8_t, 2 * 16> block);
template void AES<128>::encrypt_block<4>(std::span<uint8_t, 4 * 16> block);
template void AES<128>::encrypt_block<8>(std::span<uint8_t, 8 * 16> block);
template void AES<128>::encrypt_block<16>(std::span<uint8_t, 16 * 16> block);

template void AES<192>::encrypt_block<1>(std::span<uint8_t, 1 * 16> block);
template void AES<192>::encrypt_block<2>(std::span<uint8_t, 2 * 16> block);
template void AES<192>::encrypt_block<4>(std::span<uint8_t, 4 * 16> block);
template void AES<192>::encrypt_block<8>(std::span<uint8_t, 8 * 16> block);
template void AES<192>::encrypt_block<16>(std::span<uint8_t, 16 * 16> block);

template void AES<256>::encrypt_block<1>(std::span<uint8_t, 1 * 16> block);
template void AES<256>::encrypt_block<2>(std::span<uint8_t, 2 * 16> block);
template void AES<256>::encrypt_block<4>(std::span<uint8_t, 4 * 16> block);
template void AES<256>::encrypt_block<8>(std::span<uint8_t, 8 * 16> block);
template void AES<256>::encrypt_block<16>(std::span<uint8_t, 16 * 16> block);

template void AES<128>::decrypt_block<1>(std::span<uint8_t, 1 * 16> block);
template void AES<128>::decrypt_block<2>(std::span<uint8_t, 2 * 16> block);
template void AES<128>::decrypt_block<4>(std::span<uint8_t, 4 * 16> block);
template void AES<128>::decrypt_block<8>(std::span<uint8_t, 8 * 16> block);
template void AES<128>::decrypt_block<16>(std::span<uint8_t, 16 * 16> block);

template void AES<192>::decrypt_block<1>(std::span<uint8_t, 1 * 16> block);
template void AES<192>::decrypt_block<2>(std::span<uint8_t, 2 * 16> block);
template void AES<192>::decrypt_block<4>(std::span<uint8_t, 4 * 16> block);
template void AES<192>::decrypt_block<8>(std::span<uint8_t, 8 * 16> block);
template void AES<192>::decrypt_block<16>(std::span<uint8_t, 16 * 16> block);

template void AES<256>::decrypt_block<1>(std::span<uint8_t, 1 * 16> block);
template void AES<256>::decrypt_block<2>(std::span<uint8_t, 2 * 16> block);
template void AES<256>::decrypt_block<4>(std::span<uint8_t, 4 * 16> block);
template void AES<256>::decrypt_block<8>(std::span<uint8_t, 8 * 16> block);
template void AES<256>::decrypt_block<16>(std::span<uint8_t, 16 * 16> block);

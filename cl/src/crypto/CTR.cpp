#include "../../include/crypto/CTR.h"
#include "../../include/utils/SafeArray.h"
#include "../../include/utils/MathsOperation.h"
#include <bit>

template<CipherAlgorithm CA>
void CTR<CA>::encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counterStart) {
    uint64_t num_blocks = (in.size() + 15) / 16;
    alignas(64) std::array<uint8_t, 256> keystream = {};
    alignas(64) std::array<uint8_t, 256> intermediaire = {};

    for (uint8_t i = 0; i < 16; i++) {
        size_t offset = i * 16;
        std::memcpy(keystream.data() + offset, nonce.data(), 12);
    }

    out.resize(in.size());

    uint64_t i = 0;
#define BATCH 16
    for (; i + BATCH <= num_blocks; i += BATCH) {
        std::memcpy(intermediaire.data(), keystream.data(), 256);

        for (size_t j = 0; j < BATCH; ++j) {
            uint32_t counter = counterStart + i + j;
            uint32_t swappedCounter = std::byteswap(counter);
            std::memcpy(intermediaire.data() + j * 16 + 12, &swappedCounter, 4);
        }

        m_CA.template encrypt_block<BATCH>(intermediaire);

        size_t block_start = i * 16;

        MathsOperation::cl_xor(
            std::span<const uint8_t>(in.data() + block_start, BATCH * 16),
            std::span<const uint8_t>(intermediaire.data(), BATCH * 16),
            std::span<uint8_t>(out.data() + block_start, BATCH * 16)
        );
    }
#undef BATCH
#define BATCH 8
    for (; i + BATCH <= num_blocks; i += BATCH) {
        std::memcpy(intermediaire.data(), keystream.data(), 256);

        for (size_t j = 0; j < BATCH; ++j) {
            uint32_t counter = counterStart + i + j;
            uint32_t swappedCounter = std::byteswap(counter);
            std::memcpy(intermediaire.data() + j * 16 + 12, &swappedCounter, 4);
        }

        m_CA.template encrypt_block<BATCH>(std::span<uint8_t, 256>(intermediaire).subspan(0).first<BATCH * 16>());

        size_t block_start = i * 16;

        MathsOperation::cl_xor(
            std::span<const uint8_t>(in.data() + block_start, BATCH * 16),
            std::span<const uint8_t>(intermediaire.data(), BATCH * 16),
            std::span<uint8_t>(out.data() + block_start, BATCH * 16)
        );
    }
#undef BATCH
#define BATCH 4
    for (; i + BATCH <= num_blocks; i += BATCH) {
        std::memcpy(intermediaire.data(), keystream.data(), 256);

        for (size_t j = 0; j < BATCH; ++j) {
            uint32_t counter = counterStart + i + j;
            uint32_t swappedCounter = std::byteswap(counter);
            std::memcpy(intermediaire.data() + j * 16 + 12, &swappedCounter, 4);
        }

        m_CA.template encrypt_block<BATCH>(std::span<uint8_t, 256>(intermediaire).subspan(0).first<BATCH * 16>());

        size_t block_start = i * 16;

        MathsOperation::cl_xor(
            std::span<const uint8_t>(in.data() + block_start, BATCH * 16),
            std::span<const uint8_t>(intermediaire.data(), BATCH * 16),
            std::span<uint8_t>(out.data() + block_start, BATCH * 16)
        );
    }
#undef BATCH
#define BATCH 2
    for (; i + BATCH <= num_blocks; i += BATCH) {
        std::memcpy(intermediaire.data(), keystream.data(), 256);

        for (size_t j = 0; j < BATCH; ++j) {
            uint32_t counter = counterStart + i + j;
            uint32_t swappedCounter = std::byteswap(counter);
            std::memcpy(intermediaire.data() + j * 16 + 12, &swappedCounter, 4);
        }

        m_CA.template encrypt_block<BATCH>(std::span<uint8_t, 256>(intermediaire).subspan(0).first<BATCH * 16>());

        size_t block_start = i * 16;

        MathsOperation::cl_xor(
            std::span<const uint8_t>(in.data() + block_start, BATCH * 16),
            std::span<const uint8_t>(intermediaire.data(), BATCH * 16),
            std::span<uint8_t>(out.data() + block_start, BATCH * 16)
        );
    }
#undef BATCH
#define BATCH 1
    for (; i + BATCH <= num_blocks; i += BATCH) {
        std::memcpy(intermediaire.data(), keystream.data(), 256);

        for (size_t j = 0; j < BATCH; ++j) {
            uint32_t counter = counterStart + i + j;
            uint32_t swappedCounter = std::byteswap(counter);
            std::memcpy(intermediaire.data() + j * 16 + 12, &swappedCounter, 4);
        }

        m_CA.template encrypt_block<BATCH>(std::span<uint8_t, 256>(intermediaire).subspan(0).first<BATCH * 16>());

        size_t block_start = i * 16;

        MathsOperation::cl_xor(
            std::span<const uint8_t>(in.data() + block_start, BATCH * 16),
            std::span<const uint8_t>(intermediaire.data(), BATCH * 16),
            std::span<uint8_t>(out.data() + block_start, BATCH * 16)
        );
    }
#undef BATCH
}

template<CipherAlgorithm CA>
bool CTR<CA>::decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counterStart) {
    encrypt(in, out, nonce, counterStart);
    return true; // always, just for GCM / tag methods
}

#include "../../include/crypto/AES.h"

template class CTR<AES<128>>;
template class CTR<AES<192>>;
template class CTR<AES<256>>;

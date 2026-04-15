#include "../../include/crypto/CTR.h"
#include "../../include/utils/SafeArray.h"

template<CipherAlgorithm CA>
void CTR<CA>::encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counterStart) {
	uint32_t num_blocks = (in.size() + 15) / 16;
	out.reserve(in.size());

    SafeArray<16> counter_block = {};

    std::memcpy(counter_block.data(), nonce.data(), 12);

    for (uint32_t i = 0; i < num_blocks; i++) {
        uint32_t counter = counterStart + i;
        counter_block[12] = (counter >> 24) & 0xFF;
        counter_block[13] = (counter >> 16) & 0xFF;
        counter_block[14] = (counter >> 8) & 0xFF;
        counter_block[15] = (counter) & 0xFF;

        SafeArray<16> keystream = counter_block;
        m_CA.encrypt_block(std::span<uint8_t, 16>(keystream));

        size_t block_start = i * 16;
        size_t block_size = (i == num_blocks - 1) ? (in.size() - block_start) : 16;

        for (size_t j = 0; j < block_size; j++)
            out.push_back(in[block_start + j] ^ keystream[j]);
    }
}

template<CipherAlgorithm CA>
void CTR<CA>::decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counterStart) {
    encrypt(in, out, nonce, counterStart);
}


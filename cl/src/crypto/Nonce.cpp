#include <memory>
#include "../../include/crypto/CryptoRandom.h"
#include "../../include/crypto/Nonce.h"

template <size_t N>
	requires (N == 12 || N == 24)
Nonce<N>::Nonce() {
	CryptoRandom::fill(m_random_part);
}

template <size_t N>
	requires (N == 12 || N == 24)
bool Nonce<N>::GetNonce(std::span<uint8_t, N> out, uint64_t allocation) {
	if constexpr (N == 12) {
		if (allocation >= UINT32_MAX) { // TODO : Log warning
			return false;
		}
	}

	{
		std::lock_guard<std::mutex> lock(m_mtx);

		if ((uint64_t)(allocation + m_incremental_part) >= UINT32_MAX - 1) {
			CryptoRandom::fill(m_random_part);
			m_incremental_part = allocation;
		}
		else {
			m_incremental_part += allocation;
		}
	}

	std::memcpy(out.data(), m_random_part.data(), RANDOM_BYTES);

	for (uint8_t i = 0; i < COUNTER_BYTES; i++) {
		out[RANDOM_BYTES + i] = (m_incremental_part >> ((COUNTER_BYTES - 1 - i) * 8)) & 0xFF;
	}

	return true;
}


template class Nonce<12>;
template class Nonce<24>;

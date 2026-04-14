#pragma once
#include <span>
#include "../../include/utils/SafeArray.h"

template <size_t N>
	requires (N == 12 || N == 24 /* XChacha20 only */)
class Nonce {
public:
	void GetNonce(std::span<uint8_t, N> in, size_t allocation);
private:
	static constexpr size_t RANDOM_BYTES = (N / 8) * 2 / 3;
	static constexpr size_t COUNTER_BYTES = (N / 8) / 3;

	SafeArray<N> m_random_part;
	std::atomic<>
};



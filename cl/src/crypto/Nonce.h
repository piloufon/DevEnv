#pragma once
#include <span>
#include <atomic>
#include "../../include/utils/SafeArray.h"

template <size_t N>
	requires (N == 12 || N == 24 /* XChacha20 only */)
class Nonce {
public:
	Nonce();

	// Don't go higher than a UINT32_MAX, the uint64_t is just for warning
	bool GetNonce(std::span<uint8_t, N> in, uint64_t allocation);
private:
	static constexpr size_t RANDOM_BYTES = (N / 8) * 2 / 3;
	static constexpr size_t COUNTER_BYTES = (N / 8) / 3;
	using counter_t = std::conditional_t<N == 96, uint32_t, uint64_t>;

	SafeArray<N> m_random_part = {};
	std::atomic<counter_t> m_incremental_part = 0;
};

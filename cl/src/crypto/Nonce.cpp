#include "Nonce.h"

template <size_t N>
	requires (N == 12 || N == 24)
void Nonce<N>::GetNonce(std::span<uint8_t, N> in, size_t allocation) {
	return;
}

template class Nonce<12>;
template class Nonce<24>;

#include "../../include/utils/MathsOperation.h"
#include "../../include/utils/CPUFeatures.h"
#include <immintrin.h>
#include <cstdint>
#include <cassert>
#include <print>

// Ressource :
// https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html

namespace MathsOperation {
	template <size_t N>
		requires(N == 16 || N == 32 /* || N == 64*/)
	inline void xor_blocks_simd(std::span<const uint8_t, N> a, std::span<const uint8_t, N> b, std::span<uint8_t, N> out) {
		if constexpr (N == 16) {
			__m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a.data()));
			__m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b.data()));
			_mm_storeu_si128(reinterpret_cast<__m128i*>(out.data()), _mm_xor_si128(va, vb)); // SSE2
		}
		else if constexpr (N == 32) {
			__m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a.data()));
			__m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b.data()));
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(out.data()), _mm256_xor_si256(va, vb)); // AVX2
		}
	}

	void cl_multiply(std::span<uint8_t> a, std::span<uint8_t> b, std::span<uint8_t> out) {
		// Empty
	}
	void cl_divide(std::span<uint8_t> a, std::span<uint8_t> b, std::span<uint8_t> out) {
		// Empty
	}
	void cl_add(std::span<uint8_t> a, std::span<uint8_t> b, std::span<uint8_t> out) {
		// Empty
	}
	void cl_sub(std::span<uint8_t> a, std::span<uint8_t> b, std::span<uint8_t> out) {
		// Empty
	}

	void cl_xor(std::span<const uint8_t> a, std::span<const uint8_t> b, std::span<uint8_t> out) {
		if (a.size() != b.size() || a.size() != out.size()) {
			// Error, should tell to not forget out.empty(); out.resize(x);
			std::println("Size not matching for \"cl_xor\" ! Don't forget tu use \"out.empty(); out.resize(x);\n");
			return;
		}

		size_t i = 0;
		if (CPUFeatures::has_avx2()) [[likely]] {
			for (; i + 32 <= a.size(); i += 32) {
				xor_blocks_simd<32>(a.subspan(i).first<32>(), b.subspan(i).first<32>(), out.subspan(i).first<32>());
			}
		}

		if (CPUFeatures::has_sse2()) [[likely]] {
			for (; i + 16 <= a.size(); i += 16) {
				xor_blocks_simd<16>(a.subspan(i).first<16>(), b.subspan(i).first<16>(), out.subspan(i).first<16>());
			}
		}

		for (; i < a.size(); ++i)
			out[i] = a[i] ^ b[i];
	}

};

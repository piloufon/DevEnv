#include "../../include/utils/MathsOperation.h"
#include "../../include/utils/CPUFeatures.h"
#include <immintrin.h>
#include <cstdint>
#include <cassert>
#include <print>

// Ressource :
// https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html

namespace MathsOperation {

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
		if (a.size() != b.size() || a.size() != out.size()) [[unlikely]] {
			// Error, should tell to not forget out.empty(); out.resize(x);
			std::println("Size not matching for \"cl_xor\" ! Don't forget tu use \"out.empty(); out.resize(x);\n");
			return;
		}
		size_t size = a.size();
		const uint8_t* a_ptr = a.data();
		const uint8_t* b_ptr = b.data();
		uint8_t* out_ptr = out.data();

		size_t i = 0;
		if (CPUFeatures::has_avx512f()) [[likely]] {
			for (; i + 256 <= size; i += 256) {
				// Unrolling
				__m512i va0 = _mm512_loadu_si512((__m512i*)(a_ptr + i));
				__m512i va1 = _mm512_loadu_si512((__m512i*)(a_ptr + i + 64));
				__m512i va2 = _mm512_loadu_si512((__m512i*)(a_ptr + i + 128));
				__m512i va3 = _mm512_loadu_si512((__m512i*)(a_ptr + i + 192));

				__m512i vb0 = _mm512_loadu_si512((__m512i*)(b_ptr + i));
				__m512i vb1 = _mm512_loadu_si512((__m512i*)(b_ptr + i + 64));
				__m512i vb2 = _mm512_loadu_si512((__m512i*)(b_ptr + i + 128));
				__m512i vb3 = _mm512_loadu_si512((__m512i*)(b_ptr + i + 192));

				_mm512_storeu_si512((__m512i*)(out_ptr + i), _mm512_xor_epi32(va0, vb0));
				_mm512_storeu_si512((__m512i*)(out_ptr + i + 64), _mm512_xor_epi32(va1, vb1));
				_mm512_storeu_si512((__m512i*)(out_ptr + i + 128), _mm512_xor_epi32(va2, vb2));
				_mm512_storeu_si512((__m512i*)(out_ptr + i + 192), _mm512_xor_epi32(va3, vb3));
			}

			for (; i + 64 <= size; i += 64) {
				__m512i va = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(a_ptr + i));
				__m512i vb = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(b_ptr + i));
				_mm512_storeu_si512(reinterpret_cast<__m512i*>(out_ptr + i), _mm512_xor_epi32(va, vb));
			}
		}
		if (CPUFeatures::has_avx2()) [[likely]] {
			for (; i + 128 <= size; i += 128) {
				// Unrolling
				__m256i va0 = _mm256_loadu_si256((__m256i*)(a_ptr + i));
				__m256i va1 = _mm256_loadu_si256((__m256i*)(a_ptr + i + 32));
				__m256i va2 = _mm256_loadu_si256((__m256i*)(a_ptr + i + 64));
				__m256i va3 = _mm256_loadu_si256((__m256i*)(a_ptr + i + 96));

				__m256i vb0 = _mm256_loadu_si256((__m256i*)(b_ptr + i));
				__m256i vb1 = _mm256_loadu_si256((__m256i*)(b_ptr + i + 32));
				__m256i vb2 = _mm256_loadu_si256((__m256i*)(b_ptr + i + 64));
				__m256i vb3 = _mm256_loadu_si256((__m256i*)(b_ptr + i + 96));

				_mm256_storeu_si256((__m256i*)(out_ptr + i), _mm256_xor_si256(va0, vb0));
				_mm256_storeu_si256((__m256i*)(out_ptr + i + 32), _mm256_xor_si256(va1, vb1));
				_mm256_storeu_si256((__m256i*)(out_ptr + i + 64), _mm256_xor_si256(va2, vb2));
				_mm256_storeu_si256((__m256i*)(out_ptr + i + 96), _mm256_xor_si256(va3, vb3));
			}

			for (; i + 32 <= size; i += 32) {
				__m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a_ptr + i));
				__m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b_ptr + i));
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(out_ptr + i), _mm256_xor_si256(va, vb)); // AVX2
			}
		}

		if (CPUFeatures::has_sse2()) [[likely]] {
			for (; i + 16 <= size; i += 16) {
				__m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a_ptr + i));
				__m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b_ptr + i));
				_mm_storeu_si128(reinterpret_cast<__m128i*>(out_ptr + i), _mm_xor_si128(va, vb)); // SSE2
			}
		}

		for (; i < size; ++i)
			out[i] = a[i] ^ b[i];
	}

	template <size_t N>
	void cl_xor(std::span<const uint8_t, N> a, std::span<const uint8_t, N> b, std::span<uint8_t, N> out) {
		size_t i = 0;
		const uint8_t* a_ptr = a.data();
		const uint8_t* b_ptr = b.data();
		uint8_t* out_ptr = out.data();


		if (CPUFeatures::has_avx2()) [[likely]] {
			for (; i + 128 <= N; i += 128) {
				// Unrolling
				__m256i va0 = _mm256_loadu_si256((__m256i*)(a_ptr + i));
				__m256i va1 = _mm256_loadu_si256((__m256i*)(a_ptr + i + 32));
				__m256i va2 = _mm256_loadu_si256((__m256i*)(a_ptr + i + 64));
				__m256i va3 = _mm256_loadu_si256((__m256i*)(a_ptr + i + 96));

				__m256i vb0 = _mm256_loadu_si256((__m256i*)(b_ptr + i));
				__m256i vb1 = _mm256_loadu_si256((__m256i*)(b_ptr + i + 32));
				__m256i vb2 = _mm256_loadu_si256((__m256i*)(b_ptr + i + 64));
				__m256i vb3 = _mm256_loadu_si256((__m256i*)(b_ptr + i + 96));

				_mm256_storeu_si256((__m256i*)(out_ptr + i), _mm256_xor_si256(va0, vb0));
				_mm256_storeu_si256((__m256i*)(out_ptr + i + 32), _mm256_xor_si256(va1, vb1));
				_mm256_storeu_si256((__m256i*)(out_ptr + i + 64), _mm256_xor_si256(va2, vb2));
				_mm256_storeu_si256((__m256i*)(out_ptr + i + 96), _mm256_xor_si256(va3, vb3));
			}

			for (; i + 32 <= N; i += 32) {
				__m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a_ptr + i));
				__m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b_ptr + i));
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(out_ptr + i), _mm256_xor_si256(va, vb)); // AVX2
			}
		}

		if (CPUFeatures::has_sse2()) [[likely]] {
			for (; i + 16 <= N; i += 16) {
				__m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a_ptr + i));
				__m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b_ptr + i));
				_mm_storeu_si128(reinterpret_cast<__m128i*>(out_ptr + i), _mm_xor_si128(va, vb)); // SSE2
			}
		}

		for (; i < N; ++i)
			out[i] = a[i] ^ b[i];
	}

	template void cl_xor<16>(std::span<const uint8_t, 16>, std::span<const uint8_t, 16>, std::span<uint8_t, 16>);
	template void cl_xor<32>(std::span<const uint8_t, 32>, std::span<const uint8_t, 32>, std::span<uint8_t, 32>);
	template void cl_xor<64>(std::span<const uint8_t, 64>, std::span<const uint8_t, 64>, std::span<uint8_t, 64>);
	template void cl_xor<128>(std::span<const uint8_t, 128>, std::span<const uint8_t, 128>, std::span<uint8_t, 128>);
	template void cl_xor<256>(std::span<const uint8_t, 256>, std::span<const uint8_t, 256>, std::span<uint8_t, 256>);
	template void cl_xor<2048>(std::span<const uint8_t, 2048>, std::span<const uint8_t, 2048>, std::span<uint8_t, 2048>);
};
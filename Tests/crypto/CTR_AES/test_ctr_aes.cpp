#include "test_ecb_aes.h"
#include "../cl/include/crypto/CTR_AES.h"
#include "../cl/include/crypto/CryptoRandom.h"
#include <cstdint>
#include <array>
#include <vector>
#include <print>

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_coformity() {
	bool success = true;
	std::vector<uint8_t> pt_16(16, 0);
	std::vector<uint8_t> pt_32(32, 0);
	std::vector<uint8_t> pt_48(48, 0);

	std::vector<uint8_t> result(128, 0);
	std::vector<uint8_t> ciphertext(128, 0);
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);

	CryptoRandom::fill(pt_16);
	CryptoRandom::fill(pt_32);
	CryptoRandom::fill(pt_48);
	CryptoRandom::fill(result); // To fill with garbage
	CryptoRandom::fill(ciphertext);

	CTR_AES<N> aes(key);
	{
		ciphertext.resize(16);
		if (size_t enc_success = aes.encrypt(pt_16, ciphertext, nonce, 0)) {
			std::println("Failed check_coformity - pt_16 CTR_AES<{}>::encrypt(pt_16, ciphertext, nonce, 0)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
			success = false;
		}
		// Same as encrypt but if I were to change decrypt and messed up, it will be catch here, but the real test should be x2 encrypt for enc + dec
		if (size_t dec_success = aes.decrypt(ciphertext, result, nonce, 0)) {
			std::println("Failed check_coformity - pt_16 CTR_AES<{}>::encrypt(ciphertext, result, nonce, 0)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(dec_success));
			success = false;
		}
		int diff = std::memcmp(result.data(), pt_16.data(), pt_16.size());
		if (diff) {
			std::println("Failed check_coformity - pt_16 CTR_AES<{}> result != pt_16", N);
			success = false;
		}
	}
	{
		ciphertext.resize(32);
		if (size_t enc_success = aes.encrypt(pt_32, ciphertext, nonce, 0)) {
			std::println("Failed check_coformity - pt_32 CTR_AES<{}>::encrypt(pt_32, ciphertext, nonce, 0)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
			success = false;
		}
		if (size_t dec_success = aes.encrypt(ciphertext, result, nonce, 0)) {
			std::println("Failed check_coformity - pt_32 CTR_AES<{}>::encrypt(ciphertext, result, nonce, 0)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(dec_success));
			success = false;
		}
		int diff = std::memcmp(result.data(), pt_32.data(), pt_32.size());
		if (diff) {
			std::println("Failed check_coformity - pt_32 CTR_AES<{}> result != pt_32", N);
			success = false;
		}
	}
	{
		ciphertext.resize(48);
		if (size_t enc_success = aes.encrypt(pt_48, ciphertext, nonce, 0)) {
			std::println("Failed check_coformity - pt_48 CTR_AES<{}>::encrypt(pt_48, ciphertext, nonce, 0)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
			success = false;
		}
		if (size_t dec_success = aes.encrypt(ciphertext, result, nonce, 0)) {
			std::println("Failed check_coformity - pt_48 CTR_AES<{}>::encrypt(ciphertext, result, nonce, 0)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(dec_success));
			success = false;
		}
		int diff = std::memcmp(result.data(), pt_48.data(), pt_48.size());
		if (diff) {
			std::println("Failed check_coformity - pt_48 CTR_AES<{}> result != pt_48", N);
			success = false;
		}
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_boundary_sizes() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	CTR_AES<N> aes(key);

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);

	static constexpr size_t sizes[] = {
		0, 1, 2, 3, 4, 5, 6,
		7, 8, 9, 10, 11, 12,
		13, 14, 15, 16, 17,
		31, 32, 33, 47, 63,
		64, 65, 100, 128, 255,
		256, 257, 1000, 1040,
		320, 80, 81, 321, 1056
	};

	for (size_t size : sizes) {
		std::vector<uint8_t> plaintext(size);
		if (size > 0) {
			CryptoRandom::fill(plaintext);
		}

		std::vector<uint8_t> ciphertext(size);
		std::vector<uint8_t> result(256, 0);
		CryptoRandom::fill(ciphertext);
		CryptoRandom::fill(result);

		if (size_t enc_success = aes.encrypt(plaintext, ciphertext, nonce, 0)) {
			std::println("Failed check_boundary_sizes CTR_AES<{}>::encrypt(plaintext, ciphertext, nonce, 0)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
			success = false;
			continue;
		}
		if (size_t dec_success = aes.encrypt(ciphertext, result, nonce, 0)) {
			std::println("Failed check_boundary_sizes CTR_AES<{}>::encrypt(ciphertext, result, nonce, 0)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(dec_success));
			success = false;
			continue;
		}

		int diff = std::memcmp(result.data(), plaintext.data(), plaintext.size());
		if (diff) {
			std::println("Failed check_boundary_sizes CTR_AES<{}> result != plaintext", N);
			if (result.size() != plaintext.size())
				std::println("For size: {}\nMismatch: got {} bytes, expected {}", size, result.size(), plaintext.size());

			success = false;
		}
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_output_buffer_too_small() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	CTR_AES<N> aes(key);

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);

	std::vector<uint8_t> plaintext(32);
	CryptoRandom::fill(plaintext);

	const size_t needed = plaintext.size();
	std::vector<uint8_t> ciphertext(needed - 1);
	std::array<uint8_t, 31> ciphertext_arr;

	size_t enc_success = aes.encrypt(plaintext, std::span<uint8_t>(ciphertext), nonce, 0);
	if (enc_success != 2ULL /* InvalidOutputSize */) {
		std::println("Failed check_output_buffer_too_small CTR_AES<{}>::encrypt(plaintext, ciphertext), nonce, 0", N);
		std::println("error_code: {}", enc_success);
		std::println("Expected: \"InvalidOutputSize\", got \"{}\"", CTR_AES<N>::get_error_message(enc_success));
		success = false;
	}
	enc_success = aes.encrypt(plaintext, ciphertext_arr, nonce, 0);
	if (enc_success != 2ULL /* InvalidOutputSize */) {
		std::println("Failed check_output_buffer_too_small CTR_AES<{}>::encrypt(plaintext, ciphertext_arr, nonce, 0)", N);
		std::println("error_code: {}", enc_success);
		std::println("Expected: \"InvalidOutputSize\", got \"{}\"", CTR_AES<N>::get_error_message(enc_success));
		success = false;
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_counter_overflow() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	CTR_AES<N> aes(key);

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);

	{
		std::vector<uint8_t> plaintext(32);
		CryptoRandom::fill(plaintext);
		std::vector<uint8_t> ciphertext(32);

		size_t enc_success = aes.encrypt(plaintext, ciphertext, nonce, UINT32_MAX);
		if (enc_success != 1ULL /* CounterOverflow */) {
			std::println("Failed check_counter_overflow CTR_AES<{}>::encrypt(plaintext, ciphertext, nonce, UINT32_MAX)", N);
			std::println("error_code: {}", enc_success);
			std::println("Expected: \"CounterOverflow\", got \"{}\"", CTR_AES<N>::get_error_message(enc_success));
			success = false;
		}
	}

	{
		std::vector<uint8_t> plaintext(16);
		CryptoRandom::fill(plaintext);
		std::vector<uint8_t> ciphertext(16);

		size_t enc_success = aes.encrypt(plaintext, ciphertext, nonce, UINT32_MAX);
		if (enc_success != 0) {
			std::println("Failed check_counter_overflow CTR_AES<{}>::encrypt(plaintext, ciphertext, nonce, UINT32_MAX)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
			success = false;
		}
	}
	{
		std::vector<uint8_t> plaintext(16 * 5);
		CryptoRandom::fill(plaintext);
		std::vector<uint8_t> ciphertext(16 * 5);

		size_t enc_success = aes.encrypt(plaintext, ciphertext, nonce, UINT32_MAX - 4);
		if (enc_success != 0) {
			std::println("Failed check_counter_overflow CTR_AES<{}>::encrypt(plaintext, ciphertext, nonce, UINT32_MAX - 4)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
			success = false;
		}
	}

	{
		std::vector<uint8_t> plaintext(1000);
		CryptoRandom::fill(plaintext);
		std::vector<uint8_t> ciphertext(1000);

		size_t enc_success = aes.encrypt(plaintext, ciphertext, nonce, 0);
		if (enc_success != 0) {
			std::println("Failed check_counter_overflow CTR_AES<{}>::encrypt(plaintext, ciphertext, nonce, 0)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
			success = false;
		}
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_identical_blocks_differ() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	CTR_AES<N> aes(key);

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);

	std::vector<uint8_t> block(16);
	CryptoRandom::fill(block);

	std::vector<uint8_t> plaintext;
	plaintext.insert(plaintext.end(), block.begin(), block.end());
	plaintext.insert(plaintext.end(), block.begin(), block.end());
	plaintext.insert(plaintext.end(), block.begin(), block.end());

	std::vector<uint8_t> ciphertext;
	if (size_t enc_success = aes.encrypt(plaintext, ciphertext, nonce, 0)) {
		std::println("Failed check_identical_blocks_differ CTR_AES<{}>::encrypt(plaintext, ciphertext, nonce, 0)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
		return false;
	}

	std::span<const uint8_t> ct_block0(ciphertext.data() + 0, 16);
	std::span<const uint8_t> ct_block1(ciphertext.data() + 16, 16);
	std::span<const uint8_t> ct_block2(ciphertext.data() + 32, 16);

	if (std::equal(ct_block0.begin(), ct_block0.end(), ct_block1.begin())) {
		std::println("Failed check_identical_blocks_differ CTR_AES<{}>", N);
		success = false;
	}
	if (std::equal(ct_block1.begin(), ct_block1.end(), ct_block2.begin())) {
		std::println("Failed check_identical_blocks_differ CTR_AES<{}>", N);
		success = false;
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_error_messages() {
	bool success = true;
	std::vector<const char*> messages = { "Success", "CounterOverflow", "InvalidOutputSize", "Unkown" };

	for (uint8_t i = 0; i < 4; i++) {
		const char* got = CTR_AES<N>::get_error_message(i);

		if (std::strcmp(got, messages[i]) != 0) {
			std::println("Failed check_error_messages CTR_AES<{}>::get_error_message({})", N, messages[i]);
			std::println("Expected: \"{}\", got: \"{}\"", messages[i], got);
			success = false;
		}
	}
	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_key_bit_flip() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);

	SafeArray<N / 8> flipped_key(key);
	flipped_key[0] ^= 0x01;

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);

	std::vector<uint8_t> plaintext(32);
	CryptoRandom::fill(plaintext);

	CTR_AES<N> aes(key);
	CTR_AES<N> aes_flipped(flipped_key);

	std::vector<uint8_t> ciphertext;
	std::vector<uint8_t> ciphertext_flipped;

	if (size_t enc_success = aes.encrypt(plaintext, ciphertext, nonce, 0)) {
		std::println("Failed check_key_bit_flip CTR_AES<{}>::encrypt(plaintext, ciphertext, nonce, 0)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
		success = false;
	}
	if (size_t enc_success = aes_flipped.encrypt(plaintext, ciphertext_flipped, nonce, 0)) {
		std::println("Failed check_key_bit_flip CTR_AES<{}>::encrypt(plaintext, ciphertext_flipped, nonce, 0)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
		success = false;
	}

	if (ciphertext == ciphertext_flipped) {
		std::println("Failed check_key_bit_flip CTR_AES<{}>", N);
		success = false;
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_nonce_bit_flip() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	CTR_AES<N> aes(key);

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);
	std::array<uint8_t, 12> flipped_nonce = nonce;
	flipped_nonce[0] ^= 0x01;

	std::vector<uint8_t> plaintext(32);
	CryptoRandom::fill(plaintext);

	std::vector<uint8_t> ciphertext;
	std::vector<uint8_t> ciphertext_flipped;

	if (size_t enc_success = aes.encrypt(plaintext, ciphertext, nonce, 0)) {
		std::println("Failed check_nonce_bit_flip CTR_AES<{}>::encrypt(plaintext, ciphertext, nonce, 0)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
		success = false;
	}
	if (size_t enc_success = aes.encrypt(plaintext, ciphertext_flipped, flipped_nonce, 0)) {
		std::println("Failed check_nonce_bit_flip CTR_AES<{}>::encrypt(plaintext, ciphertext_flipped, flipped_nonce, 0)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
		success = false;
	}

	if (ciphertext == ciphertext_flipped) {
		std::println("Failed check_nonce_bit_flip CTR_AES<{}>", N);
		success = false;
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_encrypt_overloads_consistency() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	CTR_AES<N> aes(key);

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);

	static constexpr size_t sizes[] = { 0, 1, 15, 16, 17, 32, 47, 80, 320, 1000 };

	for (size_t size : sizes) {
		std::vector<uint8_t> plaintext(size);
		if (size > 0) {
			CryptoRandom::fill(plaintext);
		}

		std::vector<uint8_t> ct_by_ref;
		size_t enc_success_ref = aes.encrypt(plaintext, ct_by_ref, nonce, 0);

		std::vector<uint8_t> ct_by_span(size);
		size_t enc_success_span = aes.encrypt(plaintext, std::span<uint8_t>(ct_by_span), nonce, 0);

		if (enc_success_ref) {
			std::println("Failed check_encrypt_overloads_consistency - vector& overload CTR_AES<{}>::encrypt(plaintext, ct_by_ref, nonce, 0), size: {}", N, size);
			std::println("error_code: {}", enc_success_ref);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success_ref));
			success = false;
			continue;
		}
		if (enc_success_span) {
			std::println("Failed check_encrypt_overloads_consistency - span overload CTR_AES<{}>::encrypt(plaintext, ct_by_span, nonce, 0), size: {}", N, size);
			std::println("error_code: {}", enc_success_span);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success_span));
			success = false;
			continue;
		}

		if (ct_by_ref.size() != size) {
			std::println("Failed check_encrypt_overloads_consistency CTR_AES<{}> wrong output size, size={}", N, size);
			success = false;
			continue;
		}

		if (ct_by_ref != ct_by_span) {
			std::println("Failed check_encrypt_overloads_consistency CTR_AES<{}> overloads disagree on output, size={}", N, size);
			success = false;
			continue;
		}

		std::vector<uint8_t> result;
		if (size_t dec_success = aes.decrypt(ct_by_ref, result, nonce, 0)) {
			std::println("Failed check_encrypt_overloads_consistency CTR_AES<{}>::decrypt(ct_by_ref, result, nonce, 0), size: {}", N, size);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", CTR_AES<N>::get_error_message(dec_success));
			success = false;
			continue;
		}
		if (result != plaintext) {
			std::println("Failed check_encrypt_overloads_consistency CTR_AES<{}>, size: {}", N, size);
			success = false;
		}
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_aliasing_conformity() {
	bool success = true;
	constexpr size_t size = 128;
	std::vector<uint8_t> blocks(size, 0);
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	CryptoRandom::fill(blocks);
	std::vector<uint8_t> original = blocks;

	std::array<uint8_t, 12> nonce;
	CryptoRandom::fill(nonce);

	CTR_AES<N> aes(key);

	if (size_t enc_success = aes.encrypt(std::span<uint8_t>(blocks), std::span<uint8_t>(blocks), nonce, 0)) {
		std::println("Failed check_aliasing_conformity CTR_AES<{}>::encrypt(std::span<uint8_t>(blocks), std::span<uint8_t>(blocks), nonce, 0)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", CTR_AES<N>::get_error_message(enc_success));
		success = false;
	}

	if (size_t dec_success = aes.decrypt(blocks, blocks, nonce, 0)) {
		std::println("Failed check_aliasing_conformity CTR_AES<{}>::decrypt(blocks, blocks, nonce, 0)", N);
		std::println("error_code: {}", dec_success);
		std::println("error_message: {}", CTR_AES<N>::get_error_message(dec_success));
		success = false;
	}

	if (blocks != original) {
		std::println("Failed check_aliasing_conformity CTR_AES<{}>", N);
		success = false;
	}

	return success;
}

int test_ctr_aes_128(){
	int failed = 0;

	if (!check_coformity<128>()) failed++;
	if (!check_boundary_sizes<128>()) failed++;
	if (!check_output_buffer_too_small<128>()) failed++;
	if (!check_counter_overflow<128>()) failed++;
	if (!check_identical_blocks_differ<128>()) failed++;
	if (!check_error_messages<128>()) failed++;
	if (!check_key_bit_flip<128>()) failed++;
	if (!check_nonce_bit_flip<128>()) failed++;
	if (!check_encrypt_overloads_consistency<128>()) failed++;
	if (!check_aliasing_conformity<128>()) failed++;

	return failed;
}
int test_ctr_aes_192(){
	int failed = 0;

	if (!check_coformity<192>()) failed++;
	if (!check_boundary_sizes<192>()) failed++;
	if (!check_output_buffer_too_small<192>()) failed++;
	if (!check_counter_overflow<192>()) failed++;
	if (!check_identical_blocks_differ<192>()) failed++;
	if (!check_error_messages<192>()) failed++;
	if (!check_key_bit_flip<192>()) failed++;
	if (!check_nonce_bit_flip<192>()) failed++;
	if (!check_encrypt_overloads_consistency<192>()) failed++;
	if (!check_aliasing_conformity<192>()) failed++;

	return failed;
}
int test_ctr_aes_256(){
	int failed = 0;

	if (!check_coformity<256>()) failed++;
	if (!check_boundary_sizes<256>()) failed++;
	if (!check_output_buffer_too_small<256>()) failed++;
	if (!check_counter_overflow<256>()) failed++;
	if (!check_identical_blocks_differ<256>()) failed++;
	if (!check_error_messages<256>()) failed++;
	if (!check_key_bit_flip<256>()) failed++;
	if (!check_nonce_bit_flip<256>()) failed++;
	if (!check_encrypt_overloads_consistency<256>()) failed++;
	if (!check_aliasing_conformity<256>()) failed++;

	return failed;
}

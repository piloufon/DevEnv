#include "test_ecb_aes.h"
#include "../cl/include/crypto/ECB_AES.h"
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

	CryptoRandom::fill(pt_16);
	CryptoRandom::fill(pt_32);
	CryptoRandom::fill(pt_48);
	CryptoRandom::fill(result); // To fill with garbage
	CryptoRandom::fill(ciphertext);

	ECB_AES<N> aes(key);
	{
		ciphertext.resize(32);
		if (size_t enc_success = aes.encrypt(pt_16, std::span<uint8_t>(ciphertext))) {
			std::println("Failed check_coformity - pt_16 ECB_AES<{}>::encrypt(pt_16, ciphertext)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
			success = false;
		}
		if (size_t dec_success = aes.decrypt(ciphertext, result)) {
			std::println("Failed check_coformity - pt_16 ECB_AES<{}>::decrypt(ciphertext, result)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(dec_success));
			success = false;
		}
		if (result != pt_16) {
			std::println("Failed check_coformity - pt_16 ECB_AES<{}> result != pt_16", N);
			success = false;
		}
	}
	{
		ciphertext.resize(48);
		if (size_t enc_success = aes.encrypt(pt_32, std::span<uint8_t>(ciphertext))) {
			std::println("Failed check_coformity - pt_32 ECB_AES<{}>::encrypt(pt_32, ciphertext)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
			success = false;
		}
		if (size_t dec_success = aes.decrypt(ciphertext, result)) {
			std::println("Failed check_coformity - pt_32 ECB_AES<{}>::decrypt(ciphertext, result)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(dec_success));
			success = false;
		}
		if (result != pt_32) {
			std::println("Failed check_coformity - pt_32 ECB_AES<{}> result != pt_32", N);
			success = false;
		}
	}
	{
		ciphertext.resize(64);
		if (size_t enc_success = aes.encrypt(pt_48, std::span<uint8_t>(ciphertext))) {
			std::println("Failed check_coformity - pt_48 ECB_AES<{}>::encrypt(pt_48, ciphertext)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
			success = false;
		}
		if (size_t dec_success = aes.decrypt(ciphertext, result)) {
			std::println("Failed check_coformity - pt_48 ECB_AES<{}>::decrypt(ciphertext, result)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(dec_success));
			success = false;
		}
		if (result != pt_48) {
			std::println("Failed check_coformity - pt_48 ECB_AES<{}> result != pt_48", N);
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
	ECB_AES<N> aes(key);

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

		const size_t needed = ECB_AES<N>::encryption_size_out(size);
		std::vector<uint8_t> ciphertext(needed);
		std::vector<uint8_t> result(256, 0);
		CryptoRandom::fill(ciphertext);
		CryptoRandom::fill(result);

		if (size_t enc_success = aes.encrypt(plaintext, std::span<uint8_t>(ciphertext))) {
			std::println("Failed check_boundary_sizes ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
			success = false;
			continue;
		}
		if (size_t dec_success = aes.decrypt(ciphertext, result)) {
			std::println("Failed check_boundary_sizes ECB_AES<{}>::decrypt(plaintext, ciphertext)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(dec_success));
			success = false;
			continue;
		}

		if (result != plaintext) {
			std::println("Failed check_boundary_sizes ECB_AES<{}> result != plaintext", N);
			if(result.size() != plaintext.size())
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
	ECB_AES<N> aes(key);

	std::vector<uint8_t> plaintext(32);
	CryptoRandom::fill(plaintext);

	const size_t needed = ECB_AES<N>::encryption_size_out(plaintext.size());
	std::vector<uint8_t> ciphertext(needed - 1);

	size_t enc_success = aes.encrypt(plaintext, std::span<uint8_t>(ciphertext));
	if (enc_success == 0 || enc_success != 2ULL /* Same, but the hardcoded 2ULL can be commented */) {
		std::println("Failed check_output_buffer_too_small ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
		std::println("error_code: {}", enc_success);
		std::println("Expected: \"InvalidOutputSize\", got \"{}\"", ECB_AES<N>::get_error_message(enc_success));
		success = false;
	}
	
	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_output_buffer_exact_and_larger() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	ECB_AES<N> aes(key);

	std::vector<uint8_t> plaintext(20);
	CryptoRandom::fill(plaintext);
	const size_t needed = ECB_AES<N>::encryption_size_out(plaintext.size());

	{
		std::vector<uint8_t> ciphertext(needed);
		size_t enc_success = aes.encrypt(plaintext, ciphertext);
		if (enc_success != 0) {
			std::println("Failed check_output_buffer_exact_and_larger - exact-size output buffer ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
			success = false;
		}
	}

	{
		constexpr uint8_t filler = 0xAA;
		std::vector<uint8_t> ciphertext(needed + 16, filler);
		size_t enc_success = aes.encrypt(plaintext, ciphertext);
		if (enc_success != 0) {
			std::println("Failed check_output_buffer_exact_and_larger - larger output buffer ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
			success = false;
		}

		for (size_t i = needed; i < ciphertext.size(); ++i) {
			if (ciphertext[i] != filler) {
				std::println("Failed check_output_buffer_exact_and_larger ECB_AES<{}> byte {} was overwritten (0x{:02x} instead of 0x{:02x})", N, i, ciphertext[i], filler);
				success = false;
				break;
			}
		}
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_wrong_input_size() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	ECB_AES<N> aes(key);

	std::vector<uint8_t> plaintext(20);
	CryptoRandom::fill(plaintext);
	const size_t needed = ECB_AES<N>::encryption_size_out(plaintext.size());

	{
		std::vector<uint8_t> ciphertext(needed);
		size_t enc_success = aes.encrypt(plaintext, ciphertext);
		if (enc_success != 0) {
			std::println("Failed check_wrong_input_size ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
			success = false;
		}
		std::vector<uint8_t> result;
		ciphertext.push_back(CryptoRandom::generate<uint8_t>());
		size_t dec_success = aes.decrypt(ciphertext, result);
		if (dec_success == 0 || dec_success != 1ULL /* Same, but the hardcoded 1ULL can be commented */) {
			std::println("Failed check_wrong_input_size ECB_AES<{}>::decrypt(ciphertext, result)", N);
			std::println("error_code: {}", dec_success);
			std::println("Expected: \"InvalidInputSize\", got \"{}\"", ECB_AES<N>::get_error_message(dec_success));
			success = false;
		}
	}
	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_fake_padding_cropping() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	ECB_AES<N> aes(key);

	std::vector<uint8_t> plaintext(32);
	CryptoRandom::fill(plaintext);
	for (uint8_t i = 0; i < 0x11; i++) {
		std::memset(plaintext.data() + 16, i, 16);
	
		std::vector<uint8_t> ciphertext;
		std::vector<uint8_t> result;
		size_t enc_success = aes.encrypt(plaintext, ciphertext);
		if (enc_success != 0) {
			std::println("Failed check_fake_padding_cropping ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
			std::println("error_code: {}", enc_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
			success = false;
			break;
		}

		size_t dec_success = aes.decrypt(ciphertext, result);
		if (dec_success != 0) {
			std::println("Failed check_fake_padding_cropping ECB_AES<{}>::decrypt(ciphertext, result)", N);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(dec_success));
			success = false;
			break;
		}

		if (plaintext != result) {
			std::println("Failed check_fake_padding_cropping ECB_AES<{}> end byte (0x{:02x} was cropped from {} bytes to {} bytes", N, i, plaintext.size(), result.size());
			success = false;
			break;
		}
	}
	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_tampered_padding(uint8_t padding) {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	ECB_AES<N> aes(key);

	std::vector<uint8_t> plaintext(32);
	CryptoRandom::fill(plaintext);
	std::vector<uint8_t> ciphertext;
	if (size_t enc_success = aes.encrypt(plaintext, ciphertext)) {
		std::println("Failed check_tampered_padfing ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
		success = false;
	}
	std::vector<uint8_t> tampering(16, 0);
	CryptoRandom::fill(tampering);
	tampering[15] = padding;
	if (tampering[14] == padding)
		tampering[14] = (padding % 2) + 1;

	std::vector<uint8_t> tampered;
	if (size_t enc_success = aes.encrypt(tampering, tampered)) {
		std::println("Failed check_tampered_padfing ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
		success = false;
	}

	std::memcpy(ciphertext.data() + 32, tampered.data(), 16);
	std::vector<uint8_t> result;
	size_t dec_success = aes.decrypt(ciphertext, result);
	if (dec_success == 0 || dec_success != 3ULL /* InvalidPadding*/) {
		std::println("Failed check_padding_zero_byte ECB_AES<{}>::decrypt", N);
		std::println("error_code: {}", dec_success);
		std::println("Expected: \"InvalidPadding\", got \"{}\"", ECB_AES<N>::get_error_message(dec_success));
		success = false;
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_identical_blocks() {
	bool success = true;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	ECB_AES<N> aes(key);

	std::vector<uint8_t> block(16);
	CryptoRandom::fill(block);

	std::vector<uint8_t> plaintext;
	plaintext.insert(plaintext.end(), block.begin(), block.end());
	plaintext.insert(plaintext.end(), block.begin(), block.end());

	std::vector<uint8_t> other(16);
	CryptoRandom::fill(other);
	plaintext.insert(plaintext.end(), other.begin(), other.end());

	std::vector<uint8_t> ciphertext;
	if (size_t enc_success = aes.encrypt(plaintext, ciphertext)) {
		std::println("Failed check_identical_blocks ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
		return false;
	}

	std::span<const uint8_t> ct_block0(ciphertext.data() + 0, 16);
	std::span<const uint8_t> ct_block1(ciphertext.data() + 16, 16);
	std::span<const uint8_t> ct_block2(ciphertext.data() + 32, 16);

	// Damn girl you live like this
	if (!std::equal(ct_block0.begin(), ct_block0.end(), ct_block1.begin())) {
		std::println("Failed check_identical_blocks ECB_AES<{}> identical plaintext blocks produced different ciphertext blocks", N);
		success = false;
	}

	if (std::equal(ct_block0.begin(), ct_block0.end(), ct_block2.begin())) {
		std::println("Failed check_identical_blocks ECB_AES<{}> different plaintext block produced identical ciphertext (suspiciously unlikely, check key/logic)", N);
		success = false;
	}

	return success;
}

template <size_t N>
	requires(N == 128 || N == 192 || N == 256)
bool check_error_messages() {
	bool success = true;
	std::vector<const char*> messages = { "Success", "InvalidInputSize", "InvalidOutputSize", "InvalidPadding", "Unkown" };

	for (uint8_t i = 0; i < 5; i++) {
		const char* got = ECB_AES<N>::get_error_message(i);

		if (std::strcmp(got, messages[i]) != 0) {
			std::println("Failed check_error_messages ECB_AES<{}>::get_error_message({})", N, messages[i]);
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

	std::vector<uint8_t> plaintext(32);
	CryptoRandom::fill(plaintext);

	ECB_AES<N> aes(key);
	ECB_AES<N> aes_flipped(flipped_key);

	std::vector<uint8_t> ciphertext;
	std::vector<uint8_t> ciphertext_flipped;

	if (size_t enc_success = aes.encrypt(plaintext, ciphertext)) {
		std::println("Failed check_key_bit_flip ECB_AES<{}>::encrypt(plaintext, ciphertext)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
		success = false;
	}
	if (size_t enc_success = aes_flipped.encrypt(plaintext, ciphertext_flipped)) {
		std::println("Failed check_key_bit_flip ECB_AES<{}>::encrypt(plaintext, ciphertext_flipped)", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
		success = false;
	}

	if (ciphertext == ciphertext_flipped) {
		std::println("Failed check_key_bit_flip ECB_AES<{}> ciphertext identical after 1-bit key flip", N);
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
	ECB_AES<N> aes(key);

	static constexpr size_t sizes[] = { 0, 1, 15, 16, 17, 32, 47, 80, 320, 1000 };

	for (size_t size : sizes) {
		std::vector<uint8_t> plaintext(size);
		if (size > 0) {
			CryptoRandom::fill(plaintext);
		}

		const size_t needed = ECB_AES<N>::encryption_size_out(size);

		std::vector<uint8_t> ct_by_value = aes.encrypt(plaintext);

		std::vector<uint8_t> ct_by_ref;
		size_t enc_success_ref = aes.encrypt(plaintext, ct_by_ref);

		std::vector<uint8_t> ct_by_span(needed);
		size_t enc_success_span = aes.encrypt(plaintext, std::span<uint8_t>(ct_by_span));

		if (enc_success_ref) {
			std::println("Failed check_encrypt_overloads_consistency - vector& overload ECB_AES<{}>::encrypt(plaintext, ct_by_ref), size={}", N, size);
			std::println("error_code: {}", enc_success_ref);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success_ref));
			success = false;
			continue;
		}
		if (enc_success_span) {
			std::println("Failed check_encrypt_overloads_consistency - span overload ECB_AES<{}>::encrypt(plaintext, ct_by_span), size={}", N, size);
			std::println("error_code: {}", enc_success_span);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success_span));
			success = false;
			continue;
		}

		if (ct_by_value.size() != needed || ct_by_ref.size() != needed) {
			std::println("Failed check_encrypt_overloads_consistency ECB_AES<{}> wrong output size, size={}", N, size);
			success = false;
			continue;
		}

		if (ct_by_value != ct_by_span || ct_by_ref != ct_by_span) {
			std::println("Failed check_encrypt_overloads_consistency ECB_AES<{}> overloads disagree on output, size={}", N, size);
			success = false;
			continue;
		}

		std::vector<uint8_t> result;
		if (size_t dec_success = aes.decrypt(ct_by_value, result)) {
			std::println("Failed check_encrypt_overloads_consistency - round-trip ECB_AES<{}>::decrypt(ct_by_value, result), size={}", N, size);
			std::println("error_code: {}", dec_success);
			std::println("error_message: {}", ECB_AES<N>::get_error_message(dec_success));
			success = false;
			continue;
		}
		if (result != plaintext) {
			std::println("Failed check_encrypt_overloads_consistency ECB_AES<{}> result != plaintext, size={}", N, size);
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
	std::vector<uint8_t> result;
	SafeArray<N / 8> key;
	CryptoRandom::fill(key);
	CryptoRandom::fill(blocks);
	
	ECB_AES<N> aes(key);

	if (size_t enc_success = aes.encrypt(std::vector<uint8_t>(blocks.begin(), blocks.end() - 16 /* * sizeof(uint8_t) but = 1 so np */), blocks)) {
		std::println("Failed check_aliasing_conformity ECB_AES<{}>::encryptstd::span<uint8_t, size - 16>(blocks.data(), size - 16), std::span<uint8_t, size>(blocks.data(), size))", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
		success = false;
	}
	if(size_t enc_success = aes.encrypt(std::span<uint8_t, size - 16>(blocks.data(), size - 16), blocks)) {
		std::println("Failed check_aliasing_conformity ECB_AES<{}>::encryptstd::span<uint8_t, size - 16>(blocks.data(), size - 16), std::span<uint8_t, size>(blocks.data(), size))", N);
		std::println("error_code: {}", enc_success);
		std::println("error_message: {}", ECB_AES<N>::get_error_message(enc_success));
		success = false;
	}

	if (size_t dec_success = aes.decrypt(blocks, result)) {
		std::println("Failed check_aliasing_conformity ECB_AES<{}>::decrypt(std::span<uint8_t, size - 16>(blocks.data(), size - 16), blocks)", N);
		std::println("error_code: {}", dec_success);
		std::println("error_message: {}", ECB_AES<N>::get_error_message(dec_success));
		success = false;
	}

	return success;
}

int test_ecb_aes_128() {
	int failed = 0;
	if (!check_coformity<128>()) failed++;
	if (!check_boundary_sizes<128>()) failed++;
	if (!check_output_buffer_too_small<128>()) failed++;
	if (!check_output_buffer_exact_and_larger<128>()) failed++;
	if (!check_wrong_input_size<128>()) failed++;
	if (!check_fake_padding_cropping<128>()) failed++;
	if (!check_tampered_padding<128>(0)) failed++;
	if (!check_tampered_padding<128>(17)) failed++;
	if (!check_tampered_padding<128>(255)) failed++;
	if (!check_tampered_padding<128>(2)) failed++;
	if (!check_error_messages<128>()) failed++;
	if (!check_identical_blocks<128>()) failed++;
	if (!check_key_bit_flip<128>()) failed++;
	if (!check_encrypt_overloads_consistency<128>()) failed++;
	if (!check_aliasing_conformity<128>()) failed++;

	return failed;
}
int test_ecb_aes_192() {
	int failed = 0;

	if (!check_coformity<192>()) failed++;
	if (!check_boundary_sizes<192>()) failed++;
	if (!check_output_buffer_too_small<192>()) failed++;
	if (!check_output_buffer_exact_and_larger<192>()) failed++;
	if (!check_wrong_input_size<192>()) failed++;
	if (!check_fake_padding_cropping<192>()) failed++;
	if (!check_tampered_padding<192>(0)) failed++;
	if (!check_tampered_padding<192>(17)) failed++;
	if (!check_tampered_padding<192>(255)) failed++;
	if (!check_tampered_padding<192>(2)) failed++;
	if (!check_error_messages<192>()) failed++;
	if (!check_identical_blocks<192>()) failed++;
	if (!check_key_bit_flip<192>()) failed++;
	if (!check_encrypt_overloads_consistency<192>()) failed++;
	if (!check_aliasing_conformity<192>()) failed++;

	return failed;
}
int test_ecb_aes_256() {
	int failed = 0;

	if (!check_coformity<256>()) failed++;
	if (!check_boundary_sizes<256>()) failed++;
	if (!check_output_buffer_too_small<256>()) failed++;
	if (!check_output_buffer_exact_and_larger<256>()) failed++;
	if (!check_wrong_input_size<256>()) failed++;
	if (!check_fake_padding_cropping<256>()) failed++;
	if (!check_tampered_padding<256>(0)) failed++;
	if (!check_tampered_padding<256>(17)) failed++;
	if (!check_tampered_padding<256>(255)) failed++;
	if (!check_tampered_padding<256>(2)) failed++;
	if (!check_error_messages<256>()) failed++;
	if (!check_identical_blocks<256>()) failed++;
	if (!check_key_bit_flip<256>()) failed++;
	if (!check_encrypt_overloads_consistency<256>()) failed++;
	if (!check_aliasing_conformity<256>()) failed++;

	return failed;
}

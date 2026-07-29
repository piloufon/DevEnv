#include "crypto.h"
#include <print>
#include "test_ecb_aes.h"
#include "test_ctr_aes.h"

int test_crypto() {
	int failed = 0;

	failed += test_ecb_aes_128();
	failed += test_ecb_aes_192();
	failed += test_ecb_aes_256();

	failed += test_ctr_aes_128();
	failed += test_ctr_aes_192();
	failed += test_ctr_aes_256();




	return failed;
}

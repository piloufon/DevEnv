#include "crypto.h"
#include <cstdio>

#define TEST(func, string) { int temp = failed; failed += func; if(temp != failed) printf("[-] Failed test: %s\n", string); }
//#define NO_CHECK

int main() {
    #ifdef NO_CHECK
    return 0;
    #else
    int failed = 0;
    TEST(test_crypto(), "test_crypto")

    if (failed == 0)
        printf("[+] All tests passed\n");
    else
        printf("[-] %d test(s) failed\n", failed);

    return failed > 0 ? 1 : 0;
    #endif
}

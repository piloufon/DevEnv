#include "../cl/include/crypto/AES.h"
#include "../cl/include/crypto/CTR.h"
#include "../cl/include/crypto/CryptoRandom.h"
#include "../cl/include/crypto/test/AES_ECB.h"
#include "../cl/include/crypto/test/AES_CTR.h"
#include "../cl/include/crypto/Nonce.h"
#include "../cl/include/utils/CPUFeatures.h"
#include "../cl/include/utils/MathsOperation.h"
#include <print>
#include <chrono>

std::string message = "Nam quis nulla. Integer malesuada. In in enim a arcu imperdiet malesuada. Sed vel lectus."
    " Donec odio urna, tempus molestie, porttitor ut, iaculis quis, sem. Phasellus rhoncus. Aenean id metus id v"
    "elit ullamcorper pulvinar. Vestibulum fermentum tortor id mi. Pellentesque ipsum. Nulla non arcu lacinia ne"
    "que faucibus fringilla. Nulla non lectus sed nisl molestie malesuada. Proin in tellus sit amet nibh digniss"
    "im sagittis. Vivamus luctus egestas leo. Maecenas sollicitudin. Nullam rhoncus aliquam metus. Etiam egestas"
    " wisi a erat.Lorem ipsum dolor sit amet, consectetuer adipiscing elit.Nullam feugiat, turpis at pulvinar vu"
    "lputate, erat libero tristique tellus, nec bibendum odio risus sit amet ante.Aliquam erat volutpat.Nunc auc"
    "tor.Mauris pretium quam et urna.Fusce nibh.Duis risus.Curabitur sagittis hendrerit ante.Aliquam erat volutp"
    "at.Vestibulum erat nulla, ullamcorper nec, rutrum non, nonummy ac, erat.Duis condimentum augue id magna sem"
    "per rutrum.Nullam justo enim, consectetuer nec, ullamcorper ac, vestibulum in, elit.Proin pede metus, vulpu"
    "tate nec, fermentum fringilla, vehicula vitae, justo.Fusce consectetuer risus a nunc.Aliquam ornare wisi eu"
    " metus.Integer pellentesque quam vel velit.Duis pulvinar. Lorem ipsum dolor sit amet, consectetuer adipisci"
    "ng elit.Morbi gravida libero nec velit.Morbi scelerisque luctus velit.Etiam dui sem, fermentum vitae, sagit"
    "tis id, malesuada in, quam.Proin mattis lacinia justo.Vestibulum facilisis auctor urna.Aliquam in lorem sit"
    " amet leo accumsan lacinia.Integer rutrum, orci vestibulum ullamcorper ultricies, lacus quam ultricies odio"
    ", vitae placerat pede sem sit amet enim.Phasellus et lorem id felis nonummy placerat.Fusce dui leo, imperdi"
    "et in, aliquam sit amet, feugiat eu, orci.Aenean vel massa quis mauris vehicula lacinia.Quisque tincidunt s"
    "celerisque libero.Maecenas libero.Etiam dictum tincidunt diam.Donec ipsum massa, ullamcorper in, auctor et,"
    " scelerisque sed, est.Suspendisse nisl.Sed convallis magna eu sem.Cras pede libero, dapibus nec, pretium"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // Add for 2048 + \00


int main() {
    if (!testAES()) {
        std::println("Vector NIST for AES (ECB) failed !");
        return -1;
    }
    if (!testAESCTR()) {
        std::println("Vector NIST for AES (CTR) failed !");
        return -1;
    }
    
    std::vector<uint8_t> in(message.begin(), message.end());
    std::vector<uint8_t> out;
    
    SafeArray<12> nonce;
    
    CTR<AES<256>>::Key key;
    CTR<AES<256>> ctr(key);
    
    uint64_t iterations = 1'000'000;
    //uint64_t iterations = 50'000;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < iterations; i++) {
        ctr.encrypt(in, out, nonce, 0);
    }
    auto end = std::chrono::high_resolution_clock::now();
    uint64_t duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double average = duration / iterations;
    
    std::println("Time taken: {} us", duration / 1'000);
    std::println("Averge: {:.3f} ns", average);
    return 0;
}

#include "../cl/include/AES.h"
#include "../cl/include/test/AES_ECB.h"
#include <print>

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
    " scelerisque sed, est.Suspendisse nisl.Sed convallis magna eu sem.Cras pede libero, dapibus nec, pretium";


int main() {
    if (!testAES()) {
        std::println("Vector NIST failed !");
        return -1;
    }

    std::vector<uint8_t> ciphered;
    std::vector<uint8_t> out;
    {
        AES<256>::Key key;
        std::vector<uint8_t> raw_bytes(message.begin(), message.end());
    
        AES<256> aes(key);
        aes.encrypt(raw_bytes, ciphered);
    }
    {
        AES<256>::Key key;
        AES<256> aes(key);
        aes.encrypt(ciphered, out);

    }
    std::string result(out.begin(), out.end());
    std::println("Message: {}", result);

    //uint64_t random_number = CryptoRandom::generate<uint64_t>();
    //std::println("Random number = {}", random_number);
    return 0;
}

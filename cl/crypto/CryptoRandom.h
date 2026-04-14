#pragma once
#include <span>

class CryptoRandom {
public:
    static void fill(std::span<uint8_t> buffer);

    template<typename T>
        requires (std::is_arithmetic_v<T>)
    static T generate() {
        T value;
        fill(std::span<uint8_t>(
            reinterpret_cast<uint8_t*>(&value),
            sizeof(T)
        ));
        return value;
    }
};

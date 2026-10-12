// Quick test — prove rng produces different values every run
// Header: include/botan-3/botan/auto_rng.h
// Source: botan-src/src/lib/rng/auto_rng/

#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>

int main() {
    Botan::AutoSeeded_RNG rng;

    std::cout << "Run this multiple times — all outputs should be different\n\n";

    for (int i = 1; i <= 5; i++) {
        auto bytes = rng.random_vec(16);
        std::cout << "Random " << i << ": " << Botan::hex_encode(bytes) << "\n";
    }

    return 0;
}

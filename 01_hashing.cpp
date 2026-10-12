// Lesson 01 — Hashing
// Header: include/botan-3/botan/hash.h
// Source: botan-src/src/lib/hash/

#include <botan/hash.h>
#include <botan/hex.h>
#include <iostream>
#include <string>

int main() {
    std::string input = "hash me nowwwwwwww";

    // algorithms to test
    for (const std::string& algo : {"MD5", "SHA-1", "SHA-256", "SHA-512", "SHA-3(256)", "BLAKE2b(256)"}) {

        // create a hash object — throws if algo name is wrong
        // botan/hash.h → HashFunction::create()
        auto hash = Botan::HashFunction::create(algo);

        // feed input bytes into the hash
        hash->update(reinterpret_cast<const uint8_t*>(input.data()), input.size());

        // finalize and get the digest as bytes
        auto digest = hash->final();

        // botan/hex.h → hex_encode() converts bytes to hex string
        std::cout << algo << ":\n  " << Botan::hex_encode(digest) << "\n\n";
    }

    return 0;
}

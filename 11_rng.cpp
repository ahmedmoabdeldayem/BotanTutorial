// Lesson 11 — Random Number Generation
// Headers: include/botan-3/botan/auto_rng.h
//          include/botan-3/botan/system_rng.h
//          include/botan-3/botan/chacha_rng.h
// Sources: botan-src/src/lib/rng/auto_rng/
//          botan-src/src/lib/rng/system_rng/
//          botan-src/src/lib/rng/chacha_rng/

#include <botan/auto_rng.h>
#include <botan/system_rng.h>
#include <botan/chacha_rng.h>
#include <botan/hex.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>

int main() {

    // -------------------------------------------------------
    // PART 1: AutoSeeded_RNG
    // -------------------------------------------------------
    std::cout << "=== Part 1: AutoSeeded_RNG ===\n";
    std::cout << "Seeds itself from OS entropy automatically\n";
    std::cout << "Reseeds periodically to stay unpredictable\n\n";

    // botan/auto_rng.h → AutoSeeded_RNG
    // internally uses HMAC_DRBG seeded from System_RNG
    Botan::AutoSeeded_RNG auto_rng;

    std::cout << "Name : " << auto_rng.name() << "\n\n";

    // generate random bytes — different every run
    for(int i = 1; i <= 3; i++) {
        auto bytes = auto_rng.random_vec(16);
        std::cout << "Run " << i << " : " << Botan::hex_encode(bytes) << "\n";
    }
    std::cout << "(all different — unpredictable)\n\n";

    // -------------------------------------------------------
    // PART 2: System_RNG — direct OS entropy
    // -------------------------------------------------------
    std::cout << "=== Part 2: System_RNG ===\n";
    std::cout << "Reads directly from OS: getentropy() on macOS\n";
    std::cout << "Slowest but highest quality — hardware entropy\n\n";

    // botan/system_rng.h → system_rng()
    // singleton — one instance shared across the program
    Botan::RandomNumberGenerator& sys_rng = Botan::system_rng();
    std::cout << "Name : " << sys_rng.name() << "\n\n";

    for(int i = 1; i <= 3; i++) {
        auto bytes = sys_rng.random_vec(16);
        std::cout << "Run " << i << " : " << Botan::hex_encode(bytes) << "\n";
    }
    std::cout << "\n";

    // -------------------------------------------------------
    // PART 3: ChaCha_RNG — fast userspace CSPRNG
    // -------------------------------------------------------
    std::cout << "=== Part 3: ChaCha_RNG ===\n";
    std::cout << "ChaCha20 stream cipher used as RNG\n";
    std::cout << "Much faster than System_RNG for bulk random data\n\n";

    // botan/chacha_rng.h → ChaCha_RNG
    // seeded from system_rng, then generates using ChaCha20
    Botan::ChaCha_RNG chacha_rng(Botan::system_rng());
    std::cout << "Name : " << chacha_rng.name() << "\n\n";

    for(int i = 1; i <= 3; i++) {
        auto bytes = chacha_rng.random_vec(16);
        std::cout << "Run " << i << " : " << Botan::hex_encode(bytes) << "\n";
    }
    std::cout << "\n";

    // -------------------------------------------------------
    // PART 4: PROVE OUTPUTS ARE UNPREDICTABLE
    // -------------------------------------------------------
    std::cout << "=== Part 4: Statistical uniformity test ===\n";
    std::cout << "Generate 10,000 bytes and count bit distribution\n";
    std::cout << "Good RNG: roughly 50% zeros, 50% ones\n\n";

    const size_t N = 10000;
    auto large_sample = auto_rng.random_vec(N);

    size_t ones = 0;
    for(uint8_t byte : large_sample)
        for(int bit = 0; bit < 8; bit++)
            if(byte & (1 << bit)) ones++;

    size_t total_bits = N * 8;
    double pct_ones = (double)ones / total_bits * 100.0;

    std::cout << "Total bits : " << total_bits << "\n";
    std::cout << "Ones       : " << ones << " (" << pct_ones << "%)\n";
    std::cout << "Zeros      : " << (total_bits - ones) << " (" << (100.0 - pct_ones) << "%)\n";
    std::cout << "Distribution: " << (pct_ones > 48.0 && pct_ones < 52.0 ? "UNIFORM — good RNG" : "SKEWED — bad RNG") << "\n\n";

    // -------------------------------------------------------
    // PART 5: FIXED SEED — deterministic (testing only)
    // -------------------------------------------------------
    std::cout << "=== Part 5: Fixed seed (deterministic — NEVER use in production) ===\n";
    std::cout << "Same seed → same output every time\n";
    std::cout << "Useful for reproducible tests only\n\n";

    // seed ChaCha_RNG with a fixed key for deterministic output
    std::vector<uint8_t> fixed_seed(32, 0x42);  // all bytes = 0x42

    Botan::ChaCha_RNG det_rng1(Botan::secure_vector<uint8_t>(fixed_seed.begin(), fixed_seed.end()));
    Botan::ChaCha_RNG det_rng2(Botan::secure_vector<uint8_t>(fixed_seed.begin(), fixed_seed.end()));

    auto det1 = det_rng1.random_vec(16);
    auto det2 = det_rng2.random_vec(16);

    std::cout << "RNG 1 (seed 0x42) : " << Botan::hex_encode(det1) << "\n";
    std::cout << "RNG 2 (seed 0x42) : " << Botan::hex_encode(det2) << "\n";
    std::cout << "Same output       : " << (det1 == det2 ? "YES — deterministic" : "NO") << "\n\n";

    std::cout << "WARNING: Never use a fixed seed in real code.\n";
    std::cout << "         An attacker who knows the seed can predict all your keys.\n";

    return 0;
}

// Lesson 16 — Shamir's Secret Sharing (5-of-3 threshold scheme)
// Split a secret into N shares where any K reconstruct it.
// Fewer than K shares reveal mathematically zero information.
// Header: include/botan-3/botan/tss.h
// Source: botan-src/src/lib/misc/tss/

#include <botan/tss.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>
#include <string>
#include <vector>

int main() {
    Botan::AutoSeeded_RNG rng;

    // -------------------------------------------------------
    // PART 1: Split a secret — 5 shares, threshold 3
    //
    // Real-world analogy: a company master key split across
    // 5 executives. Any 3 must agree to reconstruct it.
    // One person resigns, one device stolen — still safe.
    // -------------------------------------------------------
    std::cout << "=== Part 1: Split secret (5 shares, threshold 3) ===\n\n";

    std::string secret = "master-key-super-secret";
    const uint8_t threshold = 3;  // minimum shares to reconstruct
    const uint8_t total     = 5;  // total shares to generate

    // 16-byte identifier — labels this secret (like a key ID)
    // all shares from the same split share the same identifier
    std::vector<uint8_t> identifier(16, 0x01);

    auto shares = Botan::RTSS_Share::split(
        threshold, total,
        reinterpret_cast<const uint8_t*>(secret.data()),
        static_cast<uint16_t>(secret.size()),
        identifier, "SHA-256", rng);

    std::cout << "Secret    : " << secret << "\n";
    std::cout << "Threshold : " << (int)threshold << " of " << (int)total << "\n\n";

    for(size_t i = 0; i < shares.size(); i++) {
        std::cout << "Share " << (i+1) << "  : " << shares[i].to_string().substr(0, 48) << "...\n";
    }
    std::cout << "\n";

    // -------------------------------------------------------
    // PART 2: Try every possible combination from size 1 to 5
    //
    // For each group size k, generate all C(5,k) combinations
    // and attempt reconstruction. Below threshold → fail.
    // At or above threshold → succeed with correct secret.
    // -------------------------------------------------------
    std::cout << "=== Part 2: All combinations by group size ===\n\n";

    // generate all combinations of size k from indices 0..n-1
    auto combinations = [](size_t n, size_t k) {
        std::vector<std::vector<size_t>> result;
        std::vector<size_t> combo(k);
        std::function<void(size_t, size_t)> gen = [&](size_t start, size_t depth) {
            if(depth == k) { result.push_back(combo); return; }
            for(size_t i = start; i < n; i++) {
                combo[depth] = i;
                gen(i + 1, depth + 1);
            }
        };
        gen(0, 0);
        return result;
    };

    for(size_t k = 1; k <= total; k++) {
        std::cout << "--- " << k << " share" << (k > 1 ? "s" : "")
                  << " (threshold is " << (int)threshold << ") ---\n";

        auto combos = combinations(total, k);
        size_t ok = 0;

        for(auto& indices : combos) {
            // print share indices used e.g. {1,3,5}
            std::cout << "  {";
            for(size_t j = 0; j < indices.size(); j++) {
                std::cout << (indices[j] + 1);
                if(j + 1 < indices.size()) std::cout << ",";
            }
            std::cout << "} → ";

            std::vector<Botan::RTSS_Share> subset;
            for(size_t idx : indices) subset.push_back(shares[idx]);

            try {
                auto recovered = Botan::RTSS_Share::reconstruct(subset);
                std::string result(recovered.begin(), recovered.end());
                if(result == secret) { std::cout << "OK\n"; ok++; }
                else                 { std::cout << "WRONG OUTPUT\n"; }
            } catch(const std::exception&) {
                std::cout << "FAIL (below threshold)\n";
            }
        }

        std::cout << "  Result: " << ok << "/" << combos.size()
                  << (k >= threshold ? " succeeded — at or above threshold\n\n"
                                     : " succeeded — below threshold\n\n");
    }

    // -------------------------------------------------------
    // PART 3: Split an AES key — the real use case
    //
    // In practice you never split a password directly.
    // You split a key (random bytes). This is how Vault does it —
    // the master encryption key is split, not user passwords.
    // -------------------------------------------------------
    std::cout << "=== Part 3: Split an AES-256 key (Vault-style) ===\n\n";

    auto aes_key = rng.random_vec(32);  // 256-bit AES key
    std::cout << "AES key (original) : " << Botan::hex_encode(aes_key) << "\n\n";

    std::vector<uint8_t> key_identifier(16, 0xAB);
    auto key_shares = Botan::RTSS_Share::split(
        3, 5,
        aes_key.data(),
        static_cast<uint16_t>(aes_key.size()),
        key_identifier, "SHA-256", rng);

    std::cout << "Split into 5 shares (threshold 3):\n";
    for(size_t i = 0; i < key_shares.size(); i++) {
        std::cout << "  Share " << (i+1) << " : " << key_shares[i].to_string().substr(0, 48) << "...\n";
    }
    std::cout << "\n";

    // reconstruct using shares 1, 4, 5
    std::vector<Botan::RTSS_Share> key_subset = { key_shares[0], key_shares[3], key_shares[4] };
    auto recovered_key = Botan::RTSS_Share::reconstruct(key_subset);

    std::cout << "AES key (recovered): " << Botan::hex_encode(recovered_key) << "\n";
    std::cout << "Match              : " << (recovered_key == aes_key ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // PART 4: Properties
    // -------------------------------------------------------
    std::cout << "=== Part 4: Security properties ===\n\n";
    std::cout << "Threshold   — any K of N shares reconstruct the secret\n";
    std::cout << "Zero info   — K-1 shares reveal nothing mathematically\n";
    std::cout << "No single point of failure — no one person holds the secret\n";
    std::cout << "Flexible    — change N and K to match your trust model\n";
    std::cout << "Used by     — HashiCorp Vault, ICANN DNS root, hardware wallets\n";

    return 0;
}

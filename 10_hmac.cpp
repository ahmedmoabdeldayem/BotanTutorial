// Lesson 10 — HMAC & Message Authentication
// Headers: include/botan-3/botan/mac.h
//          include/botan-3/botan/hex.h
// Sources: botan-src/src/lib/mac/hmac/

#include <botan/mac.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/symkey.h>
#include <iostream>
#include <string>
#include <vector>

// timing-safe comparison — prevents timing attacks
// regular == leaks how many bytes matched before mismatch
bool safe_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if(a.size() != b.size()) return false;
    uint8_t diff = 0;
    for(size_t i = 0; i < a.size(); ++i)
        diff |= a[i] ^ b[i];   // accumulate all differences
    return diff == 0;           // only zero if ALL bytes matched
}

int main() {
    Botan::AutoSeeded_RNG rng;

    // shared secret key — both sender and receiver must have this
    Botan::SymmetricKey key(rng, 32);
    std::cout << "Shared key : " << Botan::hex_encode(key.bits_of()) << "\n\n";

    // -------------------------------------------------------
    // PART 1: HMAC-SHA256 — sign and verify a message
    // -------------------------------------------------------
    std::cout << "=== Part 1: HMAC-SHA256 sign and verify ===\n";

    std::string message = "pay Bob $100";

    // botan/mac.h → MessageAuthenticationCode::create()
    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

    // sign — sender computes HMAC
    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    std::vector<uint8_t> tag = Botan::unlock(hmac->final());

    std::cout << "Message : " << message << "\n";
    std::cout << "HMAC    : " << Botan::hex_encode(tag) << "\n\n";

    // verify — receiver recomputes HMAC and compares
    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    std::vector<uint8_t> verify_tag = Botan::unlock(hmac->final());

    std::cout << "Verified : " << (safe_compare(tag, verify_tag) ? "VALID" : "INVALID") << "\n\n";

    // -------------------------------------------------------
    // PART 2: TAMPER DETECTION
    // -------------------------------------------------------
    std::cout << "=== Part 2: Tamper detection ===\n";

    std::string tampered = "pay Bob $999";   // attacker modified amount

    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t*>(tampered.data()), tampered.size());
    std::vector<uint8_t> tampered_tag = Botan::unlock(hmac->final());

    std::cout << "Original message : " << message  << " → HMAC: " << Botan::hex_encode(tag)         << "\n";
    std::cout << "Tampered message : " << tampered << " → HMAC: " << Botan::hex_encode(tampered_tag) << "\n";
    std::cout << "Tags match       : " << (safe_compare(tag, tampered_tag) ? "YES (bad)" : "NO — tampering detected") << "\n\n";

    // -------------------------------------------------------
    // PART 3: WRONG KEY
    // -------------------------------------------------------
    std::cout << "=== Part 3: Wrong key ===\n";

    Botan::SymmetricKey wrong_key(rng, 32);
    auto hmac_wrong = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    hmac_wrong->set_key(wrong_key);
    hmac_wrong->update(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    std::vector<uint8_t> wrong_tag = Botan::unlock(hmac_wrong->final());

    std::cout << "Correct key HMAC : " << Botan::hex_encode(tag)       << "\n";
    std::cout << "Wrong key HMAC   : " << Botan::hex_encode(wrong_tag)  << "\n";
    std::cout << "Tags match       : " << (safe_compare(tag, wrong_tag) ? "YES (bad)" : "NO — wrong key detected") << "\n\n";

    // -------------------------------------------------------
    // PART 4: JWT-STYLE TOKEN
    // -------------------------------------------------------
    std::cout << "=== Part 4: JWT-style token ===\n";

    // JWT = header.payload.signature (base64 encoded, but we use hex here for clarity)
    std::string header  = "algorithm:HMAC-SHA256";
    std::string payload = "user_id:12345,role:admin,exp:9999999999";
    std::string signing_input = header + "." + payload;

    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t*>(signing_input.data()), signing_input.size());
    std::vector<uint8_t> jwt_sig = Botan::unlock(hmac->final());

    std::string token = signing_input + "." + Botan::hex_encode(jwt_sig);
    std::cout << "Token   : " << token << "\n\n";

    // server verifies by re-signing the header.payload part
    std::string received_signing_input = header + "." + payload;
    hmac->set_key(key);
    hmac->update(reinterpret_cast<const uint8_t*>(received_signing_input.data()), received_signing_input.size());
    std::vector<uint8_t> expected_sig = Botan::unlock(hmac->final());

    std::cout << "Token valid : " << (safe_compare(jwt_sig, expected_sig) ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // PART 5: WHY TIMING-SAFE COMPARISON MATTERS
    // -------------------------------------------------------
    std::cout << "=== Part 5: Timing-safe comparison ===\n";

    std::cout << "Regular == : stops at first mismatch\n";
    std::cout << "  HMAC starts with 'AA...' vs 'AB...' → returns false after 2 bytes\n";
    std::cout << "  HMAC starts with 'AA...' vs 'ZZ...' → returns false after 1 byte\n";
    std::cout << "  Attacker measures response time → learns how many bytes matched\n";
    std::cout << "  → can forge HMAC byte by byte\n\n";

    std::cout << "safe_compare : always checks ALL bytes\n";
    std::cout << "  XORs every byte, accumulates into diff\n";
    std::cout << "  always takes same time regardless of where mismatch is\n";
    std::cout << "  attacker learns nothing from timing\n";

    return 0;
}

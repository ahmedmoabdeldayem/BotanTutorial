// Lesson 09 — Key Derivation (PBKDF2 & HKDF)
// Headers: include/botan-3/botan/pbkdf.h
//          include/botan-3/botan/hkdf.h
//          include/botan-3/botan/pwdhash.h
// Sources: botan-src/src/lib/pbkdf/
//          botan-src/src/lib/kdf/hkdf/

#include <botan/pwdhash.h>
#include <botan/kdf.h>
#include <botan/ecdh.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>
#include <string>
#include <vector>

int main() {
    Botan::AutoSeeded_RNG rng;

    // -------------------------------------------------------
    // SCENARIO 1: PBKDF2 — password → AES key
    // -------------------------------------------------------
    std::cout << "=== Scenario 1: PBKDF2 (password → AES key) ===\n";

    const std::string password = "BotanTutorial";
    Botan::secure_vector<uint8_t> pbkdf2_salt = rng.random_vec(16);

    // botan/pwdhash.h → PasswordHashFamily
    // PBKDF2(SHA-256) = 600,000 iterations of SHA-256 — intentionally slow
    auto pbkdf2_family = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");
    auto pbkdf2        = pbkdf2_family->from_iterations(600000);

    std::vector<uint8_t> aes_key(32);
    pbkdf2->hash(aes_key, password, pbkdf2_salt);

    std::cout << "Password : " << password << "\n";
    std::cout << "Salt     : " << Botan::hex_encode(pbkdf2_salt) << "\n";
    std::cout << "AES key  : " << Botan::hex_encode(aes_key)     << "\n\n";

    // same password + same salt → same key every time (deterministic)
    std::vector<uint8_t> aes_key2(32);
    pbkdf2->hash(aes_key2, password, pbkdf2_salt);
    std::cout << "Deterministic : " << (aes_key == aes_key2 ? "YES — same inputs always give same key" : "NO") << "\n\n";

    // -------------------------------------------------------
    // SCENARIO 2: HKDF — ECDH secret → multiple independent keys
    // -------------------------------------------------------
    std::cout << "=== Scenario 2: HKDF (ECDH secret → AES key + IV + HMAC key) ===\n";

    // perform ECDH to get shared secret (same as lesson 04b)
    Botan::EC_Group curve = Botan::EC_Group::from_name("secp256r1");
    Botan::ECDH_PrivateKey alice_priv(rng, curve);
    Botan::ECDH_PrivateKey bob_priv(rng, curve);

    Botan::PK_Key_Agreement alice_ka(alice_priv, rng, "Raw");
    Botan::SymmetricKey raw_secret = alice_ka.derive_key(32, bob_priv.raw_public_key_bits());

    std::cout << "ECDH raw secret  : " << Botan::hex_encode(raw_secret.bits_of()) << "\n";
    std::cout << "  (has mathematical structure — not safe to use directly as AES key)\n\n";

    // botan/kdf.h → KDF::create()
    // HKDF Step 1 — Extract: remove mathematical structure
    auto hkdf_extract = Botan::KDF::create_or_throw("HKDF-Extract(SHA-256)");
    Botan::secure_vector<uint8_t> hkdf_salt = rng.random_vec(32);
    Botan::secure_vector<uint8_t> prk = hkdf_extract->derive_key(
        32,
        raw_secret.bits_of(),   // input key material
        hkdf_salt,              // salt
        std::vector<uint8_t>{}  // no context for extract step
    );
    std::cout << "PRK (after extract): " << Botan::hex_encode(prk) << "\n";
    std::cout << "  (uniform random — mathematical structure removed)\n\n";

    // HKDF Step 2 — Expand: derive multiple independent keys from PRK
    auto hkdf_expand = Botan::KDF::create_or_throw("HKDF-Expand(SHA-256)");

    // each context string produces an independent key
    auto derive = [&](const std::string& context, size_t len) {
        std::vector<uint8_t> info(context.begin(), context.end());
        return hkdf_expand->derive_key(len, prk, std::vector<uint8_t>{}, info);
    };

    auto enc_key  = derive("aes encryption key", 32);
    auto iv       = derive("aes iv",             16);
    auto hmac_key = derive("hmac key",           32);

    std::cout << "AES encryption key : " << Botan::hex_encode(enc_key)  << "\n";
    std::cout << "AES IV             : " << Botan::hex_encode(iv)        << "\n";
    std::cout << "HMAC key           : " << Botan::hex_encode(hmac_key)  << "\n\n";

    // -------------------------------------------------------
    // SCENARIO 3: HKDF — master key → per-purpose independent keys
    // -------------------------------------------------------
    std::cout << "=== Scenario 3: HKDF (master key → per-purpose keys) ===\n";

    Botan::secure_vector<uint8_t> master_key = rng.random_vec(32);
    std::cout << "Master key : " << Botan::hex_encode(master_key) << "\n\n";

    // derive independent keys for each purpose
    auto derive_from_master = [&](const std::string& purpose, size_t len) {
        std::vector<uint8_t> info(purpose.begin(), purpose.end());
        return hkdf_expand->derive_key(len, master_key, std::vector<uint8_t>{}, info);
    };

    auto file_key = derive_from_master("file encryption", 32);
    auto sign_key = derive_from_master("message signing", 32);
    auto api_key  = derive_from_master("api authentication", 32);

    std::cout << "File encryption key : " << Botan::hex_encode(file_key) << "\n";
    std::cout << "Message signing key : " << Botan::hex_encode(sign_key) << "\n";
    std::cout << "API auth key        : " << Botan::hex_encode(api_key)  << "\n\n";

    // prove keys are independent — all different despite same master key
    std::cout << "file_key == sign_key : " << (file_key == sign_key ? "YES (BAD)" : "NO — independent") << "\n";
    std::cout << "sign_key == api_key  : " << (sign_key == api_key  ? "YES (BAD)" : "NO — independent") << "\n";

    return 0;
}

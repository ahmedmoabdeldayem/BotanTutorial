// Lesson 08 — Password Hashing
// Headers: include/botan-3/botan/pwdhash.h
//          include/botan-3/botan/bcrypt.h
//          include/botan-3/botan/hash.h
// Sources: botan-src/src/lib/pbkdf/argon2/
//          botan-src/src/lib/passhash/bcrypt/

#include <botan/pwdhash.h>
#include <botan/bcrypt.h>
#include <botan/argon2fmt.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <iostream>
#include <string>
#include <chrono>

// helper — measures how long a function takes in milliseconds
template<typename Func>
double measure_ms(Func f) {
    auto start = std::chrono::steady_clock::now();
    f();
    auto end = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

int main() {
    Botan::AutoSeeded_RNG rng;
    const std::string password = "BotanTutorial";

    // -------------------------------------------------------
    // PART 1: WHY SHA-256 IS WRONG FOR PASSWORDS
    // -------------------------------------------------------
    std::cout << "=== SHA-256 (WRONG for passwords) ===\n";

    auto sha256 = Botan::HashFunction::create("SHA-256");
    sha256->update(reinterpret_cast<const uint8_t*>(password.data()), password.size());
    auto hash1 = sha256->final();

    sha256->update(reinterpret_cast<const uint8_t*>(password.data()), password.size());
    auto hash2 = sha256->final();

    std::cout << "Hash 1 : " << Botan::hex_encode(hash1) << "\n";
    std::cout << "Hash 2 : " << Botan::hex_encode(hash2) << "\n";
    std::cout << "Same   : " << (hash1 == hash2 ? "YES — attacker can use rainbow tables" : "NO") << "\n\n";

    // -------------------------------------------------------
    // PART 2: BCRYPT
    // -------------------------------------------------------
    std::cout << "=== bcrypt (work factor 12) ===\n";

    std::string bcrypt_hash;
    double bcrypt_time = measure_ms([&]() {
        bcrypt_hash = Botan::generate_bcrypt(password, rng, 12);
    });

    std::cout << "Hash   : " << bcrypt_hash << "\n";
    std::cout << "Time   : " << bcrypt_time << " ms\n";

    bool bcrypt_ok    = Botan::check_bcrypt(password, bcrypt_hash);
    bool bcrypt_wrong = Botan::check_bcrypt("wrongpassword", bcrypt_hash);
    std::cout << "Correct password : " << (bcrypt_ok    ? "MATCH"    : "NO MATCH") << "\n";
    std::cout << "Wrong password   : " << (bcrypt_wrong ? "MATCH"    : "NO MATCH") << "\n\n";

    // two users with same password → different hashes (salt protection)
    std::string alice_hash = Botan::generate_bcrypt(password, rng, 12);
    std::string bob_hash   = Botan::generate_bcrypt(password, rng, 12);
    std::cout << "Alice hash : " << alice_hash << "\n";
    std::cout << "Bob hash   : " << bob_hash   << "\n";
    std::cout << "Same       : " << (alice_hash == bob_hash
        ? "YES — no salt protection"
        : "NO  — attacker must crack each hash separately") << "\n\n";

    std::cout << "Alice check hash  : " << (Botan::check_bcrypt(password, alice_hash) ? "MATCH"    : "NO MATCH") << "\n";
    std::cout << "Bob check hash  : "   << (Botan::check_bcrypt(password, bob_hash) ? "MATCH"    : "NO MATCH") << "\n\n";

    

    // -------------------------------------------------------
    // PART 3: ARGON2id (best choice today)
    // -------------------------------------------------------
    std::cout << "=== Argon2id ===\n";

    // botan/pwdhash.h → PasswordHashFamily::create()
    // "Argon2id" = the recommended variant (hybrid of Argon2i and Argon2d)
    auto argon2_family = Botan::PasswordHashFamily::create_or_throw("Argon2id");

    // from_params(memory_kb, iterations, parallelism)
    auto argon2 = argon2_family->from_params(65536, 3, 1);  // 64MB, 3 passes, 1 thread

    // random salt — different every time
    Botan::secure_vector<uint8_t> salt = rng.random_vec(16);

    std::vector<uint8_t> argon2_hash(32);
    double argon2_time = measure_ms([&]() {
        argon2->hash(argon2_hash, password, salt);
    });

    std::cout << "Salt   : " << Botan::hex_encode(salt)        << "\n";
    std::cout << "Hash   : " << Botan::hex_encode(argon2_hash) << "\n";
    std::cout << "Time   : " << argon2_time << " ms\n\n";

    // verify — hash again with same salt, compare
    std::vector<uint8_t> verify_hash(32);
    argon2->hash(verify_hash, password, salt);
    std::cout << "Correct password : " << (verify_hash == argon2_hash ? "MATCH" : "NO MATCH") << "\n";

    std::vector<uint8_t> wrong_hash(32);
    argon2->hash(wrong_hash, "wrongpassword", salt);
    std::cout << "Wrong password   : " << (wrong_hash == argon2_hash ? "MATCH" : "NO MATCH") << "\n\n";

    // -------------------------------------------------------
    // PART 4: ARGON2id WITH EMBEDDED SALT (PHC string format)
    // -------------------------------------------------------
    std::cout << "=== Argon2id with embedded salt (like bcrypt) ===\n";

    // argon2_generate_pwhash() produces one self-contained string:
    // $argon2id$v=19$m=65536,t=3,p=1$<base64 salt>$<base64 hash>
    // botan/argon2fmt.h → argon2_generate_pwhash()
    std::string phc_hash = Botan::argon2_generate_pwhash(
        password.c_str(), password.size(),
        rng,
        1,      // parallelism
        65536,  // memory KB
        3);     // iterations

    std::cout << "Hash   : " << phc_hash << "\n";
    std::cout << "  (salt + params + hash all in one string — nothing extra to store)\n\n";

    // verify — just pass the full string back
    bool argon2_ok    = Botan::argon2_check_pwhash(password.c_str(),    password.size(),    phc_hash);
    bool argon2_wrong = Botan::argon2_check_pwhash("wrongpassword", 13, phc_hash);

    std::cout << "Correct password : " << (argon2_ok    ? "MATCH" : "NO MATCH") << "\n";
    std::cout << "Wrong password   : " << (argon2_wrong ? "MATCH" : "NO MATCH") << "\n";

    return 0;
}

// Lesson 13 — ChaCha20-Poly1305
// The other major AEAD cipher alongside AES-256-GCM.
// Used in TLS 1.3, preferred on hardware without AES acceleration.
// Header: include/botan-3/botan/aead.h
// Source: botan-src/src/lib/stream/chacha/
//         botan-src/src/lib/mac/poly1305/

#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/exceptn.h>
#include <iostream>
#include <string>
#include <vector>

int main() {
    Botan::AutoSeeded_RNG rng;

    // -------------------------------------------------------
    // PART 1: Basic encrypt / decrypt
    // Same interface as AES-256-GCM — only the algorithm string changes
    // -------------------------------------------------------
    std::cout << "=== Part 1: Encrypt / Decrypt ===\n\n";

    std::string plaintext = "hello from ChaCha20-Poly1305";

    // 32-byte key, 12-byte nonce — same sizes as AES-256-GCM
    auto key   = rng.random_vec(32);
    auto nonce = rng.random_vec(12);

    // "ChaCha20Poly1305" is all it takes to switch from AES-256-GCM
    auto enc = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
    enc->set_key(key);
    enc->start(nonce);

    Botan::secure_vector<uint8_t> buf(plaintext.begin(), plaintext.end());
    enc->finish(buf);  // buf = ciphertext + 16-byte Poly1305 tag

    std::cout << "Key        : " << Botan::hex_encode(key)   << "\n";
    std::cout << "Nonce      : " << Botan::hex_encode(nonce) << "\n";
    std::cout << "Ciphertext : " << Botan::hex_encode(buf)   << "\n";
    std::cout << "  (last 32 hex chars = 16-byte Poly1305 auth tag)\n\n";

    auto dec = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Decryption);
    dec->set_key(key);
    dec->start(nonce);
    dec->finish(buf);

    std::cout << "Decrypted  : " << std::string(buf.begin(), buf.end()) << "\n\n";

    // -------------------------------------------------------
    // PART 2: Side-by-side with AES-256-GCM
    // Same Botan interface — swap the string, get a different cipher
    // -------------------------------------------------------
    std::cout << "=== Part 2: Same interface as AES-256-GCM ===\n\n";

    auto aes_enc     = Botan::AEAD_Mode::create_or_throw("AES-256/GCM",       Botan::Cipher_Dir::Encryption);
    auto chacha_enc  = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305",  Botan::Cipher_Dir::Encryption);

    std::string msg = "same plaintext, two ciphers";

    auto key2   = rng.random_vec(32);
    auto nonce2 = rng.random_vec(12);

    Botan::secure_vector<uint8_t> aes_buf(msg.begin(), msg.end());
    aes_enc->set_key(key2);
    aes_enc->start(nonce2);
    aes_enc->finish(aes_buf);

    Botan::secure_vector<uint8_t> chacha_buf(msg.begin(), msg.end());
    chacha_enc->set_key(key2);
    chacha_enc->start(nonce2);
    chacha_enc->finish(chacha_buf);

    std::cout << "AES-256-GCM       : " << Botan::hex_encode(aes_buf)    << "\n";
    std::cout << "ChaCha20-Poly1305 : " << Botan::hex_encode(chacha_buf) << "\n";
    std::cout << "Same ciphertext   : " << (aes_buf == chacha_buf ? "YES" : "NO — different algorithms, different output") << "\n\n";

    // -------------------------------------------------------
    // PART 3: Nonce reuse — why it is catastrophic
    //
    // ChaCha20 is a stream cipher: key + nonce → keystream, then XOR with plaintext.
    // Reusing the same nonce with the same key produces the same keystream.
    //
    // If an attacker has two ciphertexts encrypted with the same key+nonce:
    //   C1 = P1 XOR keystream
    //   C2 = P2 XOR keystream
    //   C1 XOR C2 = P1 XOR P2   ← keystream cancels, attacker gets XOR of plaintexts
    //
    // This is called a "two-time pad" and completely breaks confidentiality.
    // -------------------------------------------------------
    std::cout << "=== Part 3: Nonce reuse attack ===\n\n";

    std::string secret1 = "transfer $1000 to alice";
    std::string secret2 = "transfer $9999 to carol";

    // same key and nonce for both — this is the mistake
    auto reused_key   = rng.random_vec(32);
    auto reused_nonce = rng.random_vec(12);

    auto e1 = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
    e1->set_key(reused_key);
    e1->start(reused_nonce);
    Botan::secure_vector<uint8_t> c1(secret1.begin(), secret1.end());
    e1->finish(c1);

    auto e2 = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
    e2->set_key(reused_key);
    e2->start(reused_nonce);
    Botan::secure_vector<uint8_t> c2(secret2.begin(), secret2.end());
    e2->finish(c2);

    // attacker XORs the two ciphertexts (strips the 16-byte tags first)
    size_t len = secret1.size();  // both messages same length here
    std::vector<uint8_t> xored(len);
    for(size_t i = 0; i < len; i++)
        xored[i] = c1[i] ^ c2[i];

    // attacker also XORs with known plaintext (crib-dragging)
    // if they guess secret1, they can recover secret2 directly
    std::vector<uint8_t> recovered(len);
    for(size_t i = 0; i < len; i++)
        recovered[i] = xored[i] ^ static_cast<uint8_t>(secret1[i]);

    std::cout << "Secret 1           : " << secret1 << "\n";
    std::cout << "Secret 2           : " << secret2 << "\n";
    std::cout << "C1 XOR C2          : " << Botan::hex_encode(xored) << "\n";
    std::cout << "Recovered secret 2 : " << std::string(recovered.begin(), recovered.end()) << "\n";
    std::cout << "Match              : " << (std::string(recovered.begin(), recovered.end()) == secret2 ? "YES — nonce reuse broke encryption" : "NO") << "\n\n";
    std::cout << "Fix: always use a fresh random nonce per encryption.\n\n";

    // -------------------------------------------------------
    // PART 4: Tamper detection — Poly1305 catches it
    // -------------------------------------------------------
    std::cout << "=== Part 4: Tamper detection ===\n\n";

    auto key3   = rng.random_vec(32);
    auto nonce3 = rng.random_vec(12);

    auto e3 = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
    e3->set_key(key3);
    e3->start(nonce3);
    Botan::secure_vector<uint8_t> c3(plaintext.begin(), plaintext.end());
    e3->finish(c3);

    c3[4] ^= 0xFF;  // tamper with a byte in the ciphertext

    auto d3 = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Decryption);
    d3->set_key(key3);
    d3->start(nonce3);

    try {
        d3->finish(c3);
        std::cout << "Decrypted tampered message (should not happen)\n";
    } catch(const Botan::Invalid_Authentication_Tag&) {
        std::cout << "Tampered message rejected — Poly1305 tag invalid\n\n";
    }

    // -------------------------------------------------------
    // PART 5: When to use which
    // -------------------------------------------------------
    std::cout << "=== Part 5: AES-256-GCM vs ChaCha20-Poly1305 ===\n\n";
    std::cout << "AES-256-GCM        — fast with hardware AES-NI (servers, modern desktops)\n";
    std::cout << "ChaCha20-Poly1305  — fast in pure software (mobile, embedded, older CPUs)\n";
    std::cout << "TLS 1.3            — offers both, negotiates based on client capability\n";
    std::cout << "Security           — both are equally strong, pick based on hardware\n";
    std::cout << "Safe default       — ChaCha20-Poly1305 (works everywhere, never slow)\n";

    return 0;
}

// Lesson 02 — Symmetric Encryption (AES-256-GCM)
// Header: include/botan-3/botan/aead.h
// Source: botan-src/src/lib/modes/aead/gcm/

#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/exceptn.h>
#include <iostream>
#include <string>
#include <vector>

int main() {
    std::string plaintext_str = "this is notsecret";

    // --- ENCRYPT ---

    // botan/auto_rng.h → cryptographically secure random number generator
    Botan::AutoSeeded_RNG rng;

    // generate a random 256-bit (32 byte) key
    // botan-src/src/lib/rng/auto_rng/auto_rng.cpp → random_vec()
    Botan::secure_vector<uint8_t> key = rng.random_vec(32);

    // generate a random 96-bit (12 byte) nonce — must be unique per encryption
    Botan::secure_vector<uint8_t> nonce = rng.random_vec(12);

    // create AES-256-GCM cipher in encryption mode
    // botan/aead.h → AEAD_Mode::create()
    auto enc = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);

    // set the key
    enc->set_key(key);

    // set the nonce and start encryption
    enc->start(nonce);

    // copy plaintext into a buffer — finish() encrypts in place and appends the 16-byte auth tag
    Botan::secure_vector<uint8_t> buf(plaintext_str.begin(), plaintext_str.end());
    std::cout << "=== beforeeeeee ===\n";

    for (const auto& element : buf) {
        std::cout << element << " ";
    }
    std::cout << "\n";
    std::cout << "buf : " << Botan::hex_encode(buf)    << "\n";
    std::cout << "plaintxt : " << plaintext_str   << "\n";




    enc->finish(buf);

    std::cout << "=== ENCRYPT ===\n";
    std::cout << "Key        : " << Botan::hex_encode(key)    << "\n";
    std::cout << "Nonce      : " << Botan::hex_encode(nonce)  << "\n";
    std::cout << "Ciphertext : " << Botan::hex_encode(buf)    << "\n";

    std::cout << "  (last 32 hex chars = 16-byte auth tag)\n\n";

    // --- DECRYPT ---

    auto dec = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    dec->set_key(key);
    dec->start(nonce);

    // buf still contains ciphertext + auth tag — decrypt in place
    dec->finish(buf);

    std::string decrypted(buf.begin(), buf.end());
    std::cout << "=== DECRYPT ===\n";
    std::cout << "Decrypted  : " << decrypted << "\n\n";

    // --- TAMPER TEST ---
    // flip one bit in the ciphertext and try to decrypt — GCM should reject it

    Botan::secure_vector<uint8_t> tampered_buf(plaintext_str.begin(), plaintext_str.end());
    enc->start(nonce);
    enc->finish(tampered_buf);
    tampered_buf[0] ^= 0x01;  // flip one bit

    auto dec2 = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    dec2->set_key(key);
    dec2->start(nonce);

    try {
        dec2->finish(tampered_buf);
        std::cout << "TAMPER TEST: decrypted (should not happen)\n";
    } catch (const Botan::Invalid_Authentication_Tag&) {
        std::cout << "=== TAMPER TEST ===\n";
        std::cout << "Flipped one bit → authentication failed → decryption rejected\n";
        std::cout << "This is GCM protecting you\n";
    }

    return 0;
}

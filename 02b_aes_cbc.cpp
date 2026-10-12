// Lesson 02b — Symmetric Encryption (AES-256-CBC)
// Header: include/botan-3/botan/cipher_mode.h
// Source: botan-src/src/lib/modes/cbc/

#include <botan/cipher_mode.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/exceptn.h>
#include <iostream>
#include <string>

int main() {
    std::string plaintext_str = "this is secret";

    Botan::AutoSeeded_RNG rng;

    // 256-bit key
    Botan::secure_vector<uint8_t> key = rng.random_vec(32);

    // CBC needs a 16-byte IV (block size of AES)
    Botan::secure_vector<uint8_t> iv = rng.random_vec(16);

    // botan/cipher_mode.h → Cipher_Mode::create()
    // note: Cipher_Mode not AEAD_Mode — CBC has no authentication
    auto enc = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Encryption);

    enc->set_key(key);
    enc->start(iv);

    Botan::secure_vector<uint8_t> buf(plaintext_str.begin(), plaintext_str.end());
    enc->finish(buf);

    std::cout << "=== ENCRYPT (CBC) ===\n";
    std::cout << "Key        : " << Botan::hex_encode(key)   << "\n";
    std::cout << "IV         : " << Botan::hex_encode(iv)    << "\n";
    std::cout << "Ciphertext : " << Botan::hex_encode(buf)   << "\n\n";

    // --- DECRYPT ---
    auto dec = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Decryption);
    dec->set_key(key);
    dec->start(iv);
    dec->finish(buf);

    std::cout << "=== DECRYPT (CBC) ===\n";
    std::cout << "Decrypted  : " << std::string(buf.begin(), buf.end()) << "\n\n";

    // --- TAMPER TEST ---
    // flip one bit — CBC has no auth tag so it will NOT catch this
    Botan::secure_vector<uint8_t> tampered(plaintext_str.begin(), plaintext_str.end());
    auto enc2 = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Encryption);
    enc2->set_key(key);
    enc2->start(iv);
    enc2->finish(tampered);
    tampered[0] ^= 0x01;

    auto dec2 = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Decryption);
    dec2->set_key(key);
    dec2->start(iv);
    try {
        dec2->finish(tampered);
        std::cout << "=== TAMPER TEST ===\n";
        std::cout << "Decrypted  : " << std::string(tampered.begin(), tampered.end()) << "\n";
        std::cout << "No error — CBC accepted tampered ciphertext\n";
    } catch (const Botan::Decoding_Error& e) {
        std::cout << "=== TAMPER TEST ===\n";
        std::cout << "Exception  : " << e.what() << "\n";
        std::cout << "CBC caught it via padding check — but this is NOT safe\n";
        std::cout << "An attacker can exploit these padding errors (padding oracle attack)\n";
    }

    return 0;
}

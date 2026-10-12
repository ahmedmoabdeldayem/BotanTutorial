// Lesson 04 — Asymmetric Encryption (RSA)
// Header: include/botan-3/botan/pubkey.h
// Source: botan-src/src/lib/pubkey/rsa/

#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/exceptn.h>
#include <iostream>
#include <string>

int main() {
    Botan::AutoSeeded_RNG rng;
    Botan::AutoSeeded_RNG rng2;

    // --- GENERATE KEY PAIR ---
    std::cout << "=== Generating RSA-2048 key pair... ===\n";
    Botan::RSA_PrivateKey priv_key(rng, 2048);

    // extract public key from private key
    // the public key is always derivable from the private key
    Botan::RSA_PublicKey pub_key(priv_key.get_n(), priv_key.get_e());

    std::string message = "hello from asymmetric world";
    std::cout << "Plaintext  : " << message << "\n\n";

    // --- ENCRYPT WITH PUBLIC KEY ---
    // OAEP = Optimal Asymmetric Encryption Padding (secure padding scheme)
    // botan/pubkey.h → PK_Encryptor_EME
    Botan::PK_Encryptor_EME encryptor(pub_key, rng, "OAEP(SHA-256)");

    std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> ciphertext = encryptor.encrypt(plaintext, rng);

    std::cout << "=== ENCRYPT (public key) ===\n";
    std::cout << "Ciphertext : " << Botan::hex_encode(ciphertext) << "\n";
    std::cout << "Size       : " << ciphertext.size() << " bytes\n\n";

    // --- DECRYPT WITH PRIVATE KEY ---
    // botan/pubkey.h → PK_Decryptor_EME
    Botan::PK_Decryptor_EME decryptor(priv_key, rng2, "OAEP(SHA-256)");

    Botan::secure_vector<uint8_t> decrypted = decryptor.decrypt(ciphertext);
    std::cout << "=== DECRYPT (private key) ===\n";
    std::cout << "Decrypted  : " << std::string(decrypted.begin(), decrypted.end()) << "\n\n";

    // --- WRONG KEY TEST ---
    // generate a different private key and try to decrypt
    std::cout << "=== Generating wrong key pair... ===\n";
    Botan::RSA_PrivateKey wrong_key(rng, 2048);
    Botan::PK_Decryptor_EME wrong_decryptor(wrong_key, rng, "OAEP(SHA-256)");

    try {
        Botan::secure_vector<uint8_t> wrong_decrypted = wrong_decryptor.decrypt(ciphertext);
        std::cout << "Wrong key decrypted (should not happen): "
                  << std::string(wrong_decrypted.begin(), wrong_decrypted.end()) << "\n";
    } catch (const std::exception& e) {
        std::cout << "Wrong key failed : " << e.what() << "\n";
    }

    return 0;
}

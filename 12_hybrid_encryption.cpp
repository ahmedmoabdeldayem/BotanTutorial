// Lesson 12 — Hybrid Encryption (ECDH + HKDF + AES-256-GCM)
// This is the real-world pattern used by Signal, WhatsApp, iMessage
// Headers: include/botan-3/botan/ecdh.h
//          include/botan-3/botan/kdf.h
//          include/botan-3/botan/aead.h
// Sources: botan-src/src/lib/pubkey/ecdh/
//          botan-src/src/lib/kdf/hkdf/
//          botan-src/src/lib/modes/aead/gcm/

#include <botan/ecdh.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/kdf.h>
#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/x509_key.h>
#include <iostream>
#include <string>
#include <vector>

// -------------------------------------------------------
// Encrypted message structure:
//   ephemeral_pub (65 bytes uncompressed) +
//   nonce         (12 bytes) +
//   ciphertext    (variable) +
//   GCM tag       (16 bytes, appended by Botan)
// -------------------------------------------------------

std::vector<uint8_t> hybrid_encrypt(
    const std::string& plaintext,
    const Botan::Public_Key& recipient_pub,
    Botan::AutoSeeded_RNG& rng)
{
    Botan::EC_Group curve = Botan::EC_Group::from_name("secp256r1");

    // Step 1 — generate ephemeral ECDH key pair (fresh per message)
    Botan::ECDH_PrivateKey ephemeral_priv(rng, curve);
    std::vector<uint8_t> ephemeral_pub_bytes = ephemeral_priv.raw_public_key_bits();

    // Step 2 — ECDH: combine ephemeral private + recipient public → shared secret
    Botan::PK_Key_Agreement ecdh(ephemeral_priv, rng, "Raw");
    Botan::SymmetricKey shared_secret = ecdh.derive_key(32, recipient_pub.raw_public_key_bits());

    // Step 3 — HKDF: clean up shared secret → derive AES key + nonce
    auto hkdf_extract = Botan::KDF::create_or_throw("HKDF-Extract(SHA-256)");
    auto hkdf_expand  = Botan::KDF::create_or_throw("HKDF-Expand(SHA-256)");

    // extract — remove mathematical structure from ECDH output
    Botan::secure_vector<uint8_t> prk = hkdf_extract->derive_key(
        32, shared_secret.bits_of(), std::vector<uint8_t>{}, std::vector<uint8_t>{});

    // expand — derive AES key and nonce independently
    auto aes_key_bytes = hkdf_expand->derive_key(32, prk, std::vector<uint8_t>{},
        std::vector<uint8_t>{'a','e','s','-','k','e','y'});
    auto nonce_bytes   = hkdf_expand->derive_key(12, prk, std::vector<uint8_t>{},
        std::vector<uint8_t>{'a','e','s','-','i','v'});

    // Step 4 — AES-256-GCM encrypt
    auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    aead->set_key(Botan::SymmetricKey(aes_key_bytes));
    aead->start(nonce_bytes);

    Botan::secure_vector<uint8_t> buf(plaintext.begin(), plaintext.end());
    aead->finish(buf);  // buf now contains ciphertext + 16-byte GCM tag

    // Step 5 — assemble final message: ephemeral_pub + nonce + ciphertext+tag
    std::vector<uint8_t> output;
    output.insert(output.end(), ephemeral_pub_bytes.begin(), ephemeral_pub_bytes.end());
    output.insert(output.end(), nonce_bytes.begin(),         nonce_bytes.end());
    output.insert(output.end(), buf.begin(),                 buf.end());

    return output;
}

std::string hybrid_decrypt(
    const std::vector<uint8_t>& encrypted,
    const Botan::ECDH_PrivateKey& recipient_priv,
    Botan::AutoSeeded_RNG& rng)
{
    // parse the message: ephemeral_pub(65) + nonce(12) + ciphertext+tag
    const size_t pub_len   = 65;
    const size_t nonce_len = 12;

    std::vector<uint8_t> ephemeral_pub_bytes(encrypted.begin(),              encrypted.begin() + pub_len);
    std::vector<uint8_t> nonce_bytes        (encrypted.begin() + pub_len,    encrypted.begin() + pub_len + nonce_len);
    Botan::secure_vector<uint8_t> ciphertext(encrypted.begin() + pub_len + nonce_len, encrypted.end());

    // Step 1 — ECDH: combine recipient private + ephemeral public → same shared secret
    Botan::PK_Key_Agreement ecdh(recipient_priv, rng, "Raw");
    Botan::SymmetricKey shared_secret = ecdh.derive_key(32, ephemeral_pub_bytes);

    // Step 2 — HKDF: same derivation as encryption side
    auto hkdf_extract = Botan::KDF::create_or_throw("HKDF-Extract(SHA-256)");
    auto hkdf_expand  = Botan::KDF::create_or_throw("HKDF-Expand(SHA-256)");

    Botan::secure_vector<uint8_t> prk = hkdf_extract->derive_key(
        32, shared_secret.bits_of(), std::vector<uint8_t>{}, std::vector<uint8_t>{});

    auto aes_key_bytes = hkdf_expand->derive_key(32, prk, std::vector<uint8_t>{},
        std::vector<uint8_t>{'a','e','s','-','k','e','y'});

    // Step 3 — AES-256-GCM decrypt (also verifies GCM authentication tag)
    auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    aead->set_key(Botan::SymmetricKey(aes_key_bytes));
    aead->start(nonce_bytes);
    aead->finish(ciphertext);  // throws if GCM tag invalid (tampered)

    return std::string(ciphertext.begin(), ciphertext.end());
}

int main() {
    Botan::AutoSeeded_RNG rng;
    Botan::EC_Group curve = Botan::EC_Group::from_name("secp256r1");

    // recipient generates a long-term key pair (done once, stored)
    Botan::ECDH_PrivateKey recipient_priv(rng, curve);
    const Botan::Public_Key& recipient_pub = recipient_priv;

    std::cout << "=== Recipient key pair ===\n";
    std::cout << "Public key : " << Botan::hex_encode(recipient_pub.raw_public_key_bits()) << "\n\n";

    // -------------------------------------------------------
    // ENCRYPT
    // -------------------------------------------------------
    std::string plaintext = "hello from hybrid encryption";
    std::cout << "=== Encrypt ===\n";
    std::cout << "Plaintext  : " << plaintext << "\n";

    std::vector<uint8_t> encrypted = hybrid_encrypt(plaintext, recipient_pub, rng);

    std::cout << "Encrypted  : " << Botan::hex_encode(encrypted) << "\n";
    std::cout << "Size       : " << encrypted.size() << " bytes\n";
    std::cout << "  (65 ephemeral pub + 12 nonce + " << (encrypted.size() - 77) << " ciphertext+tag)\n\n";

    // -------------------------------------------------------
    // DECRYPT
    // -------------------------------------------------------
    std::cout << "=== Decrypt ===\n";
    std::string decrypted = hybrid_decrypt(encrypted, recipient_priv, rng);
    std::cout << "Decrypted  : " << decrypted << "\n\n";

    // -------------------------------------------------------
    // FORWARD SECRECY DEMO
    // -------------------------------------------------------
    std::cout << "=== Forward secrecy ===\n";
    std::cout << "Encrypt same message twice → different ciphertext each time\n";

    auto enc1 = hybrid_encrypt(plaintext, recipient_pub, rng);
    auto enc2 = hybrid_encrypt(plaintext, recipient_pub, rng);

    std::cout << "Encryption 1 : " << Botan::hex_encode(std::vector<uint8_t>(enc1.begin(), enc1.begin()+16)) << "...\n";
    std::cout << "Encryption 2 : " << Botan::hex_encode(std::vector<uint8_t>(enc2.begin(), enc2.begin()+16)) << "...\n";
    std::cout << "Same         : " << (enc1 == enc2 ? "YES (bad)" : "NO — fresh ephemeral key each time") << "\n\n";

    // -------------------------------------------------------
    // TAMPER TEST
    // -------------------------------------------------------
    std::cout << "=== Tamper test ===\n";
    std::vector<uint8_t> tampered = encrypted;
    tampered[80] ^= 0x01;  // flip one bit in the ciphertext

    try {
        hybrid_decrypt(tampered, recipient_priv, rng);
        std::cout << "Decrypted tampered message (should not happen)\n";
    } catch(const std::exception& e) {
        std::cout << "Tampered message rejected : " << e.what() << "\n";
    }

    return 0;
}

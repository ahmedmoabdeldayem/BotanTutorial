// Lesson 17 — Envelope Encryption
// Encrypt data with a DEK, encrypt the DEK with a KEK.
// How AWS S3, Google Cloud Storage, and HashiCorp Vault protect data at rest.
// Headers: include/botan-3/botan/aead.h
//          include/botan-3/botan/auto_rng.h
// Sources: botan-src/src/lib/modes/aead/gcm/

#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/exceptn.h>
#include <iostream>
#include <string>
#include <vector>

// -------------------------------------------------------
// Envelope: what gets stored on disk / in the database
//
//   encrypted_dek  — the DEK encrypted with the KEK
//   dek_nonce      — nonce used to encrypt the DEK
//   ciphertext     — the actual data encrypted with the DEK
//   data_nonce     — nonce used to encrypt the data
// -------------------------------------------------------
struct Envelope {
    std::vector<uint8_t> encrypted_dek;
    std::vector<uint8_t> dek_nonce;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> data_nonce;
};

// encrypt plaintext — returns an Envelope
// kek never changes; a fresh DEK is generated per call
Envelope seal(const std::string& plaintext,
              const Botan::secure_vector<uint8_t>& kek,
              Botan::AutoSeeded_RNG& rng)
{
    Envelope env;

    // Step 1 — generate a fresh random DEK for this piece of data
    // different DEK per file: compromise of one does not affect others
    Botan::secure_vector<uint8_t> dek = rng.random_vec(32);

    // Step 2 — encrypt the data with the DEK
    auto tmp_data_nonce = rng.random_vec(12);
    env.data_nonce = std::vector<uint8_t>(tmp_data_nonce.begin(), tmp_data_nonce.end());
    auto data_enc = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    data_enc->set_key(dek);
    data_enc->start(env.data_nonce);
    Botan::secure_vector<uint8_t> buf(plaintext.begin(), plaintext.end());
    data_enc->finish(buf);
    env.ciphertext = std::vector<uint8_t>(buf.begin(), buf.end());

    // Step 3 — encrypt the DEK with the KEK
    // the DEK is now wrapped — safe to store alongside the ciphertext
    auto tmp_dek_nonce = rng.random_vec(12);
    env.dek_nonce = std::vector<uint8_t>(tmp_dek_nonce.begin(), tmp_dek_nonce.end());
    auto kek_enc = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    kek_enc->set_key(kek);
    kek_enc->start(env.dek_nonce);
    Botan::secure_vector<uint8_t> dek_buf(dek.begin(), dek.end());
    kek_enc->finish(dek_buf);
    env.encrypted_dek = std::vector<uint8_t>(dek_buf.begin(), dek_buf.end());

    // DEK is discarded here — only lives in memory during encryption
    return env;
}

// decrypt an Envelope — requires the KEK
std::string open(const Envelope& env,
                 const Botan::secure_vector<uint8_t>& kek,
                 Botan::AutoSeeded_RNG& rng)
{
    // Step 1 — decrypt the DEK using the KEK
    auto kek_dec = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    kek_dec->set_key(kek);
    kek_dec->start(env.dek_nonce);
    Botan::secure_vector<uint8_t> dek_buf(env.encrypted_dek.begin(), env.encrypted_dek.end());
    kek_dec->finish(dek_buf);  // throws if KEK is wrong

    // Step 2 — decrypt the data using the recovered DEK
    auto data_dec = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    data_dec->set_key(dek_buf);
    data_dec->start(env.data_nonce);
    Botan::secure_vector<uint8_t> buf(env.ciphertext.begin(), env.ciphertext.end());
    data_dec->finish(buf);  // throws if data was tampered

    // DEK discarded again after use
    return std::string(buf.begin(), buf.end());
}

int main() {
    Botan::AutoSeeded_RNG rng;

    // -------------------------------------------------------
    // PART 1: Basic seal and open
    //
    // KEK = master key, lives only in the KMS (never on disk)
    // DEK = per-file key, generated fresh each time
    // Envelope = what you store: encrypted DEK + encrypted data
    // -------------------------------------------------------
    std::cout << "=== Part 1: Seal and open ===\n\n";

    // KEK — in production this lives in AWS KMS / Vault, never on disk
    Botan::secure_vector<uint8_t> kek = rng.random_vec(32);
    std::cout << "KEK (master key) : " << Botan::hex_encode(kek) << "\n";
    std::cout << "(in production this never leaves the KMS)\n\n";

    std::string plaintext = "sensitive customer data — 1GB file in practice";

    Envelope env = seal(plaintext, kek, rng);

    std::cout << "=== Stored on disk ===\n";
    std::cout << "Encrypted DEK  : " << Botan::hex_encode(env.encrypted_dek) << "\n";
    std::cout << "DEK nonce      : " << Botan::hex_encode(env.dek_nonce) << "\n";
    std::cout << "Ciphertext     : " << Botan::hex_encode(env.ciphertext) << "\n";
    std::cout << "Data nonce     : " << Botan::hex_encode(env.data_nonce) << "\n\n";
    std::cout << "(DEK itself is not stored — only its encrypted form)\n\n";

    std::string recovered = open(env, kek, rng);
    std::cout << "Decrypted      : " << recovered << "\n";
    std::cout << "Match          : " << (recovered == plaintext ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // PART 2: One KEK, many files — each with its own DEK
    //
    // Compromise of one file's DEK does not affect other files.
    // This is why AWS S3 uses a unique DEK per object.
    // -------------------------------------------------------
    std::cout << "=== Part 2: One KEK, multiple files ===\n\n";

    std::vector<std::string> files = {
        "file1: contracts Q1 2025",
        "file2: salary data",
        "file3: source code",
    };

    std::vector<Envelope> envelopes;
    for(const auto& file : files) {
        envelopes.push_back(seal(file, kek, rng));
    }

    std::cout << "Encrypted DEK per file (all different — fresh DEK each time):\n";
    for(size_t i = 0; i < envelopes.size(); i++) {
        std::cout << "  File " << (i+1) << " DEK : "
                  << Botan::hex_encode(envelopes[i].encrypted_dek).substr(0, 32) << "...\n";
    }
    std::cout << "\n";

    for(size_t i = 0; i < envelopes.size(); i++) {
        std::string dec = open(envelopes[i], kek, rng);
        std::cout << "  File " << (i+1) << " decrypted : " << dec << "\n";
    }
    std::cout << "\n";

    // -------------------------------------------------------
    // PART 3: Key rotation — re-encrypt DEK only, not the data
    //
    // Old KEK is compromised. Generate new KEK.
    // Decrypt each DEK with old KEK, re-encrypt with new KEK.
    // The actual data (potentially gigabytes) is never touched.
    // -------------------------------------------------------
    std::cout << "=== Part 3: Key rotation ===\n\n";

    Botan::secure_vector<uint8_t> new_kek = rng.random_vec(32);
    std::cout << "Old KEK : " << Botan::hex_encode(kek)     << "\n";
    std::cout << "New KEK : " << Botan::hex_encode(new_kek) << "\n\n";

    // rotate: decrypt DEK with old KEK, re-encrypt with new KEK
    // data ciphertext is copied unchanged
    Envelope rotated_env;
    rotated_env.ciphertext  = env.ciphertext;   // data untouched
    rotated_env.data_nonce  = env.data_nonce;   // data nonce untouched

    // decrypt DEK with old KEK
    auto old_dec = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    old_dec->set_key(kek);
    old_dec->start(env.dek_nonce);
    Botan::secure_vector<uint8_t> dek_plain(env.encrypted_dek.begin(), env.encrypted_dek.end());
    old_dec->finish(dek_plain);

    // re-encrypt DEK with new KEK
    auto tmp_rot_nonce = rng.random_vec(12);
    rotated_env.dek_nonce = std::vector<uint8_t>(tmp_rot_nonce.begin(), tmp_rot_nonce.end());
    auto new_enc = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    new_enc->set_key(new_kek);
    new_enc->start(rotated_env.dek_nonce);
    new_enc->finish(dek_plain);
    rotated_env.encrypted_dek = std::vector<uint8_t>(dek_plain.begin(), dek_plain.end());

    std::cout << "Old encrypted DEK : " << Botan::hex_encode(env.encrypted_dek)         << "\n";
    std::cout << "New encrypted DEK : " << Botan::hex_encode(rotated_env.encrypted_dek) << "\n";
    std::cout << "Data ciphertext   : unchanged\n\n";

    std::string after_rotation = open(rotated_env, new_kek, rng);
    std::cout << "Decrypted after rotation : " << after_rotation << "\n";
    std::cout << "Match                    : " << (after_rotation == plaintext ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // PART 4: Wrong KEK — cannot recover DEK, cannot read data
    // -------------------------------------------------------
    std::cout << "=== Part 4: Wrong KEK ===\n\n";

    Botan::secure_vector<uint8_t> wrong_kek = rng.random_vec(32);
    try {
        open(env, wrong_kek, rng);
        std::cout << "Decrypted (should not happen)\n";
    } catch(const Botan::Invalid_Authentication_Tag&) {
        std::cout << "Wrong KEK rejected — cannot recover DEK — data unreadable\n\n";
    }

    // -------------------------------------------------------
    // PART 5: Why envelope encryption
    // -------------------------------------------------------
    std::cout << "=== Part 5: Why envelope encryption ===\n\n";
    std::cout << "Unique DEK per file  — one compromise does not affect others\n";
    std::cout << "KEK never on disk    — lives only in KMS, audited on every use\n";
    std::cout << "Cheap key rotation   — re-encrypt DEK only, not gigabytes of data\n";
    std::cout << "Used by              — AWS S3, GCS, Azure Blob, HashiCorp Vault\n";

    return 0;
}

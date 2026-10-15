// Lesson 15 — Post-Quantum Cryptography (ML-KEM + ML-DSA + SLH-DSA)
// NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — finalized 2024.
// Replaces ECDH and ECDSA against quantum computer attacks.
// Headers: include/botan-3/botan/ml_kem.h
//          include/botan-3/botan/ml_dsa.h
//          include/botan-3/botan/slh_dsa.h
// Sources: botan-src/src/lib/pubkey/kyber/
//          botan-src/src/lib/pubkey/dilithium/
//          botan-src/src/lib/pubkey/sphincsplus/

#include <botan/ml_kem.h>
#include <botan/ml_dsa.h>
#include <botan/slh_dsa.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/ecdh.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <iostream>
#include <string>
#include <vector>

int main() {
    Botan::AutoSeeded_RNG rng;

    // -------------------------------------------------------
    // PART 1: ML-KEM — Key Encapsulation Mechanism
    //
    // ML-KEM replaces ECDH. The difference in how it works:
    //
    // ECDH   — both sides compute the same secret from each other's public keys
    //           requires both parties to be active simultaneously
    //
    // ML-KEM — sender encapsulates a secret using recipient's public key
    //           produces: shared_secret + encapsulated_key (ciphertext)
    //           recipient uses private key to recover the same shared_secret
    //           same result, but based on lattice math quantum computers can't break
    // -------------------------------------------------------
    std::cout << "=== Part 1: ML-KEM key encapsulation ===\n\n";

    // ML_KEM_768 = NIST security level 3 (~AES-192 equivalent)
    // ML_KEM_512 = level 1, ML_KEM_1024 = level 5 (highest)
    Botan::ML_KEM_PrivateKey recipient_priv(rng, Botan::ML_KEM_Mode::ML_KEM_768);
    auto recipient_pub = recipient_priv.public_key();

    std::cout << "Recipient public key  : " << recipient_pub->raw_public_key_bits().size() << " bytes\n";
    std::cout << "Recipient private key : " << recipient_priv.raw_private_key_bits().size() << " bytes\n\n";

    // --- Sender side: encapsulate ---
    // produces a shared secret + ciphertext to send to recipient
    // "Raw" — ML-KEM already produces a uniformly random shared secret,
    // no KDF needed unlike ECDH which requires one to clean up the math output
    Botan::PK_KEM_Encryptor enc(*recipient_pub, "Raw");
    auto kem_result = enc.encrypt(rng, 32);  // 32 = desired shared key length

    const auto& encapsulated = kem_result.encapsulated_shared_key();  // send to recipient
    const auto& sender_key   = kem_result.shared_key();               // use as AES key

    std::cout << "=== Sender ===\n";
    std::cout << "Encapsulated key (send to recipient) : " << encapsulated.size() << " bytes\n";
    std::cout << "Shared secret (use for AES)          : " << Botan::hex_encode(sender_key) << "\n\n";

    // --- Recipient side: decapsulate ---
    // recovers the same shared secret using private key + ciphertext
    Botan::PK_KEM_Decryptor dec(recipient_priv, rng, "Raw");
    auto recipient_key = dec.decrypt(encapsulated, 32);

    std::cout << "=== Recipient ===\n";
    std::cout << "Shared secret (recovered)            : " << Botan::hex_encode(recipient_key) << "\n\n";

    std::cout << "Keys match : " << (sender_key == recipient_key ? "YES — same secret, secure channel established" : "NO") << "\n\n";

    // -------------------------------------------------------
    // PART 2: ML-DSA — Digital Signatures
    //
    // ML-DSA replaces ECDSA. Same job: sign a message, verify the signature.
    // Based on lattice problems instead of elliptic curves.
    // -------------------------------------------------------
    std::cout << "=== Part 2: ML-DSA signatures ===\n\n";

    // ML_DSA_6x5 = NIST security level 3
    Botan::ML_DSA_PrivateKey signing_key(rng, Botan::ML_DSA_Mode::ML_DSA_6x5);
    auto verify_key = signing_key.public_key();

    std::string message = "post-quantum signed message";

    Botan::PK_Signer signer(signing_key, rng, "");
    signer.update(message);
    auto signature = signer.signature(rng);

    std::cout << "Message   : " << message << "\n";
    std::cout << "Signature : " << signature.size() << " bytes\n";
    std::cout << "           (" << Botan::hex_encode(std::vector<uint8_t>(signature.begin(), signature.begin()+16)) << "...)\n\n";

    Botan::PK_Verifier verifier(*verify_key, "");
    verifier.update(message);
    bool valid = verifier.check_signature(signature);
    std::cout << "Signature valid : " << (valid ? "YES" : "NO") << "\n\n";

    // tamper test
    std::string tampered = "post-quantum signed messAge";  // capital A
    Botan::PK_Verifier verifier2(*verify_key, "");
    verifier2.update(tampered);
    bool tampered_valid = verifier2.check_signature(signature);
    std::cout << "Tampered message valid : " << (tampered_valid ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // PART 3: SLH-DSA — Hash-based signatures (FIPS 205)
    //
    // ML-DSA and ML-KEM both rely on lattice math being hard.
    // SLH-DSA relies only on hash functions — SHA-256 or SHAKE.
    // Hash functions have been studied for decades and are
    // considered extremely well understood. If lattice math is
    // ever broken, SLH-DSA is the fallback.
    //
    // Tradeoff: much larger signatures, slower signing.
    // Use case: code signing, firmware, CAs — sign rarely, verify often.
    //
    // Two variants:
    //   Small — smaller signatures, slower signing
    //   Fast  — larger signatures, faster signing
    // -------------------------------------------------------
    std::cout << "=== Part 3: SLH-DSA signatures (hash-based) ===\n\n";

    // SLHDSA128Small with SHA-256 — NIST security level 1, small signatures
    Botan::SLH_DSA_PrivateKey slh_key(rng,
        Botan::Sphincs_Parameter_Set::SLHDSA128Small,
        Botan::Sphincs_Hash_Type::Sha256);
    auto slh_pub = slh_key.public_key();

    Botan::PK_Signer slh_signer(slh_key, rng, "");
    slh_signer.update(message);
    auto slh_signature = slh_signer.signature(rng);

    std::cout << "Message   : " << message << "\n";
    std::cout << "Signature : " << slh_signature.size() << " bytes\n";
    std::cout << "Public key: " << slh_pub->raw_public_key_bits().size() << " bytes\n\n";

    Botan::PK_Verifier slh_verifier(*slh_pub, "");
    slh_verifier.update(message);
    bool slh_valid = slh_verifier.check_signature(slh_signature);
    std::cout << "Signature valid : " << (slh_valid ? "YES" : "NO") << "\n\n";

    std::cout << "Security basis  : hash functions only (SHA-256)\n";
    std::cout << "Trust assumption: if SHA-256 is safe, SLH-DSA is safe\n";
    std::cout << "ML-DSA basis    : lattice problems (newer assumption)\n\n";

    // -------------------------------------------------------
    // PART 4: Size comparison — classical vs post-quantum
    //
    // The tradeoff for quantum resistance: larger keys and signatures.
    // This is why post-quantum hasn't fully replaced classical yet —
    // bandwidth and storage costs are real.
    // -------------------------------------------------------
    std::cout << "=== Part 4: Size comparison — classical vs post-quantum ===\n\n";

    // classical ECDH (P-256)
    Botan::EC_Group curve = Botan::EC_Group::from_name("secp256r1");
    Botan::ECDH_PrivateKey ecdh_priv(rng, curve);
    size_t ecdh_pub_size  = ecdh_priv.raw_public_key_bits().size();
    size_t ecdh_priv_size = ecdh_priv.raw_private_key_bits().size();

    // classical ECDSA (P-256)
    Botan::ECDSA_PrivateKey ecdsa_priv(rng, curve);
    Botan::PK_Signer ecdsa_signer(ecdsa_priv, rng, "SHA-256");
    ecdsa_signer.update(message);
    auto ecdsa_sig = ecdsa_signer.signature(rng);

    std::cout << "--- Key Exchange ---\n";
    std::cout << "ECDH P-256 public key  : " << ecdh_pub_size  << " bytes\n";
    std::cout << "ECDH P-256 private key : " << ecdh_priv_size << " bytes\n";
    std::cout << "ML-KEM-768 public key  : " << recipient_pub->raw_public_key_bits().size()  << " bytes  ("
              << (recipient_pub->raw_public_key_bits().size() / ecdh_pub_size) << "x larger)\n";
    std::cout << "ML-KEM-768 private key : " << recipient_priv.raw_private_key_bits().size() << " bytes  ("
              << (recipient_priv.raw_private_key_bits().size() / ecdh_priv_size) << "x larger)\n\n";

    std::cout << "--- Signatures ---\n";
    std::cout << "ECDSA P-256 signature       : " << ecdsa_sig.size()       << " bytes\n";
    std::cout << "ML-DSA-6x5  signature       : " << signature.size()       << " bytes  ("
              << (signature.size() / ecdsa_sig.size()) << "x larger)\n";
    std::cout << "SLH-DSA-128s-sha2 signature : " << slh_signature.size()   << " bytes  ("
              << (slh_signature.size() / ecdsa_sig.size()) << "x larger)\n\n";

    std::cout << "--- Public keys ---\n";
    std::cout << "ECDSA P-256 public key      : " << ecdsa_priv.raw_public_key_bits().size() << " bytes\n";
    std::cout << "ML-DSA-6x5  public key      : " << verify_key->raw_public_key_bits().size() << " bytes  ("
              << (verify_key->raw_public_key_bits().size() / ecdsa_priv.raw_public_key_bits().size()) << "x larger)\n";
    std::cout << "SLH-DSA-128s-sha2 public key: " << slh_pub->raw_public_key_bits().size() << " bytes  "
              << "(smaller than ECDSA — hash-based keys are tiny)\n\n";

    std::cout << "--- When to use each signature algorithm ---\n";
    std::cout << "ECDSA      — classical, fast, small. Use today where quantum is not a concern.\n";
    std::cout << "ML-DSA     — lattice-based, fast, medium size. Primary PQ signature choice.\n";
    std::cout << "SLH-DSA    — hash-based, slow, large. Fallback if lattices are ever broken.\n\n";

    std::cout << "Quantum resistance comes at a cost in bandwidth and storage.\n";
    std::cout << "TLS 1.3 is already adding hybrid modes: X25519+ML-KEM-768 together,\n";
    std::cout << "so you get classical security today and quantum security tomorrow.\n";

    return 0;
}

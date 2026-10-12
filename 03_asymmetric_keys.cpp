// Lesson 03 — Asymmetric Key Generation
// Headers: include/botan-3/botan/rsa.h
//          include/botan-3/botan/ecdsa.h
//          include/botan-3/botan/ed25519.h
// Sources: botan-src/src/lib/pubkey/rsa/
//          botan-src/src/lib/pubkey/ecdsa/
//          botan-src/src/lib/pubkey/ed25519/

#include <botan/rsa.h>
#include <botan/ecdsa.h>
#include <botan/ed25519.h>
#include <botan/ec_group.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <iostream>

int main() {
    Botan::AutoSeeded_RNG rng;

    // --- RSA ----
    std::cout << "=== RSA-2048 s===\n";

    // botan/rsa.h → RSA_PrivateKey constructor
    // generating RSA is slow — it searches for large prime numbers
    Botan::RSA_PrivateKey rsa_key(rng, 2048);

    std::string rsa_priv = Botan::PKCS8::PEM_encode(rsa_key);
    std::string rsa_pub  = Botan::X509::PEM_encode(rsa_key);

    std::cout << "Private key size : " << rsa_priv.size() << " bytes\n";
    std::cout << "Public key size  : " << rsa_pub.size()  << " bytes\n";
    std::cout << rsa_pub << "\n";
    

    // --- EC (P-256) ---
    std::cout << "=== EC P-256 ===\n";

    // botan/ec_group.h → EC_Group defines the curve parameters
    // botan/ecdsa.h → ECDSA_PrivateKey constructor
    Botan::EC_Group p256 = Botan::EC_Group::from_name("secp256r1");
    Botan::ECDSA_PrivateKey ec_key(rng, p256);

    std::string ec_priv = Botan::PKCS8::PEM_encode(ec_key);
    std::string ec_pub  = Botan::X509::PEM_encode(ec_key);

    std::cout << "Private key size : " << ec_priv.size() << " bytes\n";
    std::cout << "Public key size  : " << ec_pub.size()  << " bytes\n";
    std::cout << ec_pub << "\n";

    // --- Ed25519 ---
    std::cout << "=== Ed25519 ===\n";

    // botan/ed25519.h → Ed25519_PrivateKey constructor
    Botan::Ed25519_PrivateKey ed_key(rng);

    std::string ed_priv = Botan::PKCS8::PEM_encode(ed_key);
    std::string ed_pub  = Botan::X509::PEM_encode(ed_key);

    std::cout << "Private key size : " << ed_priv.size() << " bytes\n";
    std::cout << "Public key size  : " << ed_pub.size()  << " bytes\n";
    std::cout << ed_pub << "\n";

    // --- SIZE COMPARISON ---
    std::cout << "=== Size Comparison ===\n";
    std::cout << "RSA-2048 private : " << rsa_priv.size() << " bytes\n";
    std::cout << "EC P-256 private : " << ec_priv.size()  << " bytes\n";
    std::cout << "Ed25519  private : " << ed_priv.size()  << " bytes\n";
    std::cout << "=== Size Comparison public ===\n";
    std::cout << "RSA-2048 public : " << rsa_pub.size() << " bytes\n";
    std::cout << "EC P-256 public : " << ec_pub.size()  << " bytes\n";
    std::cout << "Ed25519  public : " << ed_pub.size()  << " bytes\n";
    return 0;
}

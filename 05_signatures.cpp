// Lesson 05 — Digital Signatures
// Headers: include/botan-3/botan/ed25519.h
//          include/botan-3/botan/ecdsa.h
//          include/botan-3/botan/rsa.h
//          include/botan-3/botan/pubkey.h
// Sources: botan-src/src/lib/pubkey/ed25519/
//          botan-src/src/lib/pubkey/ecdsa/
//          botan-src/src/lib/pubkey/rsa/

#include <botan/ed25519.h>
#include <botan/ecdsa.h>
#include <botan/rsa.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>
#include <string>
#include <vector>

// helper — sign then verify, also tests tampering
void test_signature(
    const std::string& algo_name,
    Botan::Private_Key& priv_key,
    const Botan::Public_Key& pub_key,
    const std::string& padding,
    Botan::AutoSeeded_RNG& rng)
{
    std::cout << "=== " << algo_name << " ===\n";

    std::string message = "sign me please";
    std::vector<uint8_t> msg_bytes(message.begin(), message.end());

    // --- SIGN with private key ---
    // botan/pubkey.h → PK_Signer
    Botan::PK_Signer signer(priv_key, rng, padding);
    signer.update(msg_bytes);
    std::vector<uint8_t> signature = signer.signature(rng);

    std::cout << "Message   : " << message << "\n";
    std::cout << "Signature : " << Botan::hex_encode(signature) << "\n";
    std::cout << "Sig size  : " << signature.size() << " bytes\n";

    // --- VERIFY with public key ---
    // botan/pubkey.h → PK_Verifier
    Botan::PK_Verifier verifier(pub_key, padding);
    verifier.update(msg_bytes);
    bool valid = verifier.check_signature(signature);
    std::cout << "Valid sig : " << (valid ? "YES" : "NO") << "\n";

    // --- TAMPER WITH MESSAGE ---
    std::string tampered_msg = "sign me pleese";  // one char changed
    std::vector<uint8_t> tampered_bytes(tampered_msg.begin(), tampered_msg.end());

    Botan::PK_Verifier verifier2(pub_key, padding);
    verifier2.update(tampered_bytes);
    bool tampered_valid = verifier2.check_signature(signature);
    std::cout << "Tampered message  → valid: " << (tampered_valid ? "YES" : "NO") << "\n";

    // --- TAMPER WITH SIGNATURE ---
    std::vector<uint8_t> tampered_sig = signature;
    tampered_sig[0] ^= 0x01;  // flip one bit

    Botan::PK_Verifier verifier3(pub_key, padding);
    verifier3.update(msg_bytes);
    bool sig_tampered_valid = verifier3.check_signature(tampered_sig);
    std::cout << "Tampered signature → valid: " << (sig_tampered_valid ? "YES" : "NO") << "\n\n";
}

int main() {
    Botan::AutoSeeded_RNG rng;

    // --- Ed25519 ---
    Botan::Ed25519_PrivateKey ed_priv(rng);
    const Botan::Public_Key& ed_pub = ed_priv;
    test_signature("Ed25519", ed_priv, ed_pub, "Pure", rng);

    // --- ECDSA P-256 ---
    Botan::EC_Group curve = Botan::EC_Group::from_name("secp256r1");
    Botan::ECDSA_PrivateKey ec_priv(rng, curve);
    const Botan::Public_Key& ec_pub = ec_priv;
    test_signature("ECDSA P-256", ec_priv, ec_pub, "EMSA1(SHA-256)", rng);

    // --- RSA-PSS ---
    std::cout << "Generating RSA-2048 (slow)...\n";
    Botan::RSA_PrivateKey rsa_priv(rng, 2048);
    const Botan::Public_Key& rsa_pub = rsa_priv;
    test_signature("RSA-PSS", rsa_priv, rsa_pub, "EMSA-PSS(SHA-256)", rng);

    // --- SIZE COMPARISON ---
    std::cout << "=== Signature Size Comparison ===\n";
    std::vector<uint8_t> msg(14, 0x61);

    Botan::PK_Signer ed_signer(ed_priv, rng, "Pure");
    ed_signer.update(msg);
    std::cout << "Ed25519  : " << ed_signer.signature(rng).size() << " bytes\n";

    Botan::PK_Signer ec_signer(ec_priv, rng, "EMSA1(SHA-256)");
    ec_signer.update(msg);
    std::cout << "ECDSA    : " << ec_signer.signature(rng).size() << " bytes\n";

    Botan::PK_Signer rsa_signer(rsa_priv, rng, "EMSA-PSS(SHA-256)");
    rsa_signer.update(msg);
    std::cout << "RSA-PSS  : " << rsa_signer.signature(rng).size() << " bytes\n";

    return 0;
}

// Lesson 04b — ECDH Key Exchange
// Header: include/botan-3/botan/ecdh.h
// Source: botan-src/src/lib/pubkey/ecdh/

#include <botan/ecdh.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>

int main() {
    Botan::AutoSeeded_RNG rng;

    // both sides agree on the same curve upfront — this is public knowledge
    Botan::EC_Group curve = Botan::EC_Group::from_name("secp256r1");

    // --- ALICE ---
    // botan/ecdh.h → ECDH_PrivateKey
    Botan::ECDH_PrivateKey alice_priv(rng, curve);
    // extract alice public key to send to bob
    const Botan::Public_Key& alice_pub = alice_priv;

    // --- BOB ---
    Botan::ECDH_PrivateKey bob_priv(rng, curve);
    // extract bob public key to send to alice
    const Botan::Public_Key& bob_pub = bob_priv;

    std::cout << "=== Keys Generated ===\n";
    std::cout << "Alice public key: " << Botan::hex_encode(alice_pub.raw_public_key_bits()) << "\n";
    std::cout << "Bob   public key: " << Botan::hex_encode(bob_pub.raw_public_key_bits())   << "\n\n";

    // --- ALICE COMPUTES SHARED SECRET ---
    // alice uses her private key + bob's public key
    // botan/pubkey.h → PK_Key_Agreement
    Botan::PK_Key_Agreement alice_ka(alice_priv, rng, "HKDF(SHA-256)");
    Botan::SymmetricKey alice_shared = alice_ka.derive_key(32, bob_pub.raw_public_key_bits());

    // --- BOB COMPUTES SHARED SECRET ---
    // bob uses his private key + alice's public key
    Botan::PK_Key_Agreement bob_ka(bob_priv, rng, "HKDF(SHA-256)");
    Botan::SymmetricKey bob_shared = bob_ka.derive_key(32, alice_pub.raw_public_key_bits());

    std::cout << "=== Shared Secrets ===\n";
    std::cout << "Alice derived: " << Botan::hex_encode(alice_shared.bits_of()) << "\n";
    std::cout << "Bob   derived: " << Botan::hex_encode(bob_shared.bits_of())   << "\n\n";

    // both should be identical
    if(alice_shared.bits_of() == bob_shared.bits_of()) {
        std::cout << "Shared secrets MATCH\n";
        std::cout << "Both can now use this as an AES-256 key\n\n";
    } else {
        std::cout << "Shared secrets DO NOT match — something is wrong\n\n";
    }

    // --- WHAT AN ATTACKER SEES ---
    std::cout << "=== What attacker sees on the wire ===\n";
    std::cout << "Alice public key: " << Botan::hex_encode(alice_pub.raw_public_key_bits()) << "\n";
    std::cout << "Bob   public key: " << Botan::hex_encode(bob_pub.raw_public_key_bits())   << "\n";
    std::cout << "Shared secret  : [attacker cannot compute this without a private key]\n";

    return 0;
}

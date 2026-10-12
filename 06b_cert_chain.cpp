// Lesson 06b — Certificate Chain (Root → Intermediate → End Entity)
// Only the Root CA is in the trust store
// Sources: botan-src/src/lib/x509/

#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/x509self.h>
#include <botan/x509cert.h>
#include <botan/x509_ca.h>
#include <botan/x509path.h>
#include <botan/certstor.h>
#include <botan/hex.h>
#include <iostream>
#include <chrono>

// helper — signs a CSR and returns the certificate
Botan::X509_Certificate sign_cert(
    Botan::X509_CA& ca,
    Botan::PKCS10_Request& csr,
    Botan::AutoSeeded_RNG& rng)
{
    auto now    = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::hours(24 * 365);
    return ca.sign_request(csr, rng, Botan::X509_Time(now), Botan::X509_Time(expiry));
}

int main() {
    Botan::AutoSeeded_RNG rng;
    Botan::EC_Group curve = Botan::EC_Group::from_name("secp256r1");

    // -------------------------------------------------------
    // LEVEL 1: ROOT CA (self-signed)
    // -------------------------------------------------------
    std::cout << "=== Level 1: Root CA ===\n";
    Botan::ECDSA_PrivateKey root_key(rng, curve);

    Botan::X509_Cert_Options root_opts;
    root_opts.common_name  = "Root CA";
    root_opts.organization = "My Org";
    root_opts.country      = "US";
    root_opts.CA_key(2);   // path length 2 — allows 2 levels below it

    Botan::X509_Certificate root_cert =
        Botan::X509::create_self_signed_cert(root_opts, root_key, "SHA-256", rng);

    std::cout << "Subject : " << root_cert.subject_dn().to_string() << "\n";
    std::cout << "Issuer  : " << root_cert.issuer_dn().to_string()  << "\n";
    std::cout << "Is CA   : " << (root_cert.is_CA_cert() ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // LEVEL 2: INTERMEDIATE CA (signed by Root CA)
    // -------------------------------------------------------
    std::cout << "=== Level 2: Intermediate CA ===\n";
    Botan::ECDSA_PrivateKey inter_key(rng, curve);

    Botan::X509_Cert_Options inter_opts;
    inter_opts.common_name  = "Intermediate CA";
    inter_opts.organization = "My Org";
    inter_opts.country      = "US";
    inter_opts.CA_key(1);   // path length 1 — allows 1 level below it

    Botan::PKCS10_Request inter_csr =
        Botan::X509::create_cert_req(inter_opts, inter_key, "SHA-256", rng);

    Botan::X509_CA root_ca(root_cert, root_key, "SHA-256", rng);
    Botan::X509_Certificate inter_cert = sign_cert(root_ca, inter_csr, rng);

    std::cout << "Subject : " << inter_cert.subject_dn().to_string() << "\n";
    std::cout << "Issuer  : " << inter_cert.issuer_dn().to_string()  << "\n";
    std::cout << "Is CA   : " << (inter_cert.is_CA_cert() ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // LEVEL 3: END ENTITY (signed by Intermediate CA)
    // -------------------------------------------------------
    std::cout << "=== Level 3: End Entity (Bob) ===\n";
    Botan::ECDSA_PrivateKey bob_key(rng, curve);

    Botan::X509_Cert_Options bob_opts;
    bob_opts.common_name  = "Bob";
    bob_opts.organization = "Bob's Company";
    bob_opts.country      = "US";
    bob_opts.dns          = "bob.example.com";
    // no CA_key() call — this is not a CA

    Botan::PKCS10_Request bob_csr =
        Botan::X509::create_cert_req(bob_opts, bob_key, "SHA-256", rng);

    Botan::X509_CA inter_ca(inter_cert, inter_key, "SHA-256", rng);
    Botan::X509_Certificate bob_cert = sign_cert(inter_ca, bob_csr, rng);

    std::cout << "Subject : " << bob_cert.subject_dn().to_string() << "\n";
    std::cout << "Issuer  : " << bob_cert.issuer_dn().to_string()  << "\n";
    std::cout << "Is CA   : " << (bob_cert.is_CA_cert() ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // VERIFY — only Root CA in trust store
    // chain must include intermediate + end entity
    // -------------------------------------------------------
    std::cout << "=== Verification ===\n";
    std::cout << "Trust store contains: Root CA only\n\n";

    // only root is trusted
    Botan::Certificate_Store_In_Memory trust_store;
    trust_store.add_certificate(root_cert);

    // chain: end entity + intermediate (root is in trust store)
    std::vector<Botan::X509_Certificate> chain = { bob_cert, inter_cert };

    Botan::Path_Validation_Restrictions restrictions;
    auto result = Botan::x509_path_validate(chain, restrictions, trust_store);

    std::cout << "Result  : " << result.result_string() << "\n\n";

    // -------------------------------------------------------
    // TAMPER TEST — remove intermediate from chain
    // -------------------------------------------------------
    std::cout << "=== Tamper: missing intermediate cert ===\n";
    std::vector<Botan::X509_Certificate> incomplete_chain = { bob_cert };  // no intermediate

    auto bad_result = Botan::x509_path_validate(incomplete_chain, restrictions, trust_store);
    std::cout << "Result  : " << bad_result.result_string() << "\n\n";

    // -------------------------------------------------------
    // TAMPER TEST — wrong trust store (trust intermediate instead of root)
    // -------------------------------------------------------
    std::cout << "=== Tamper: trusting intermediate instead of root ===\n";
    Botan::Certificate_Store_In_Memory wrong_store;
    wrong_store.add_certificate(inter_cert);   // only intermediate trusted, not root

    auto wrong_result = Botan::x509_path_validate(chain, restrictions, wrong_store);
    std::cout << "Result  : " << wrong_result.result_string() << "\n";

    return 0;
}

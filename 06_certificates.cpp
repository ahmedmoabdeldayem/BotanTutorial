// Lesson 06 — X.509 Certificates & PKI
// Headers: include/botan-3/botan/x509self.h
//          include/botan-3/botan/x509cert.h
//          include/botan-3/botan/x509_ca.h
//          include/botan-3/botan/x509path.h
//          include/botan-3/botan/certstor.h
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

int main() {
    Botan::AutoSeeded_RNG rng;
    Botan::EC_Group curve = Botan::EC_Group::from_name("secp256r1");

    // --- STEP 1: CREATE CA KEY PAIR ---
    std::cout << "=== Step 1: Creating CA key pair ===\n";
    Botan::ECDSA_PrivateKey ca_key(rng, curve);
    std::cout << "CA private key generated\n\n";

    // --- STEP 2: CREATE SELF-SIGNED CA CERTIFICATE ---
    std::cout << "=== Step 2: Creating self-signed CA certificate ===\n";

    Botan::X509_Cert_Options ca_opts;
    ca_opts.common_name  = "My Root CA";
    ca_opts.organization = "My Org";
    ca_opts.country      = "US";
    ca_opts.CA_key(1);

    Botan::X509_Certificate ca_cert = Botan::X509::create_self_signed_cert(ca_opts, ca_key, "SHA-256", rng);

    std::cout << "CA Certificate:\n";
    std::cout << "  Subject : " << ca_cert.subject_dn().to_string() << "\n";
    std::cout << "  Issuer  : " << ca_cert.issuer_dn().to_string()  << "\n";
    std::cout << "  Is CA   : " << (ca_cert.is_CA_cert() ? "YES" : "NO") << "\n\n";

    // --- STEP 3: CREATE USER KEY PAIR ---
    std::cout << "=== Step 3: Creating user key pair ===\n";
    Botan::ECDSA_PrivateKey user_key(rng, curve);
    std::cout << "User private key generated\n\n";

    // --- STEP 4: CREATE CSR ---
    std::cout << "=== Step 4: Creating CSR ===\n";

    Botan::X509_Cert_Options user_opts;
    user_opts.common_name  = "Bob";
    user_opts.organization = "Bob's Company";
    user_opts.country      = "US";
    user_opts.dns          = "bob.example.com";

    Botan::PKCS10_Request csr = Botan::X509::create_cert_req(user_opts, user_key, "SHA-256", rng);
    std::cout << "CSR created for: " << csr.subject_dn().to_string() << "\n\n";

    // --- STEP 5: CA SIGNS THE USER CERTIFICATE ---
    std::cout << "=== Step 5: CA signing user certificate ===\n";

    Botan::X509_CA ca(ca_cert, ca_key, "SHA-256", rng);

    // X509_Time takes chrono::time_point directly
    auto now    = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::hours(24 * 365);

    Botan::X509_Time start_time(now);
    Botan::X509_Time end_time(expiry);

    Botan::X509_Certificate user_cert = ca.sign_request(csr, rng, start_time, end_time);

    std::cout << "User Certificate:\n";
    std::cout << "  Subject : " << user_cert.subject_dn().to_string()      << "\n";
    std::cout << "  Issuer  : " << user_cert.issuer_dn().to_string()       << "\n";
    std::cout << "  Is CA   : " << (user_cert.is_CA_cert() ? "YES" : "NO") << "\n\n";

    // --- STEP 6: VERIFY THE CERTIFICATE CHAIN ---
    std::cout << "=== Step 6: Verifying certificate chain ===\n";

    // botan/certstor.h → Certificate_Store_In_Memory
    Botan::Certificate_Store_In_Memory trusted_store;
    trusted_store.add_certificate(ca_cert);

    // botan/x509path.h → Path_Validation_Restrictions, x509_path_validate
    Botan::Path_Validation_Restrictions restrictions;
    std::vector<Botan::X509_Certificate> cert_chain = { user_cert };

    auto result = Botan::x509_path_validate(cert_chain, restrictions, trusted_store);
    std::cout << "Validation result: " << result.result_string() << "\n\n";

    // --- STEP 7: INSPECT CERTIFICATE FIELDS ---
    std::cout << "=== Step 7: Certificate fields ===\n";
    std::cout << "Serial number : " << Botan::hex_encode(user_cert.serial_number()) << "\n";
    std::cout << "Fingerprint   : " << user_cert.fingerprint("SHA-256")             << "\n";
    std::cout << "DNS names     : ";
    for(const auto& dns : user_cert.subject_alt_name().dns_names())
        std::cout << dns.to_string() << " ";
    std::cout << "\n";

    return 0;
}

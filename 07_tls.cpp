// Lesson 07 — TLS 1.3
// Headers: include/botan-3/botan/tls_server.h
//          include/botan-3/botan/tls_client.h
//          include/botan-3/botan/tls_callbacks.h
//          include/botan-3/botan/tls_policy.h
// Sources: botan-src/src/lib/tls/

#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/x509self.h>
#include <botan/x509cert.h>
#include <botan/x509_ca.h>
#include <botan/x509path.h>
#include <botan/certstor.h>
#include <botan/tls_server.h>
#include <botan/tls_client.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/tls_exceptn.h>
#include <botan/credentials_manager.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <memory>

// -------------------------------------------------------
// TLS 1.3 only policy
// -------------------------------------------------------
class TLS13_Policy : public Botan::TLS::Policy {
public:
    bool allow_tls12() const override { return false; }
    bool allow_tls13() const override { return true;  }
};

// -------------------------------------------------------
// PKI setup — CA + server certificate
// -------------------------------------------------------
struct PKI {
    Botan::AutoSeeded_RNG&           rng;
    Botan::ECDSA_PrivateKey          ca_key;
    Botan::X509_Certificate          ca_cert;
    Botan::ECDSA_PrivateKey          server_key;
    Botan::X509_Certificate          server_cert;

    PKI(Botan::AutoSeeded_RNG& rng) :
        rng(rng),
        ca_key(rng, Botan::EC_Group::from_name("secp256r1")),
        ca_cert(make_ca_cert()),
        server_key(rng, Botan::EC_Group::from_name("secp256r1")),
        server_cert(make_server_cert())
    {}

    Botan::X509_Certificate make_ca_cert() {
        Botan::X509_Cert_Options opts;
        opts.common_name  = "Test CA";
        opts.organization = "Test";
        opts.country      = "US";
        opts.CA_key(1);
        return Botan::X509::create_self_signed_cert(opts, ca_key, "SHA-256", rng);
    }

    Botan::X509_Certificate make_server_cert() {
        Botan::X509_Cert_Options opts;
        opts.common_name = "localhost";
        opts.dns         = "localhost";
        opts.country     = "US";

        auto csr    = Botan::X509::create_cert_req(opts, server_key, "SHA-256", rng);
        auto now    = std::chrono::system_clock::now();
        auto expiry = now + std::chrono::hours(24 * 365);

        Botan::X509_CA ca(ca_cert, ca_key, "SHA-256", rng);
        return ca.sign_request(csr, rng, Botan::X509_Time(now), Botan::X509_Time(expiry));
    }
};

// -------------------------------------------------------
// Credentials manager — provides cert + key to TLS
// -------------------------------------------------------
class Simple_Credentials : public Botan::Credentials_Manager {
public:
    Simple_Credentials(const PKI& pki,
                       Botan::Certificate_Store_In_Memory* trust_store = nullptr) :
        m_pki(pki), m_trust_store(trust_store) {}

    std::vector<Botan::X509_Certificate> cert_chain(
        const std::vector<std::string>&,
        const std::vector<Botan::AlgorithmIdentifier>&,
        const std::string&,
        const std::string&) override
    {
        return { m_pki.server_cert };
    }

    std::shared_ptr<Botan::Private_Key> private_key_for(
        const Botan::X509_Certificate&,
        const std::string&,
        const std::string&) override
    {
        return std::make_shared<Botan::ECDSA_PrivateKey>(m_pki.server_key);
    }

    std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
        const std::string&,
        const std::string&) override
    {
        if(m_trust_store)
            return { m_trust_store };
        return {};
    }

private:
    const PKI& m_pki;
    Botan::Certificate_Store_In_Memory* m_trust_store;
};

// -------------------------------------------------------
// TLS Callbacks
// -------------------------------------------------------
class TLS_Pipe : public Botan::TLS::Callbacks {
public:
    std::string              name;
    std::vector<uint8_t>     outgoing;
    std::vector<uint8_t>     received;
    bool                     handshake_done = false;
    Botan::Certificate_Store_In_Memory* trust_store = nullptr;

    explicit TLS_Pipe(const std::string& n) : name(n) {}

    void tls_emit_data(std::span<const uint8_t> data) override {
        outgoing.insert(outgoing.end(), data.begin(), data.end());
    }

    void tls_record_received(uint64_t, std::span<const uint8_t> data) override {
        received.insert(received.end(), data.begin(), data.end());
        std::cout << "[" << name << "] received: "
                  << std::string(data.begin(), data.end()) << "\n";
    }

    void tls_alert(Botan::TLS::Alert alert) override {
        std::cout << "[" << name << "] alert: " << alert.type_string() << "\n";
    }

    void tls_session_established(const Botan::TLS::Session_Summary& session) override {
        handshake_done = true;
        std::cout << "[" << name << "] handshake complete\n";
        std::cout << "[" << name << "] version : " << session.version().to_string() << "\n";
        std::cout << "[" << name << "] cipher  : " << session.ciphersuite().to_string() << "\n";
    }

    // verify server certificate chain
    void tls_verify_cert_chain(
        const std::vector<Botan::X509_Certificate>& cert_chain,
        const std::vector<std::optional<Botan::OCSP::Response>>&,
        const std::vector<Botan::Certificate_Store*>& trusted_roots,
        Botan::Usage_Type,
        std::string_view hostname,
        const Botan::TLS::Policy&) override
    {
        if(!trust_store) return;  // server side — skip client cert verification

        Botan::Path_Validation_Restrictions restrictions;
        auto result = Botan::x509_path_validate(cert_chain, restrictions, *trust_store);

        std::cout << "[" << name << "] cert check: " << result.result_string() << "\n";

        if(!result.successful_validation())
            throw Botan::TLS::TLS_Exception(
                Botan::TLS::Alert::BadCertificate,
                "Certificate validation failed");
    }
};

// helper — move bytes from one side to the other
void transfer(TLS_Pipe& from, Botan::TLS::Channel& to) {
    if(!from.outgoing.empty()) {
        to.received_data(from.outgoing);
        from.outgoing.clear();
    }
}

int main() {
    auto rng = std::make_shared<Botan::AutoSeeded_RNG>();

    std::cout << "=== Setting up PKI ===\n";
    PKI pki(*rng);
    std::cout << "CA cert     : " << pki.ca_cert.subject_dn().to_string()     << "\n";
    std::cout << "Server cert : " << pki.server_cert.subject_dn().to_string() << "\n\n";

    // trust store — client uses this to verify server cert
    Botan::Certificate_Store_In_Memory trust_store;
    trust_store.add_certificate(pki.ca_cert);

    // credentials
    Simple_Credentials server_creds(pki);
    Simple_Credentials client_creds(pki, &trust_store);

    // session managers — Botan 3 takes shared_ptr<RNG>
    auto server_session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
    auto client_session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);

    auto policy = std::make_shared<TLS13_Policy>();

    // callbacks — Botan 3 takes shared_ptr<Callbacks>
    auto server_pipe = std::make_shared<TLS_Pipe>("SERVER");
    auto client_pipe = std::make_shared<TLS_Pipe>("CLIENT");
    client_pipe->trust_store = &trust_store;  // client verifies server cert

    std::cout << "=== TLS Handshake ===\n";

    Botan::TLS::Server server(
        server_pipe, server_session_mgr,
        std::make_shared<Simple_Credentials>(pki),
        policy, rng);

    Botan::TLS::Client client(
        client_pipe, client_session_mgr,
        std::make_shared<Simple_Credentials>(pki, &trust_store),
        policy, rng,
        Botan::TLS::Server_Information("localhost", 443));

    // run handshake
    while(!server_pipe->handshake_done || !client_pipe->handshake_done) {
        transfer(*client_pipe, server);
        transfer(*server_pipe, client);
    }

    std::cout << "\n=== Sending application data ===\n";

    std::string msg = "hello from client over TLS";
    client.send(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    transfer(*client_pipe, server);

    std::string reply = "hello from server over TLS";
    server.send(reinterpret_cast<const uint8_t*>(reply.data()), reply.size());
    transfer(*server_pipe, client);

    std::cout << "\n=== Closing connection ===\n";
    client.close();
    transfer(*client_pipe, server);

    return 0;
}

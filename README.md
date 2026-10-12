# Botan Cryptography Tutorial

A hands-on C++ tutorial covering cryptography fundamentals using the [Botan](https://github.com/randombit/botan) library.

## Topics Covered

| File | Topic |
|------|-------|
| `01_hashing.cpp` | Hashing — MD5, SHA-1, SHA-256, SHA-512, SHA-3, BLAKE2 |
| `02_aes_gcm.cpp` | Symmetric Encryption — AES-256-GCM (authenticated) |
| `02b_aes_cbc.cpp` | Symmetric Encryption — AES-256-CBC (unauthenticated) |
| `03_asymmetric_keys.cpp` | Asymmetric Key Generation — RSA, EC P-256, Ed25519 |
| `04_rsa_encrypt.cpp` | RSA Encryption/Decryption — OAEP padding |
| `04b_ecdh.cpp` | ECDH Key Exchange — deriving a shared secret |
| `05_signatures.cpp` | Digital Signatures — Ed25519, ECDSA, RSA-PSS |
| `06_certificates.cpp` | X.509 Certificates — CA, CSR, signing, verification |
| `06b_cert_chain.cpp` | Certificate Chains — Root → Intermediate → End Entity |
| `07_tls.cpp` | TLS 1.3 — full handshake, cert verification, encrypted data |

## Requirements

- macOS (Apple Silicon or Intel)
- Xcode Command Line Tools
- Python 3 (for Botan's configure script)

## Setup

**1. Clone the repository with submodules:**
```bash
git clone --recurse-submodules https://github.com/yourusername/BotanTutorial
cd BotanTutorial
```

**2. Build and install Botan from source:**
```bash
make setup
```

This will:
- Configure Botan with debug symbols
- Compile the library (~3-5 minutes)
- Install headers into `include/`
- Install library into `lib/`
- Sign the library for macOS

## Compiling a Lesson

```bash
make 01_hashing
./01_hashing
```

## Compiling All Lessons

```bash
for f in 01_hashing 02_aes_gcm 02b_aes_cbc 03_asymmetric_keys \
          04_rsa_encrypt 04b_ecdh 05_signatures \
          06_certificates 06b_cert_chain 07_tls; do
    make $f && codesign --force --sign - $f
done
```

## Compiling with Debug Symbols (for stepping into Botan source)

```bash
make debug-01_hashing
codesign --force --sign - 01_hashing
./01_hashing
```

Then open the folder in VS Code and press `F5` to debug.

## Note on Code Signing

macOS requires all binaries and dynamic libraries to be signed. After compiling run:

```bash
codesign --force --sign - <binary_name>
```

The `make setup` step handles signing the library automatically.

## Clean

```bash
make clean
```

// Lesson 14 — TOTP (Time-based One-Time Passwords)
// How Google Authenticator, Authy, and every 2FA app works.
// Built on HMAC (lesson 10) + a time counter.
// Header: include/botan-3/botan/otp.h
// Source: botan-src/src/lib/misc/hotp/

#include <botan/otp.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/base32.h>
#include <botan/mac.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <ctime>

int main() {
    Botan::AutoSeeded_RNG rng;

    // -------------------------------------------------------
    // PART 1: The shared secret
    //
    // During 2FA setup, the server generates a random secret
    // and encodes it as a QR code. The authenticator app scans
    // it and stores the secret. Both sides now share the same key.
    // -------------------------------------------------------
    std::cout << "=== Part 1: Shared secret (the QR code) ===\n\n";

    // 20 bytes = 160 bits — standard size for TOTP secrets
    auto secret_bytes = rng.random_vec(20);

    // base32 is how the secret is encoded in QR codes and setup keys
    // e.g. "JBSWY3DPEHPK3PXP" — what you type if you can't scan the QR
    std::string secret_b32 = Botan::base32_encode(secret_bytes);

    std::cout << "Secret (hex)    : " << Botan::hex_encode(secret_bytes) << "\n";
    std::cout << "Secret (base32) : " << secret_b32 << "\n";
    std::cout << "(this is what gets encoded in the QR code)\n\n";

    // -------------------------------------------------------
    // PART 2: How a code is generated
    //
    // RFC 6238 algorithm:
    //   counter = floor(unix_time / 30)    — current 30-second window
    //   hmac    = HMAC-SHA1(secret, counter as 8-byte big-endian)
    //   offset  = hmac[19] & 0x0F          — dynamic truncation
    //   code    = 4 bytes from hmac[offset] with top bit cleared
    //   totp    = code % 1,000,000         — 6 digits
    // -------------------------------------------------------
    std::cout << "=== Part 2: Generating a code ===\n\n";

    Botan::TOTP totp(secret_bytes.data(), secret_bytes.size(), "SHA-1", 6, 30);

    auto now = std::chrono::system_clock::now();
    uint64_t unix_time = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    uint64_t window = unix_time / 30;
    uint32_t code   = totp.generate_totp(unix_time);

    std::cout << "Unix time       : " << unix_time << "\n";
    std::cout << "Time window     : " << window << "  (unix_time / 30)\n";
    std::cout << "Seconds left    : " << (30 - unix_time % 30) << "s until this code expires\n";
    std::cout << "TOTP code       : " << std::setw(6) << std::setfill('0') << code << "\n\n";

    // -------------------------------------------------------
    // PART 3: Verification
    //
    // The server does the same computation and compares.
    // clock_drift_accepted=1 means also accept the previous
    // and next window — handles slight clock skew between devices.
    // -------------------------------------------------------
    std::cout << "=== Part 3: Verification ===\n\n";

    bool valid = totp.verify_totp(code, now, 1);
    std::cout << "Correct code '" << std::setw(6) << std::setfill('0') << code
              << "' verified : " << (valid ? "YES" : "NO") << "\n";

    bool invalid = totp.verify_totp(123456, now, 1);
    std::cout << "Wrong code  '123456'       verified : " << (invalid ? "YES" : "NO") << "\n\n";

    // -------------------------------------------------------
    // PART 4: Adjacent windows (clock drift tolerance)
    //
    // Your phone and the server clocks may be slightly out of sync.
    // Servers typically accept the previous and next 30s window.
    // -------------------------------------------------------
    std::cout << "=== Part 4: Clock drift tolerance ===\n\n";

    uint32_t prev_code = totp.generate_totp(unix_time - 30);
    uint32_t curr_code = totp.generate_totp(unix_time);
    uint32_t next_code = totp.generate_totp(unix_time + 30); // doesnt work with botan

    std::cout << "Previous window code : " << std::setw(6) << std::setfill('0') << prev_code << "\n";
    std::cout << "Current window code  : " << std::setw(6) << std::setfill('0') << curr_code << "\n";
    std::cout << "Next window code     : " << std::setw(6) << std::setfill('0') << next_code << "\n\n";

    // verify current code with drift=1 — accepts prev, curr, and next
    std::cout << "Verify prev with drift=1 : "
              << (totp.verify_totp(prev_code, now, 1) ? "accepted" : "rejected") << "\n";
    std::cout << "Verify curr with drift=1 : "
              << (totp.verify_totp(curr_code, now, 1) ? "accepted" : "rejected") << "\n";
    std::cout << "Verify next with drift=1 : "
              << (totp.verify_totp(next_code, now, 1) ? "accepted" : "rejected") << "\n\n";

    // -------------------------------------------------------
    // PART 5: Wrong secret — different codes entirely
    //
    // An attacker without the secret cannot generate valid codes.
    // Even with the algorithm, you still need the shared secret.
    // -------------------------------------------------------
    std::cout << "=== Part 5: Wrong secret produces wrong codes ===\n\n";

    auto wrong_secret = rng.random_vec(20);
    Botan::TOTP wrong_totp(wrong_secret.data(), wrong_secret.size(), "SHA-1", 6, 30);

    uint32_t wrong_code = wrong_totp.generate_totp(unix_time);

    std::cout << "Correct secret code : " << std::setw(6) << std::setfill('0') << curr_code  << "\n";
    std::cout << "Wrong secret code   : " << std::setw(6) << std::setfill('0') << wrong_code << "\n";
    std::cout << "Match               : " << (curr_code == wrong_code ? "YES (collision)" : "NO") << "\n\n";

    std::cout << "Verify wrong secret's code against correct totp : "
              << (totp.verify_totp(wrong_code, now, 1) ? "accepted (collision)" : "rejected") << "\n\n";

    // -------------------------------------------------------
    // PART 6: Why TOTP beats static passwords
    // -------------------------------------------------------
    std::cout << "=== Part 6: Security properties ===\n\n";
    std::cout << "Time-limited   — codes expire after 30 seconds\n";
    std::cout << "One-time       — a captured code cannot be reused after its window\n";
    std::cout << "Offline        — phone generates codes with no network needed\n";
    std::cout << "No PKI needed  — just a shared secret, no certificates\n";
    std::cout << "Phishing risk  — TOTP can still be phished in real time (use passkeys to eliminate this)\n";

    return 0;
}

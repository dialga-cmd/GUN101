# GUN-101 Security Design

## Overview

GUN-101 is a file encryption tool that provides confidentiality and integrity through AES-256-GCM authenticated encryption, with key material derived via Argon2id from a user password and optional keyfile. The library enforces a strong password policy to resist brute-force attacks.

## Cryptographic Primitives

### Argon2id for Key Derivation

**Why Argon2id?**
- Winner of the Password Hashing Competition (2015)
- Memory-hard: resists GPU/ASIC attacks by requiring large amounts of memory
- Data-independent memory access: resists side-channel timing attacks
- Recommended by OWASP and NIST SP 800-63B

**Parameters:**
- Time cost: 4 iterations
- Memory cost: 256 MiB (262144 KiB)
- Parallelism: 4 lanes
- Hash length: 32 bytes (256 bits)
- Salt length: 32 bytes

These parameters provide a balance between security and usability on modern hardware. They are chosen to be from the defensive side: making attacks expensive while keeping legitimate use reasonably fast.

### AES-256-GCM for Encryption

**Why AES-GCM?**
- Provides authenticated encryption: both confidentiality and integrity in one operation
- Eliminates padding oracle vulnerabilities present in CBC mode
- Standardized by NIST SP 800-38D
- Widely supported and vetted

**Parameters:**
- Key length: 32 bytes (256 bits)
- Nonce length: 12 bytes (96 bits) - recommended for GCM
- Authentication tag: 16 bytes (128 bits)

## Keyfile Two-Factor Protection

When a keyfile is used:
- The encryption key is derived from both the password and the keyfile contents
- The keyfile must be present to decrypt the file
- The keyfile should be stored on a separate device (e.g., USB drive) from the encrypted file
- This provides true two-factor protection: something you know (password) and something you have (keyfile)

**Important:** If the keyfile is stored with the encrypted file, an attacker who steals both gains no additional protection beyond the password strength.

## Memory Wiping

The library does **not** wipe keys from memory. Python's immutable  objects cannot be securely zeroed: the old  idiom only rebound the name without touching the original allocation, so it was removed. The  helper () performs  to drop the reference, but the underlying memory is reclaimed by CPython's garbage collector at an unspecified time.

**Residual risk:** an attacker with process memory access (e.g., via  or a core dump) may recover key material after decryption. This is accepted as part of the threat model (see docs/THREAT_MODEL.md — hardware/physical compromise is out of scope). A mitigation requiring mutable buffers (e.g.,  with ) is possible but out of scope for the current design.

## What This Mode Protects Against

1. **Passive attackers** who obtain the encrypted file but lack the password (and keyfile, if used) cannot decrypt due to the strength of AES-256-GCM and Argon2id.
2. **Container integrity**: Any modification to the encrypted container (including ciphertext, nonce, tag, or header fields) is detected and rejected before returning plaintext, thanks to GCM authentication. The header fields (protocol, version, etc.) are authenticated as associated data in the v2.1 format.
3. **Two-factor protection** (when keyfile stored separately): An attacker who knows the password but does not have the keyfile cannot decrypt.
4. **Constant-time keyfile comparison**: Keyfile fingerprints are compared using `hmac.compare_digest` to prevent timing attacks that could leak information about the keyfile.

## What This Mode Does NOT Protect Against

1. **Malware on the encryption/decryption machine**: Keyloggers, memory scrapers, or other malware can capture passwords or keys during use.
2. **Weak passwords**: The library enforces a minimum password length of 10 characters requiring uppercase, lowercase, digit, and special character to resist brute-force attacks. However, users should still choose sufficiently strong passwords.
3. **Keyfile compromise**: If an attacker obtains both the encrypted file and the keyfile, security reduces to password strength only.
4. **Side-channel attacks**: While Argon2id resists many side-channels, implementation in Python may leak timing information.
5. **Future cryptographic breaks**: If AES-256-GCM or Argon2id is broken, this construction would be affected.

## Implementation Notes

- All cryptographic primitives are implemented via well-vetted libraries: `argon2-cffi` and `cryptography`.
- Nonces are generated randomly using `os.urandom()` for each encryption.
- The protocol includes versioning to allow for future updates.
- Error messages are generic to avoid leaking information about what failed.

## Environment Variable Trade-off

The `GUN101_PASSWORD` environment variable provides convenience for automation and scripting, but it carries security risks:
- Environment variables are visible to other processes running as the same user via `/proc/<pid>/environ`
- They can be inherited by child processes
- They may leak into CI/CD logs, crash dumps, or shell history
- Unlike interactive prompts, they cannot be prevented from appearing in process listings

For maximum security, use interactive password entry. The environment variable option is provided as a convenience/trade-off for trusted automation scenarios where these risks are understood and mitigated.
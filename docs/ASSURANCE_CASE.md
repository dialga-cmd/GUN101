# GUN-101 Assurance Case

This document is the assurance case for GUN-101: a structured argument that its
security requirements are met. It collects the threat model, identifies trust
boundaries, argues that secure design principles have been applied, and argues
that common implementation security weaknesses have been countered.

The three authoritative companion documents are:

- [docs/THREAT_MODEL.md](THREAT_MODEL.md) — the full threat model
- [docs/SECURITY.md](SECURITY.md) — the security design and cryptographic construction
- [docs/ARCHITECTURE.md](ARCHITECTURE.md) — the architecture

## 1. Security requirements

Derived from the project's purpose and the threat model, the security
requirements are:

1. **Confidentiality:** a passive attacker who obtains an encrypted file but
   lacks the password (and keyfile, if used) cannot recover the plaintext.
2. **Integrity:** any tampering with an encrypted container is detected and
   rejected before plaintext is returned.
3. **Authentication (two factors):** with a keyfile stored separately,
   possession of the password alone is insufficient to decrypt.
4. **Brute-force resistance:** guessing the password must be expensive for
   attackers (memory-hard key derivation).
5. **Non-leakage:** failures must not reveal which check failed (no oracle
   signals), and timing of secret comparisons must be neutralized.

## 2. Threat model and trust boundaries

The full threat model is in [docs/THREAT_MODEL.md](THREAT_MODEL.md). In summary:

**Threats addressed:** passive attackers with the encrypted file; active
(tampering) attackers; attackers who know the password but lack a keyfile;
offline brute-force/dictionary attack on weak passwords; side-channel timing on
keyfile comparison.

**Threats out of scope (explicitly documented, not "missed"):** malware on the
encrypt/decrypt machine, end-user device compromise, rubber-hose coercion,
temp-file/swap leakage, denial of service via unlimited password attempts, and
future cryptanalytic breaks of AES-256-GCM or Argon2id.

**Trust boundaries.** The primary trust boundary is the process boundary of the
machine running `gun101`:

- **Trusted side (inside):** the running Python process, the user-supplied
  password input path, and the keyfile file (in two-factor mode). Code and
  dependencies within the tool are trusted; they come only from the audited
  `cryptography` and `argon2-cffi` libraries.
- **Untrusted side (outside):** any `.gun101` container file, the filesystem path
  arguments to the CLI, and the environment in which encrypted files may be
  stored or transmitted. Every byte of the container and every CLI path
  argument is treated as attacker-controlled.
- **Data crossing the boundary:** only the encrypted container and validated
  path arguments. The boundary is crossed only by code that validates inputs
  (see section 4).

## 3. Argument: secure design principles applied

The implementation follows the secure design principles enumerated from
`know_secure_design` ["Implement secure design"](https://www.bestpractices.coreinfrastructure.org/):

1. **Principle of least privilege.** Keyfiles are written with mode `0600`
   (owner-only). The tool writes only to the paths the user requested and never
   outside the working directory (`safe_open_write` in `cli.py`/`keyfile.py`).
2. **Defense in depth.** Two independent factors (password + keyfile) must
   combine by default when a keyfile is present; even with the keyfile-derived
   material, the derived key still requires the password. Legacy `v2.0`
   containers are handled separately and validated.
3. **Fail securely.** Every cryptographic failure produces the generic
   `"Decryption failed"` error. In the **CLI** path, plaintext is staged
   to a temporary file and atomically moved only after GCM tag verification
   succeeds (see `docs/CLI.md` — Memory Footprint section). In the **library**
   API (`handler.decrypt_stream()`), plaintext chunks are written to
   `out_stream` before `finalize()` verifies the GCM tag; callers using the
   library API directly must handle partial output themselves (the function's
   docstring warns about this). Failure modes are indistinguishable by design
   (see section 4, C1).
4. **Economy of mechanism / small attack surface.** The dependency set is
   deliberately minimal (two well-known crypto libraries), all cryptography is
   delegated to them, and no networking or key-exchange functionality exists.
5. **Open design.** All constants, parameters, formats, and failure behavior are
   publicly documented (`docs/SECURITY.md`, `docs/CLI.md`, `docs/ARCHITECTURE.md`).
6. **Secure randomness by default.** Salts, nonces, and keyfiles are all
   generated with `os.urandom()` — there is no configurable insecure fallback.
7. **Future-proofing (algorithm agility).** The container format is versioned
   (`protocol`, `version` fields) and new encryptions are written with the
   current version while older versions remain decryptable, so a future
   algorithm change does not strand existing files.

## 4. Argument: common implementation weaknesses countered

This table maps common software-security weakness classes to the specific
countermeasures in the code, satisfying `know_common_errors`.

| Weakness class | Countermeasure in GUN-101 |
|----------------|---------------------------|
| C1. Oracle/error-information leakage | All cryptographic failures raise a single generic `ValueError("Decryption failed")` (`handler.py`, `cipher.py`); CLI prints generic messages. No distinguisher for wrong password vs. wrong keyfile vs. tampered container exists. |
| C2. Timing attacks on secret comparison | Keyfile fingerprints are compared with `hmac.compare_digest` (constant time) (`handler.py`); no `==`/`!=` on secrets. |
| C3. Insecure randomness | Salts, nonces, keyfiles from `os.urandom()` only (`handler.py`, `keyfile.py`); the CSPRNG comes from the operating system. |
| C4. Use of weak cryptographic primitives/modes | Only AES-256-GCM (NIST SP 800-38D) and Argon2id (PHC winner) are used by default; no MD4/MD5/DES/RC4/ECB/CBC. SHA-256 is used only for keyfile fingerprint identification, never as a security mechanism. |
| C5. Weak key derivation | Argon2id with time 4, memory 256 MiB, parallelism 4, 32-byte keys and 32-byte per-file salts (`config.py`). |
| C6. Path traversal / symlink attacks on output | Output paths are rejected if they are symlinks or resolve outside the working directory, before any write occurs (`cli.py`, `keyfile.py`). |
| C7. Unvalidated input | Every external input is validated (allowlisted): file bytes type, password policy, keyfile length, salt/nonce/key lengths in `cipher.py`/`kdf.py`, container `protocol`/`version` allowlist and base64 fields in `handler.py`. |
| C8. Missing integrity of metadata | Container header fields are bound into AES-GCM associated data (v2.1), so tampering with the header cannot go undetected (`handler.py`). |
| C9. Insecure dependency surface | Only two direct dependencies, `argon2-cffi` and `cryptography`; all direct and transitive versions are pinned with hashes in `requirements.lock`; automated `pip-audit` scans the pinned lockfile for known vulnerable dependencies in CI. |
| C10. Unreviewed code paths / regressions | Mandatory tests (positive + negative) for all security-affecting functions, run in CI on every change (`CONTRIBUTING.md`, `.github/workflows/ci.yml`); static analysis with bandit. |

## 5. Argument validity and limits

The argument above holds **only** within the documented trust boundary: a
trusted execution environment and, in two-factor mode, a physically separate
keyfile. Threats outside that boundary (documented in section 2) are accepted
residual risks, not unaddressed vulnerabilities.

In common with the rest of the ecosystem, this case is vulnerable to future
cryptanalytic progress; the versioned container format is the mitigation that
allows migrating to a stronger construction without re-encrypting the universe.

## 6. Maintenance of this assurance case

- Reviewed and updated whenever the cryptographic construction, container
  format, or threat model changes.
- The companion documents are updated in the same change that updates the
  threat model, so this case cannot silently drift from the implementation.

_Last reviewed: 2026-09-08 (alongside the 2.1 security review baseline)._
_Assurance claim: GUN-101 meets its five stated security requirements
(confidentiality, integrity, two-factor authentication, brute-force
resistance, and non-leakage) within its documented trust boundary._
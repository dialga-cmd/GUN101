# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.3] - 2026-11-26

### Fixed

- **Streaming decrypt rejects unauthenticated trailing metadata.** Fields after
  `ciphertext` other than the canonical `tag` were parsed but never covered by
  the AES-GCM associated data, so `decrypt_stream()` accepted containers that
  `decrypt_file()` rejected. They are now rejected with the generic
  `Decryption failed` error (#41).
- **Truncated streaming ciphertext no longer hangs the parser.** A container
  ending inside the base64 `ciphertext` with 1–3 characters buffered and no
  closing quote caused an infinite loop at 100% CPU. EOF now fails fast (#60).
- **`safe_open_write()` cleans up its placeholder on validation failure.** A
  failed post-open check left a zero-byte file at the destination, blocking
  retries. The newly created file is now unlinked, with an inode check to avoid
  deleting a concurrent replacement (#56).

## [2.2.2] - 2026-10-22

### Fixed

- **`encrypt` refuses to overwrite its own input.** If `--output` referred to
  the input file — directly, through a symlink, or through a hard link —
  encryption could truncate the plaintext before reading it. The CLI now
  compares the opened input file with the resolved output path and aborts
  before any write (#35).
- **`encrypt` publishes the container atomically.** The destination used to be
  opened and truncated before the container was written, and the error path
  then unlinked it, so a failed encryption destroyed a pre-existing output. The
  container is now streamed into an `O_EXCL` staging file with mode `0600` in
  the destination directory and published with a single `os.replace()` only
  after encryption succeeds. On failure, only the staging file and any
  destination reservation are removed (#36).
- **`--force` still enforces output path safety.** Because the force path now
  publishes via `os.replace()` instead of `safe_open_write()`, the CLI calls
  `validate_safe_path()` explicitly, so directory escapes and output symlinks
  remain rejected.

## [2.2.1] - 2026-10-22

### Fixed

- **`decrypt` applies the output mode before publishing the plaintext.** The
  `0600` re-assertion ran after `os.replace()`. If it failed, cleanup removed
  the decrypted output in the default path but left it behind with `--force`.
  The `chmod` now runs on the staging file before publication, so a failure
  aborts while plaintext is still confined to the temporary file and cleanup
  behaves identically in both modes.
- **`requirements.lock` resolves and audits cleanly.** The lock omitted the
  transitive `cffi` and `pycparser` pins, so both
  `pip install --require-hashes -r requirements.lock` and
  `pip-audit -r requirements.lock` failed. All direct and transitive
  dependencies are now pinned with SHA-256 hashes for every published artifact,
  refreshed to the currently resolved versions (`cryptography==50.0.2`,
  `argon2-cffi-bindings==26.1.0`, `cffi==2.1.1`, `pycparser==3.11`, and
  `typing-extensions==4.16.0`, which is conditionally required on
  Python < 3.11).

### Changed

- The CI dependency audit now runs against `requirements.lock`, so the audited
  versions are the same fully pinned set that is documented for users.
- Documentation now states that `handler.decrypt_stream()` writes plaintext
  before the GCM tag is verified and that callers must not expose its output
  until it returns successfully; the CLI's staging file is called out as the
  reference implementation. The canonical metadata-before-ciphertext field
  order required for v2.1 AAD reconstruction is also documented.

## [2.2.0] - 2026-09-28

### Security

- **Decrypted plaintext is no longer written world-readable.** `decrypt` staged
  plaintext with `open(path, 'wb')`, so the staging file inherited the process
  umask (typically `0644`) and `os.replace` carried that mode onto the finished
  output. Every local user could therefore read decrypted secrets, even though
  the container and the keyfile were correctly `0600`. In the non-`--force` path
  this also silently discarded the `0600` that `safe_open_write` had just
  applied. The staging file is now created with `O_CREAT | O_EXCL` and mode
  `0600`, and the mode is re-asserted after the atomic replace.
- `decrypt_file` no longer leaks a failure oracle. A malformed salt escaped the
  generic error handling as `"Salt must be 32 bytes"`, because `kdf.derive_key`
  is called outside the surrounding `try`. That let an attacker distinguish a
  corrupt container from a wrong password — reopening the oracle the 2.1.0
  generic-error policy was introduced to close. Salt, nonce and tag lengths are
  now validated before key derivation, matching `decrypt_stream`.
- Windows keyfiles are no longer briefly exposed. `icacls` was invoked *after*
  the secret bytes were written, leaving a window in which the keyfile was
  readable under the inherited directory ACL. ACLs are now applied before any
  key material is written, and an insecure keyfile is removed if that fails.
- `_same_file()` no longer fails open. It returned `True` when `st_ino` was `0`,
  which the symlink/TOCTOU checks interpret as "the path is unmodified"; on a
  filesystem reporting `st_ino == 0` that silently disabled the protection. It
  now fails closed. `st_ino` is populated on Linux, macOS and Windows, so
  normal operation is unaffected.

### Added

- Bounded-memory streaming encryption and decryption for large files
  (`encrypt_stream` / `decrypt_stream`, chunked AES-GCM via `StreamEncryptor`
  and `StreamDecryptor`, plus an incremental JSON container parser). Memory use
  is now independent of input size.
- Output-overwrite protection: `encrypt` and `decrypt` now refuse to clobber an
  existing output file. Pass `-f` / `--force` to overwrite.
- Password policy is now defined in a single place (`config.py`) and consumed
  from there, replacing duplicated literals.

### Changed

- `safe_open_write` was extracted into a shared internal helper
  (`_util.safe_open_write`) used by both the CLI and keyfile generation, and its
  path-containment checks were hardened against TOCTOU symlink races.
- Keyfile permissions are now enforced on Windows via `icacls` (NTFS ACLs) in
  addition to the existing POSIX `chmod`.
- The minimum pytest version required for development was bumped.

### Fixed

- Removed a misleading "key wipe" in the encrypt/decrypt paths. The previous
  `key = bytes(config.AES_KEY_LEN)` idiom only rebound the local name — `bytes`
  is immutable, so it allocated a fresh zero-filled object and left the original
  key bytes in the heap while the comment claimed to overwrite them. The code
  now documents the actual limitation rather than asserting a guarantee it
  cannot provide.

## [2.1.3] - 2026-09-10

### Fixed

- Remove password policy validation from `decrypt_file()` to allow
  containers created with older/shorter passwords to be decrypted.
  Encryption still enforces the current policy; decryption relies on
  AES-GCM authentication to verify password correctness. (Closes #4)
- Harden path traversal checks in `safe_open_write()` for case-insensitive
  filesystems (NTFS, default APFS) by folding case before the
  `commonpath` containment check. (Closes #9)

### Changed

- Expand CI matrix from Ubuntu-only to Ubuntu, macOS, and Windows across
  Python 3.10, 3.11, and 3.12.

### Added

- Regression tests for legacy password decryption and incorrect password
  failure behavior.
- Tests for case-insensitive filesystem detection and escape rejection.

## [2.1.2] - 2026-09-09

### Fixed

- Normalized path-containment checks in `cli.safe_open_write()` and
  `keyfile.safe_open_write()` using `os.path.normcase()` so paths differing
  only by letter case are handled consistently on case-insensitive
  filesystems (Windows/macOS), and cross-drive escape attempts are correctly
  rejected as "Output path attempts to escape the intended directory".

## [2.1.1] - 2026-09-09

### Added

- Hypothesis-based property fuzz tests for the container parser in
  `tests/test_fuzz_parser.py`.
- Argon2id cost benchmark script `scripts/benchmark_kdf.py` for measuring
  key-derivation performance across memory/time/parallelism configurations.
- Full external-interface reference documentation for the CLI in
  `docs/CLI.md` (all commands, inputs, outputs, environment variables, exit
  codes, and the container file format).
- README section on how to report bugs and contribute.

### Changed

- Hardened `decrypt_file` container parsing against malformed inputs: rejects
  non-dict JSON roots and non-string keyfile fingerprints instead of leaking
  unexpected `TypeError`s, and catches `TypeError` during base64 decoding so all
  failures consistently raise the generic `ValueError("Decryption failed")`.

`pyproject.toml` version will be bumped when a release is cut from these
changes. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute.

## [2.1.0] - 2026-08-09

### Added

- Authenticated container format (v2.1): protocol and version header fields are
  now bound into AES-GCM associated data, preventing undetected tampering with
  these fields. Fully backward-compatible — existing v2.0 encrypted files still
  decrypt normally.
- Constant-time keyfile fingerprint comparison using `hmac.compare_digest` to
  prevent timing attacks.
- Path traversal and symlink protection on all file writes via a new
  `safe_open_write()` helper function.
- Pinned dependency lockfile with independently-verified hashes for
  reproducible installs (`requirements.lock`).

### Changed

- Increased Argon2id memory cost to 256 MiB per current OWASP guidance for
  high-security applications (`ARGON2_MEMORY_COST = 262144` KiB).
- Password no longer accepted as a CLI argument — interactive prompt or
  `GUN101_PASSWORD` environment variable only (to avoid exposure via process
  listings or shell history).
- Updated dependency floors in `pyproject.toml` remain compatible; lockfile now
  pins to latest stable versions (`argon2-cffi==25.1.0`,
  `cryptography==50.0.0`).

### Fixed

- v2.0 containers stored the protocol and version header fields as
  unauthenticated JSON fields that could be silently edited; v2.1 binds them
  into AES-GCM associated data so any such tampering is detected and rejected.
- Keyfile fingerprints were previously compared with plain equality, which is
  vulnerable to timing attacks; they are now compared with
  `hmac.compare_digest`.

### Security

- Error messages are now generic ("Decryption failed") so a failure cannot be
  attributed to a wrong password, a wrong keyfile, or a corrupted container —
  preventing oracle-based probing.
- All cryptographic operations now authenticate associated data (header
  fields) in AES-GCM.

This project follows Semantic Versioning (semver.org).
# GUN-101 Command-Line Reference

This document is the reference for the external interface of the `gun101`
command: its inputs (arguments, options, environment variables, files) and its
outputs (files written, standard output, standard error, exit codes, and the
encrypted container format).

## Synopsis

```
gun101 encrypt <file> [--keyfile <path>] [--output <path>] [-f|--force]
gun101 decrypt <file> [--keyfile <path>] [--output <path>] [-f|--force]
gun101 generate-keyfile <path>
gun101 keyfile-fingerprint <path>
gun101 info
gun101 --help
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Any error: bad input, weak password, wrong/missing keyfile, tampered container, or I/O failure |

On success, informational messages are printed to **standard output**. On
failure, an error message is printed to **standard error** and the process
exits with code `1`.

## Environment Variables

### `GUN101_PASSWORD`

When set, its value is used as the password for `encrypt` and `decrypt`
instead of prompting interactively. A warning is printed to standard error,
because passing passwords via environment variables is less secure than an
interactive prompt. If unset, the tool prompts with `Password: ` on the
controlling terminal and does not echo input.

## Password Policy

Applies to both `encrypt` and `decrypt`. The password must be a string that:

- is at least **10 characters** long;
- contains at least one **uppercase** letter;
- contains at least one **lowercase** letter;
- contains at least one **digit**;
- contains at least one **special character** (from `string.punctuation`).

If the password does not meet the policy, `encrypt` fails with an explanatory
message. `decrypt` also validates the policy before attempting decryption so
the two commands cannot diverge.

## Commands

### `gun101 encrypt <file> [--keyfile <path>] [--output <path>] [-f|--force]`

**Inputs**

- `file` (positional, required): path to the plaintext file to encrypt.
- `--keyfile` (optional): path to a 32-byte keyfile for two-factor mode. When
  provided, the derived key depends on both the password and the keyfile bytes.
- `--output` (optional): path to write the encrypted container. Defaults to
  `<file>.gun101`.
- `-f`, `--force` (optional): overwrite output file if it already exists.

**Outputs**

- Writes the encrypted container to `--output` (or `<file>.gun101`).
- Prints `Encrypted file written to: <path>` to standard output.

**Failure modes**

- Cannot read `file` → `Error reading file: ...` on stderr, exit `1`.
- Weak password or invalid keyfile → `Error: ...` on stderr, exit `1`.
- Output path is a symlink or escapes the working directory → refused, exit `1`.
- Output path already exists and `--force` is not specified → refused, exit `1`.
- Cannot write output → `Error writing output file: ...` on stderr, exit `1`.

### `gun101 decrypt <file> [--keyfile <path>] [--output <path>] [-f|--force]`

**Inputs**

- `file` (positional, required): path to the encrypted container.
- `--keyfile` (optional): path to the keyfile. Required if the container was
  created with two-factor mode and declares `keyfile_required: true`.
- `--output` (optional): path to write the plaintext. Defaults to stripping the
  `.gun101` suffix, or appending `.decrypted` if the input does not end in
  `.gun101`.
- `-f`, `--force` (optional): overwrite output file if it already exists.

**Outputs**

- Writes the decrypted plaintext to `--output` (or the default derived path).
- Prints `Decrypted file written to: <path>` to standard output.

**Failure modes**

- Wrong password, wrong/missing keyfile, or any tampering with the container
  → a single generic message `Error: Decryption failed` on stderr, exit `1`.
  The tool deliberately does not reveal which check failed (this prevents
  oracle attacks). The container header, key file fingerprint mismatch, and
  GCM tag verification all produce this same message.
- Cannot read `file` → `Error reading file: ...` on stderr, exit `1`.
- Output path is a symlink or escapes the working directory → refused, exit `1`.
- Output path already exists and `--force` is not specified → refused, exit `1`.

### `gun101 generate-keyfile <path>`

**Inputs**

- `path` (positional, required): destination path for the new keyfile.

**Outputs**

- Creates a 32-byte cryptographically random file at `path` with permissions
  `0600` (owner read/write only).
- Prints the path and the SHA-256 fingerprint to standard output:
  ```
  Keyfile generated at: <path>
  Fingerprint (SHA-256): <64 hex characters>
  ```

**Failure modes**

- File already exists at `path` → error on stderr, exit `1` (existing files
  are never overwritten).
- Unsafe path (symlink / escapes working directory) or I/O failure → error on
  stderr, exit `1`.

### `gun101 keyfile-fingerprint <path>`

**Inputs**

- `path` (positional, required): path to an existing keyfile.

**Outputs**

- Prints the SHA-256 fingerprint to standard output:

  ```
  Fingerprint (SHA-256): <64 hex characters>
  ```

**Failure modes**

- Keyfile not found or not exactly 32 bytes → error on stderr, exit `1`.

### `gun101 info`

**Inputs**

- None (takes no arguments).

**Outputs**

- Prints configuration constants, KDF parameters, installed dependency versions, and password policy information to standard output as `key=value` lines.

**Failure modes**

- None (always succeeds and exits `0`).

## File Formats

### Keyfile

A bare 32-byte file of cryptographically random bytes. There is no header or
metadata. Its only verifiable property is the SHA-256 fingerprint.

### Encrypted container (`.gun101`)

A UTF-8 JSON object. The cleartext header fields are:

| Field                  | Type     | Description                                            |
|------------------------|----------|--------------------------------------------------------|
| `protocol`             | string   | Always `"GUN-101"`. Rejects files from other tools.    |
| `version`              | string   | `"2.1"` for new files; `"2.0"` (legacy) is decrypted.  |
| `keyfile_required`     | boolean  | True if two-factor mode was used.                      |
| `keyfile_fingerprint`  | string?  | SHA-256 fingerprint of the keyfile, or `null`.         |
| `salt`                 | string   | Base64 Argon2id salt (32 bytes).                       |
| `nonce`                | string   | Base64 AES-GCM nonce (12 bytes).                       |
| `ciphertext`           | string   | Base64 AES-256-GCM ciphertext.                         |
| `tag`                  | string   | Base64 GCM authentication tag (16 bytes).              |

For `version: "2.1"`, the header fields (excluding `ciphertext` and `tag`)
are serialized compactly with sorted keys and used as GCM associated data, so
any header tampering invalidates the authentication tag. For `version: "2.0"`,
the ciphertext was encrypted without associated data; this format is supported
for backward compatibility only.

## Library Interface

The `gun101` Python package exposes the same operations programmatically:

- `gun101.handler.encrypt_file(file_data: bytes, password: str, keyfile_path: str = None) -> bytes`
  — encrypt and return the container bytes.
- `gun101.handler.decrypt_file(container_data: bytes, password: str, keyfile_path: str = None) -> bytes`
  — decrypt and return the plaintext bytes. Raises `ValueError("Decryption failed")`
  for any failure.
- `gun101.handler.validate_password(password: str) -> None`
  — validate the password policy; raises `ValueError` on failure.
- `gun101.keyfile.generate_keyfile(path: str) -> None`
  — create a keyfile at `path`.
- `gun101.keyfile.keyfile_fingerprint(keyfile_bytes: bytes) -> str`
  — return the SHA-256 fingerprint of keyfile bytes.
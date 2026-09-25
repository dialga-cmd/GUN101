# Contributing to GUN-101

First off — thank you for taking the time to contribute. GUN-101 is a small,
security-focused project and every careful contribution makes it stronger.

This guide explains how the project works and how to get your changes merged
safely. It is written for both first-time open source contributors and
experienced cryptographers. If anything here is unclear, open a discussion
issue or email the maintainer at **adityaraj1234@duck.com**.

## A note about security

This is a cryptographic library. Incorrect code in an encryption tool is not a
minor bug — it is a liability for every person who relies on it. That is why
this guide contains explicit rules about what kinds of changes need extra
scrutiny. Please read the security sections before touching anything in the
key-derivation, encryption, or decryption paths.

The authoritative security documents are:

- [Security Design](docs/SECURITY.md) — the cryptographic construction and its guarantees
- [Threat Model](docs/THREAT_MODEL.md) — threat actors, mitigations, and what is out of scope
- [Security Policy](SECURITY.md) — how to report vulnerabilities

## What kinds of contributions are needed

GUN-101 is used and this is a good time to build it out. Useful contributions
include any of the following:

- **Bug fixes** — anything that makes encrypt/decrypt behave incorrectly or crash unexpectedly.
- **New features** — new CLI subcommands, platform support, quality-of-life improvements.
- **Security improvements** — hardening, better error handling, reducing side channels, documentation of attack surfaces.
- **Tests** — positive and negative tests for existing behaviour; property-style tests for the cryptographic invariants.
- **Documentation** — clearer READMEs, better docstrings, worked examples, translations of design reasoning.
- **Platform support** — Windows or macOS support for file permissions, path handling, and shell behaviour.
- **Performance** — a faster hot path, so long as it never weakens the cryptographic guarantees.

## Good first issues

Issues labelled **`good first issue`** in the [issue tracker](https://github.com/dialga-cmd/gun101/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
are small, well-scoped tasks intended for new or casual contributors. Each one
links to the code to touch and the tests to extend. Examples that have been
sized to fit a single PR:

- **Windows file-permission support** — keyfile permissions are not enforced
  on Windows/NTFS in the same way as POSIX systems; tracked in
  [#8](https://github.com/dialga-cmd/GUN101/issues/8), see
  [ROADMAP.md](ROADMAP.md).
- **Deduplication of `safe_open_write()`** — consolidate the duplicate
  implementations in `src/gun101/cli.py` and `src/gun101/keyfile.py` into a
  shared internal helper.

If you want to work on one of these (or propose your own small task), say so in
a comment on the issue before opening a PR so work is not duplicated.

Everything you contribute must match the project's design philosophy: simple,
transparent, and correct. We prefer a boring, well-understood implementation
over a clever one.

## Prerequisites

- **Python 3.10 or newer** (the package declares `requires-python = ">=3.10"`).
- **pip** with support for editable installs.
- **git** and a [GitHub](https://github.com) account.
- No existing cryptography background required for most tasks — but please read
  [docs/SECURITY.md](docs/SECURITY.md) before starting.

The runtime dependencies are deliberately small and well-audited:

- `argon2-cffi >= 23.1.0` — Argon2id key derivation
- `cryptography >= 42.0.2` — AES-256-GCM, HMAC, SHA-256

Dev dependencies are `pytest >= 7.0.0` and `pytest-cov >= 4.0.0` (see the `[dev]`
extra in `pyproject.toml`).

## Setting up the project

### 1. Fork the repository

Click **Fork** at [github.com/dialga-cmd/gun101](https://github.com/dialga-cmd/gun101)
to create a copy under your own account.

### 2. Clone your fork

```bash
git clone https://github.com/<your-username>/gun101.git
cd gun101
```

Add the original repository as an upstream remote so you can pull in changes
later:

```bash
git remote add upstream https://github.com/dialga-cmd/gun101.git
```

### 3. Install in editable mode with dev dependencies

It is recommended to work inside a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate   # on Windows: .venv\Scripts\activate
```

Then install the package in editable mode together with the dev dependencies:

```bash
pip install -e ".[dev]"
```

This makes the `gun101` console command available and lets you import the
library directly from `src/`.

> The project uses a **src layout** (`src/gun101/`). All library code lives
> there; tests live in `tests/` and import the package as `gun101` (not
> `src.gun101`).

## Running the test suite

Run the full suite from the repository root:

```bash
pytest tests/ -v
```

A passing run looks like this (the exact count may grow as tests are added):

```
.....................................................                    [100%]
53 passed in 47.85s
```

The suite is run under `pytest-cov`: statement coverage of the `gun101` package
is **required to stay at 80% or above**, otherwise `pytest` exits non-zero (see
`[tool.pytest.ini_options]` in `pyproject.toml`). Run the suite with coverage
explicitly if you want to see the per-module breakdown:

```bash
pytest --cov-report=term-missing
```

Every test must pass before any PR is merged. If you are changing something in
the key-derivation, encryption, or decryption paths, `pytest tests/ -v` passing
is necessary but not sufficient — your PR description must also carry the
cryptographic justification described below.

The suite covers correctness, tamper detection, password policy, keyfile
handling, Argon2id/AES parameter assertions, and CLI behaviour. There is no
fuzzing harness yet — a good-first-issue for fuzzing would be welcome.

## Coding standards

These are enforced by the maintainer during review:

- **Type hints are required** on all public functions and methods, in every
  module under `src/gun101/`. The existing code consistently annotates
  parameters and return values (e.g. `derive_key(password: str, salt: bytes, keyfile_bytes: bytes = None) -> bytes`).
- **Docstrings are required for all public functions** explaining what the
  function does and when it raises. Internal helpers should be documented where
  their behaviour is non-obvious.
- **Never reduce the Argon2id or AES parameters.** The current parameters are
  non-negotiable in this project:
  - `ARGON2_TIME_COST = 4`
  - `ARGON2_MEMORY_COST = 262144` (256 MiB in KiB)
  - `ARGON2_PARALLELISM = 4`
  - `ARGON2_HASH_LEN = 32`, `ARGON2_SALT_LEN = 32`
  - `AES_KEY_LEN = 32`, `AES_NONCE_LEN = 12`
  - `KEYFILE_LEN = 32`

  Reducing any of these weakens every file encrypted with the library. Any
  proposal to *raise* them is welcome and should come with benchmark data and a
  justification in the PR description.
- Follow **PEP 8** (the official Python style guide). This is enforced
  automatically with **ruff** across the rule sets `E`, `F`, `W`, `I`, and `B`
  (see `[tool.ruff]` in `pyproject.toml`), so make sure `ruff check src tests`
  is clean before opening a PR.
- Follow the existing style: plain Python, no third-party libraries beyond the
  declared dependencies, no cleverness for its own sake.
- Keep changes focused. A PR that mixes a bug fix with an unrelated refactor is
  harder to review safely.

## Security-specific contribution rules

Any change touching `src/gun101/kdf.py`, `src/gun101/cipher.py`,
`src/gun101/handler.py`, or `src/gun101/keyfile.py` is security-relevant.
For those changes, additionally:

1. **A written justification is mandatory.** Your PR description must explain
   the cryptographic reasoning behind the change: what property it preserves
   or improves, what attack it addresses, and why the approach is sound.
2. **No new cryptographic primitives written from scratch.** All cryptography
   must come from the well-audited libraries already in use — `cryptography`
   and `argon2-cffi`. Hand-rolled ciphers, custom MACs, or home-grown KDFs will
   be rejected. If you believe a new primitive is necessary, discuss it in an
   issue first.
3. **Do not weaken the failure behaviour.** All failures must continue to
   produce the generic `"Decryption failed"` message. Concretely distinguishable
   error messages create oracle attacks.
4. **Constant-time comparisons only.** Any new comparison of secrets (keyfile
   fingerprints, derived keys, MACs) must use `hmac.compare_digest` or an
   equivalent constant-time primitive — never `==` on secrets.
5. **Randomness comes from `os.urandom()`.** Never use `random`, `secrets` with
   an insecure fallback, or user-controlled sources for salts, nonces, or keys.
6. **Keep the general error surface the same.** If your change alters CLI
   behaviour, keep error messages informative for *user* mistakes but silent
   about *cryptographic* details.

These rules exist because the cost of a subtle flaw is paid by end users, often
years later, in situations you will never see.

## Writing tests

**Project test policy:** as major new functionality is added to the software,
tests covering that functionality are added to the automated test suite at the
same time, in the same pull request. A change that adds or changes behavior
without corresponding tests will not be merged. New tests must pass locally
(`pytest tests/ -v`) and in continuous integration before the change merges.

Every new security-affecting function must have **both** a positive test and a
negative test:

- **Positive test:** the happy path works and produces the documented output
  (e.g. correct password + correct keyfile decrypts and returns identical
  bytes).
- **Negative test:** misuse or tampering fails and raises `ValueError`
  (e.g. wrong password fails, tampered ciphertext fails, wrong keyfile fails).

The existing suite in `tests/test_gun101.py` is the model to follow. Its
helpers (`encrypt_decrypt_cycle`, the `STRONG_PASSWORD` constants, and the
weak-password variants) show the expected conventions. Add tests inside the
existing classes where they fit, or create a new class with the same style.

Security-affecting functions, at minimum, need tests that cover:

- a correct round-trip with exact byte preservation;
- each validation failure mode (empty/weak/malformed inputs);
- bit-for-bit tampering of ciphertext, salt, nonce, and tag;
- non-determinism (same input, different salt/nonce/ciphertext);
- the Argon2id and AES parameter assertions.

If you add a CLI subcommand, test it end-to-end with `subprocess` like the
existing CLI tests do.

## Submitting a pull request

### Developer Certificate of Origin

By contributing, you certify that your contribution is your own (or that you
are authorized to submit it) under the project's MIT license, as described by
the [Developer Certificate of Origin, version 1.1](https://developercertificate.org/)
([full text](DCO) in this repository). Add a sign-off line to the end of every
commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add this automatically from your git identity.

### Branch naming

Create a dedicated branch off `main`, named after the kind of change and the
subject:

```bash
git checkout -b fix/keyfile-permissions-windows
git checkout -b feat/zxcvbn-password-strength
git checkout -b docs/explain-argon2-params
git checkout -b test/tamper-nonce-vectors
```

Use `feat/`, `fix/`, `docs/`, `test/`, `perf/`, or `security/` prefixes.

### Commit messages

Write clear, imperative commit messages using conventional prefixes so the
changelog can be assembled mechanically:

```
feat: add zxcvbn-based password strength enforcement

Add an optional strength check in validate_password() that rejects
passwords scoring below a threshold with zxcvbn. Gated behind the
extra dependency so the default install is unchanged.
```

Prefixes in use: `feat:`, `fix:`, `security:`, `docs:`, `test:`, `perf:`,
`refactor:`, `build:`. Keep the summary under 72 characters and put rationale
in the body. Reference the issue number if one exists (`Closes #12`).

### Push and open the PR

```bash
git push -u origin fix/keyfile-permissions-windows
```

Then open a pull request against `main` using the provided
[PR template](.github/pull_request_template.md). Make sure you fill in the
security review checklist — every item matters.

### Code review standards

Review is mandatory: **no change is merged into `main` without review by a
maintainer other than the author.** This applies to every pull request, whatever
its size.

**How review is conducted**

- PRs are reviewed asynchronously in the GitHub pull request UI. The reviewer
  reads the diff, runs the checks locally (`pytest tests/ -v`,
  `ruff check src tests`, `bandit -r src -q`), and comments inline on
  questionable lines.
- The author and reviewer discuss inline until open questions are resolved,
  then the reviewer approves or requests changes.
- Only an approved PR is merged; the author does not merge their own approved
  change without a second maintainer's explicit approval.

**What must be checked**

- Every diff line is read, not skimmed.
- Security-relevant changes (anything touching `kdf.py`, `cipher.py`,
  `handler.py`, `keyfile.py`, or the container format) are additionally checked
  against the rules in [Security-specific contribution rules](#security-specific-contribution-rules):
  the cryptographic justification, no hand-rolled primitives, no weakened
  failure behaviour, constant-time comparisons only, `os.urandom` only for
  secrets, and no widened error surface.
- Tests are checked for the required positive + negative coverage, and the
  coverage gate (≥80% statements, enforced by pytest-cov) must pass.
- API/CLI changes must update `docs/CLI.md`; user-visible changes must update
  `CHANGELOG.md` (and `docs/UPGRADING.md` when upgrade impact exists).
- The DCO sign-off (see above) must be present on every commit.

**What is required to be acceptable**

- The change does what it claims, matches the documented design, and contains
  no known issues that argue against inclusion.
- All CI checks pass and the PR checklist in the template is complete.
- For security-relevant changes: the reasoning holds up under the reviewer's
  questioning, and no security property is weakened.
- The reviewer records their decision (approve / request changes) on the PR.

The maintainer reviews within a few days and runs `pytest tests/ -v` locally.
Expect questions — cryptographic review is a conversation, not a formality.
Be ready to defend design choices with reasoning, not just code. Changes that
reduce parameters, loosen password policy, or weaken error handling will be
sent back with an explanation.

Please treat review comments as engineering feedback, not criticism. A
respectful technical debate about a cryptographic decision is exactly the kind
of discussion this project wants (see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).

## Reporting security vulnerabilities

**Do not open a public GitHub issue for a security vulnerability.**

Report vulnerabilities privately by emailing **adityaraj1234@duck.com**.
Publicly disclosing a flaw before a fix is released puts every user of the
library at risk — including people who have no idea this project exists, such
as anyone decrypting files that were sealed with GUN-101.

Before reporting, please check [docs/SECURITY.md](docs/SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — the issue may be a documented
limitation (e.g. malware on the host, weak user passwords) rather than a
defect.

What we commit to when you report:

- Acknowledgement within **48 hours**.
- A fix timeline communicated within **7 days**.
- You will be credited in the changelog and README acknowledgements unless you
  request anonymity.

Full details are in [SECURITY.md](SECURITY.md).

## Good first issues

These are small, well-scoped tasks that match the current codebase. Pick one,
comment on the issue, and open a PR. They are ordered roughly from simplest to
most involved.

1. **Add password strength enforcement using zxcvbn** — `validate_password()`
   in `src/gun101/handler.py` enforces composition rules but not entropy.
   Integrate the well-audited `zxcvbn` library as an optional check that
   rejects weak passwords. Decision needed: add as a hard or optional
   dependency. Security-relevant — include justification in the PR.

2. **Add Windows file permission support for the keyfile** —
   `os.chmod(path, 0o600)` in `src/gun101/keyfile.py` is POSIX-only and does
   not translate to real ACLs on Windows. Research the correct handling (e.g.
   NTFS ACLs or a documented fallback) and implement it with tests that skip
   gracefully on non-Windows.

3. **Add a benchmarking script for Argon2id parameters** — a small script
   (e.g. `scripts/benchmark_kdf.py`) that measures `derive_key()` wall time and
   memory across the current parameters, so parameter changes can be justified
   with data. Purely additive, no security impact.

4. **Add a `gun101 info` subcommand** — inspect a `.gun101` container's
   cleartext header fields (protocol, version, whether a keyfile is required,
   and the stored keyfile fingerprint) without decrypting. Reads the
   unauthenticated header only, so no key material is involved. No decryption
   code touched, but write the CLI test suite-style like the existing
   subcommands.

5. **Improve CLI help text** — expand the `argparse` descriptions in
   `src/gun101/cli.py` so `gun101 --help` and each subcommand's `--help`
   explain the container format, password policy, and keyfile two-factor mode
   clearly. Documentation-only change.

## Final checklist before you open a PR

- [ ] I have read [CONTRIBUTING.md](CONTRIBUTING.md).
- [ ] I have read [docs/SECURITY.md](docs/SECURITY.md).
- [ ] My change does not reduce Argon2id `time_cost`, `memory_cost`, or `parallelism`.
- [ ] My change does not reduce AES key length or nonce length.
- [ ] If I touched key derivation, encryption, or decryption, my PR description contains a written cryptographic justification.
- [ ] All new code has type hints and docstrings.
- [ ] I added both a positive and a negative test for any new security-affecting function.
- [ ] `pytest tests/ -v` passes.

Thanks for contributing to GUN-101. Every line you write, review, or fix makes
the tool more trustworthy for the people who depend on it.
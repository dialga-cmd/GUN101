# Releasing GUN-101

This document describes how releases are cut, how they are cryptographically
signed, and how users verify that a release is genuine. It is intended for both
maintainers (who release) and users (who verify).

## Release process

1. **Prepare the release.** Update `pyproject.toml` (bump `version`) and
   `CHANGELOG.md` (move the `[Unreleased]` section into a dated release entry).
   Update `SECURITY.md` if the supported-versions table changes.
2. **Open a pull request.** Follow `CONTRIBUTING.md`; merge only after review.
3. **Tag the release.** Create a git tag named `vX.Y.Z` on the release commit:

   ```bash
   git tag -s v2.2.2 -m "v2.2.2"
   git push origin v2.2.2
   ```

   Tags are **cryptographically signed** (`-s`). GitHub "Verified" tags show
   the signature automatically. Use a signing key that is registered on your
   GitHub account so reviewers can confirm the tag is yours.
4. **Draft a GitHub release** pointing at that tag, using the CHANGELOG entry
   as the release notes. Publishing the GitHub release triggers the
   `Publish to PyPI` workflow.
5. **Build and publish.** The workflow builds the sdist and wheel with
   `python -m build` and publishes to PyPI using trusted publishing (OIDC). The
   published files get PEP 740 attestations that are cryptographically bound to
   the GitHub release and repository.

The private material used for signing attestations is a short-lived OIDC token
minted by GitHub Actions. It never resides on PyPI or on any machine you
control, and it expires immediately after the workflow run.

## How users verify a release

Every published `gun101` release is served over **HTTPS** from PyPI and signed
with **PEP 740 attestations** whose signing identity is the GitHub Actions
workflow of this repository.

### Verify the package matches the source

You can pin exact versions with cryptographic hashes using the project's
`requirements.lock` (all direct and transitive dependencies are listed with their SHA-256 hashes):

```bash
pip install --require-hashes -r requirements.lock
```

### Verify the provenance attestation

PyPI stores the signed attestation for each release. To inspect it:

```bash
pip download --no-deps gun101==<version> --dest ./dl
python -m pip_audit --path ./dl
```

or fetch the attestation bundle and verify it with a Sigstore/PEP 740 aware
tool. The attestation proves the artifact was uploaded by the GitHub Actions
workflow of `https://github.com/dialga-cmd/gun101` (see the
[OpenID Connect identity](https://docs.pypi.org/trusted-publishers/) recorded
on the PyPI release page).

### Verify the git tag

The `vX.Y.Z` tags are intended to be signed with `git tag -s`. However,
the `v2.2.2` tag is annotated but **not signed** — `git tag -v v2.2.2`
returns `error: no signature found`. Either sign existing tags or update
the documentation to reflect that signing is optional. Until signing is
restored, users should verify the tag against the GitHub release page and the
PyPI trusted publisher attestation instead.

## Checking a release before publishing (maintainers)

Before publishing, run the full CI suite locally:

```bash
pytest tests/ -v
ruff check src tests
bandit -r src -q
mkdir -p dist
python -m build --outdir dist
```

CI (`.github/workflows/ci.yml`) does the same on every commit and pull
request, so a green pipeline is a reliable signal that the release is ready.
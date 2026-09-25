# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Tests for output overwrite protection and --force flag (GitHub Issue #1)."""

import argparse
import contextlib
import io
import os
import subprocess
import sys

import pytest

from gun101 import cli, config, handler

STRONG_PASSWORD = "Str0ngP@ssw0rd!"


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    """Fast Argon2 parameters to keep test suite responsive."""
    monkeypatch.setattr(config, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(config, "ARGON2_MEMORY_COST", 8)
    monkeypatch.setattr(config, "ARGON2_PARALLELISM", 1)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Run test inside an isolated temporary working directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def env_password(monkeypatch):
    """Provide password through environment variable."""
    monkeypatch.setenv("GUN101_PASSWORD", STRONG_PASSWORD)
    yield
    monkeypatch.delenv("GUN101_PASSWORD", raising=False)


def make_arg(**kwargs):
    return argparse.Namespace(**kwargs)


def run_func(func, args):
    """Execute a CLI function in-process, capturing stdout, stderr, and SystemExit."""
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            func(args)
        return out.getvalue(), err.getvalue(), None
    except SystemExit as exc:
        return out.getvalue(), err.getvalue(), exc


def run_main(args_list):
    """Execute cli.main() in-process with the given sys.argv."""
    out, err = io.StringIO(), io.StringIO()
    old_argv = sys.argv
    sys.argv = ["gun101"] + args_list
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main()
        return out.getvalue(), err.getvalue(), None
    except SystemExit as exc:
        return out.getvalue(), err.getvalue(), exc
    finally:
        sys.argv = old_argv


# ---------------------------------------------------------------------------
# Unit tests for safe_open_write()
# ---------------------------------------------------------------------------


class TestSafeOpenWriteOverwriteProtection:
    def test_safe_open_write_creates_new_file(self, workdir):
        """safe_open_write should create and open a non-existing file."""
        path = "brand_new.bin"
        with cli.safe_open_write(path) as f:
            f.write(b"content")
        assert os.path.exists(path)
        with open(path, "rb") as f:
            assert f.read() == b"content"

    def test_safe_open_write_fails_when_file_exists_without_force(self, workdir):
        """safe_open_write should raise FileExistsError if file already exists and force=False."""
        path = "existing.bin"
        with open(path, "wb") as f:
            f.write(b"original data")

        with pytest.raises(FileExistsError) as exc_info:
            cli.safe_open_write(path, force=False)

        assert "already exists" in str(exc_info.value)
        assert "--force" in str(exc_info.value)

        # File content must remain intact
        with open(path, "rb") as f:
            assert f.read() == b"original data"

    def test_safe_open_write_defaults_to_force_false(self, workdir):
        """safe_open_write should default to force=False when omitted."""
        path = "existing_default.bin"
        with open(path, "wb") as f:
            f.write(b"original")

        with pytest.raises(FileExistsError):
            cli.safe_open_write(path)

        with open(path, "rb") as f:
            assert f.read() == b"original"

    def test_safe_open_write_overwrites_with_force_true(self, workdir):
        """safe_open_write should overwrite an existing file when force=True."""
        path = "overwrite_me.bin"
        with open(path, "wb") as f:
            f.write(b"old data")

        with cli.safe_open_write(path, force=True) as f:
            f.write(b"new data")

        with open(path, "rb") as f:
            assert f.read() == b"new data"


# ---------------------------------------------------------------------------
# Encrypt overwrite protection tests
# ---------------------------------------------------------------------------


class TestEncryptOverwriteProtection:
    def test_encrypt_default_output_exists_fails_without_force(self, workdir, env_password):
        """Encrypt when default output (<file>.gun101) already exists must fail without --force."""
        with open("doc.txt", "wb") as f:
            f.write(b"sensitive plaintext")
        with open("doc.txt.gun101", "wb") as f:
            f.write(b"prior existing container")

        out, err, exc = run_func(cli.encrypt, make_arg(file="doc.txt", keyfile=None, output=None, force=False))
        assert exc is not None and exc.code == 1
        assert "Output file already exists: doc.txt.gun101" in err
        assert "--force" in err

        # Verify existing file was not overwritten
        with open("doc.txt.gun101", "rb") as f:
            assert f.read() == b"prior existing container"

    def test_encrypt_default_output_missing_force_attr_fails(self, workdir, env_password):
        """Encrypt with Namespace lacking force attribute safely defaults to no-overwrite."""
        with open("doc.txt", "wb") as f:
            f.write(b"sensitive plaintext")
        with open("doc.txt.gun101", "wb") as f:
            f.write(b"prior existing container")

        out, err, exc = run_func(cli.encrypt, make_arg(file="doc.txt", keyfile=None, output=None))
        assert exc is not None and exc.code == 1
        assert "Output file already exists" in err

        with open("doc.txt.gun101", "rb") as f:
            assert f.read() == b"prior existing container"

    def test_encrypt_explicit_output_exists_fails_without_force(self, workdir, env_password):
        """Encrypt with an existing explicit --output must fail without --force."""
        with open("doc.txt", "wb") as f:
            f.write(b"plaintext")
        with open("custom_out.enc", "wb") as f:
            f.write(b"do not overwrite me")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="custom_out.enc", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output file already exists: custom_out.enc" in err
        assert "--force" in err

        with open("custom_out.enc", "rb") as f:
            assert f.read() == b"do not overwrite me"

    def test_encrypt_default_output_overwritten_with_force(self, workdir, env_password):
        """Encrypt with --force overwrites existing default output."""
        with open("doc.txt", "wb") as f:
            f.write(b"new secret payload")
        with open("doc.txt.gun101", "wb") as f:
            f.write(b"old garbage")

        out, err, exc = run_func(cli.encrypt, make_arg(file="doc.txt", keyfile=None, output=None, force=True))
        assert exc is None
        assert "Encrypted file written to: doc.txt.gun101" in out

        # Verify output is a valid container and decrypts to new payload
        with open("doc.txt.gun101", "rb") as f:
            container = f.read()
        assert container != b"old garbage"
        assert handler.decrypt_file(container, STRONG_PASSWORD) == b"new secret payload"

    def test_encrypt_explicit_output_overwritten_with_force(self, workdir, env_password):
        """Encrypt with explicit --output and --force overwrites existing output."""
        with open("doc.txt", "wb") as f:
            f.write(b"payload")
        with open("custom.enc", "wb") as f:
            f.write(b"stale data")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="custom.enc", force=True)
        )
        assert exc is None
        assert "Encrypted file written to: custom.enc" in out

        with open("custom.enc", "rb") as f:
            container = f.read()
        assert container != b"stale data"
        assert handler.decrypt_file(container, STRONG_PASSWORD) == b"payload"

    def test_encrypt_normal_when_output_does_not_exist(self, workdir, env_password):
        """Encrypt when output does not exist succeeds normally without --force."""
        with open("doc.txt", "wb") as f:
            f.write(b"hello world")
        assert not os.path.exists("doc.txt.gun101")

        out, err, exc = run_func(cli.encrypt, make_arg(file="doc.txt", keyfile=None, output=None, force=False))
        assert exc is None
        assert os.path.exists("doc.txt.gun101")
        with open("doc.txt.gun101", "rb") as f:
            container = f.read()
        assert handler.decrypt_file(container, STRONG_PASSWORD) == b"hello world"


# ---------------------------------------------------------------------------
# Decrypt overwrite protection tests
# ---------------------------------------------------------------------------


class TestDecryptOverwriteProtection:
    def _create_container(self, payload=b"original decrypted content", filename="doc.txt"):
        container = handler.encrypt_file(payload, STRONG_PASSWORD)
        enc_path = filename + ".gun101"
        with open(enc_path, "wb") as f:
            f.write(container)
        return enc_path

    def test_decrypt_default_output_exists_fails_without_force(self, workdir, env_password):
        """Decrypt when default output (<file>) already exists must fail without --force."""
        enc_file = self._create_container(payload=b"new payload", filename="secret.txt")
        # Pre-create the default output file
        with open("secret.txt", "wb") as f:
            f.write(b"precious existing local file")

        out, err, exc = run_func(cli.decrypt, make_arg(file=enc_file, keyfile=None, output=None, force=False))
        assert exc is not None and exc.code == 1
        assert "Output file already exists: secret.txt" in err
        assert "--force" in err

        # Verify existing file was not modified or truncated
        with open("secret.txt", "rb") as f:
            assert f.read() == b"precious existing local file"

    def test_decrypt_default_output_missing_force_attr_fails(self, workdir, env_password):
        """Decrypt with Namespace lacking force attribute safely defaults to no-overwrite."""
        enc_file = self._create_container(payload=b"new payload", filename="secret.txt")
        with open("secret.txt", "wb") as f:
            f.write(b"precious existing local file")

        out, err, exc = run_func(cli.decrypt, make_arg(file=enc_file, keyfile=None, output=None))
        assert exc is not None and exc.code == 1
        assert "Output file already exists" in err

        with open("secret.txt", "rb") as f:
            assert f.read() == b"precious existing local file"

    def test_decrypt_non_gun101_suffix_default_output_fails_without_force(self, workdir, env_password):
        """Decrypt non-.gun101 file defaults to .decrypted suffix; fails if that exists."""
        container = handler.encrypt_file(b"secret", STRONG_PASSWORD)
        with open("raw.blob", "wb") as f:
            f.write(container)
        with open("raw.blob.decrypted", "wb") as f:
            f.write(b"existing decrypted file")

        out, err, exc = run_func(cli.decrypt, make_arg(file="raw.blob", keyfile=None, output=None, force=False))
        assert exc is not None and exc.code == 1
        assert "Output file already exists: raw.blob.decrypted" in err

        with open("raw.blob.decrypted", "rb") as f:
            assert f.read() == b"existing decrypted file"

    def test_decrypt_explicit_output_exists_fails_without_force(self, workdir, env_password):
        """Decrypt with an existing explicit --output must fail without --force."""
        enc_file = self._create_container(payload=b"new content", filename="test.txt")
        with open("target.txt", "wb") as f:
            f.write(b"important target file")

        out, err, exc = run_func(
            cli.decrypt, make_arg(file=enc_file, keyfile=None, output="target.txt", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output file already exists: target.txt" in err
        assert "--force" in err

        with open("target.txt", "rb") as f:
            assert f.read() == b"important target file"

    def test_decrypt_default_output_overwritten_with_force(self, workdir, env_password):
        """Decrypt with --force overwrites existing default output."""
        enc_file = self._create_container(payload=b"new recovered content", filename="doc.txt")
        with open("doc.txt", "wb") as f:
            f.write(b"old content to replace")

        out, err, exc = run_func(cli.decrypt, make_arg(file=enc_file, keyfile=None, output=None, force=True))
        assert exc is None
        assert "Decrypted file written to: doc.txt" in out

        with open("doc.txt", "rb") as f:
            assert f.read() == b"new recovered content"

    def test_decrypt_explicit_output_overwritten_with_force(self, workdir, env_password):
        """Decrypt with explicit --output and --force overwrites existing output."""
        enc_file = self._create_container(payload=b"recovered data", filename="archive.bin")
        with open("restored.bin", "wb") as f:
            f.write(b"stale binary")

        out, err, exc = run_func(
            cli.decrypt, make_arg(file=enc_file, keyfile=None, output="restored.bin", force=True)
        )
        assert exc is None
        assert "Decrypted file written to: restored.bin" in out

        with open("restored.bin", "rb") as f:
            assert f.read() == b"recovered data"

    def test_decrypt_normal_when_output_does_not_exist(self, workdir, env_password):
        """Decrypt when output does not exist succeeds normally without --force."""
        enc_file = self._create_container(payload=b"fresh decrypted data", filename="notes.txt")
        assert not os.path.exists("notes.txt")

        out, err, exc = run_func(cli.decrypt, make_arg(file=enc_file, keyfile=None, output=None, force=False))
        assert exc is None
        assert os.path.exists("notes.txt")
        with open("notes.txt", "rb") as f:
            assert f.read() == b"fresh decrypted data"


# ---------------------------------------------------------------------------
# CLI Argument parsing & main() integration tests
# ---------------------------------------------------------------------------


class TestCliMainForceIntegration:
    def test_main_encrypt_refuses_overwrite_without_force(self, workdir, env_password):
        """CLI main encrypt fails without --force if output exists."""
        with open("sample.txt", "wb") as f:
            f.write(b"content")
        with open("sample.txt.gun101", "wb") as f:
            f.write(b"existing")

        out, err, exc = run_main(["encrypt", "sample.txt"])
        assert exc is not None and exc.code == 1
        assert "Output file already exists" in err

    def test_main_encrypt_allows_overwrite_with_long_flag(self, workdir, env_password):
        """CLI main encrypt allows overwrite with --force."""
        with open("sample.txt", "wb") as f:
            f.write(b"updated data")
        with open("sample.txt.gun101", "wb") as f:
            f.write(b"stale")

        out, err, exc = run_main(["encrypt", "sample.txt", "--force"])
        assert exc is None
        assert "Encrypted file written to: sample.txt.gun101" in out

    def test_main_encrypt_allows_overwrite_with_short_flag(self, workdir, env_password):
        """CLI main encrypt allows overwrite with -f."""
        with open("sample.txt", "wb") as f:
            f.write(b"updated data short flag")
        with open("sample.txt.gun101", "wb") as f:
            f.write(b"stale")

        out, err, exc = run_main(["encrypt", "sample.txt", "-f"])
        assert exc is None
        assert "Encrypted file written to: sample.txt.gun101" in out

    def test_main_decrypt_refuses_overwrite_without_force(self, workdir, env_password):
        """CLI main decrypt fails without --force if output exists."""
        container = handler.encrypt_file(b"secret", STRONG_PASSWORD)
        with open("file.gun101", "wb") as f:
            f.write(container)
        with open("file", "wb") as f:
            f.write(b"existing local file")

        out, err, exc = run_main(["decrypt", "file.gun101"])
        assert exc is not None and exc.code == 1
        assert "Output file already exists" in err

    def test_main_decrypt_allows_overwrite_with_long_flag(self, workdir, env_password):
        """CLI main decrypt allows overwrite with --force."""
        container = handler.encrypt_file(b"new secret", STRONG_PASSWORD)
        with open("file.gun101", "wb") as f:
            f.write(container)
        with open("file", "wb") as f:
            f.write(b"old local file")

        out, err, exc = run_main(["decrypt", "file.gun101", "--force"])
        assert exc is None
        assert "Decrypted file written to: file" in out
        with open("file", "rb") as f:
            assert f.read() == b"new secret"

    def test_main_decrypt_allows_overwrite_with_short_flag(self, workdir, env_password):
        """CLI main decrypt allows overwrite with -f."""
        container = handler.encrypt_file(b"new secret -f", STRONG_PASSWORD)
        with open("file.gun101", "wb") as f:
            f.write(container)
        with open("file", "wb") as f:
            f.write(b"old local file")

        out, err, exc = run_main(["decrypt", "file.gun101", "-f"])
        assert exc is None
        assert "Decrypted file written to: file" in out
        with open("file", "rb") as f:
            assert f.read() == b"new secret -f"


# ---------------------------------------------------------------------------
# Subprocess end-to-end tests
# ---------------------------------------------------------------------------


class TestSubprocessCliOverwrite:
    def test_subprocess_encrypt_and_decrypt_with_and_without_force(self, workdir):
        """End-to-end subprocess testing of encrypt/decrypt overwrite protection."""
        src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
        env = os.environ.copy()
        env["PYTHONPATH"] = src_dir
        env["GUN101_PASSWORD"] = STRONG_PASSWORD

        # 1. Prepare plaintext and pre-existing output
        with open("input.txt", "wb") as f:
            f.write(b"original data")
        with open("input.txt.gun101", "wb") as f:
            f.write(b"prior file")

        # 2. Encrypt without --force should fail
        res = subprocess.run(
            [sys.executable, "-m", "gun101.cli", "encrypt", "input.txt"],
            cwd=str(workdir),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 1
        assert "Output file already exists: input.txt.gun101" in res.stderr
        with open("input.txt.gun101", "rb") as f:
            assert f.read() == b"prior file"

        # 3. Encrypt with --force should succeed
        res = subprocess.run(
            [sys.executable, "-m", "gun101.cli", "encrypt", "input.txt", "--force"],
            cwd=str(workdir),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        with open("input.txt.gun101", "rb") as f:
            assert f.read() != b"prior file"

        # 4. Decrypt without --force when input.txt already exists should fail
        res = subprocess.run(
            [sys.executable, "-m", "gun101.cli", "decrypt", "input.txt.gun101"],
            cwd=str(workdir),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 1
        assert "Output file already exists: input.txt" in res.stderr

        # 5. Decrypt with --force when input.txt exists should succeed
        with open("input.txt", "wb") as f:
            f.write(b"pre-existing unencrypted file")

        res = subprocess.run(
            [sys.executable, "-m", "gun101.cli", "decrypt", "input.txt.gun101", "--force"],
            cwd=str(workdir),
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        with open("input.txt", "rb") as f:
            assert f.read() == b"original data"

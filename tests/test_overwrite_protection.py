# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Tests for output overwrite protection and --force flag (GitHub Issue #1)."""

import argparse
import contextlib
import errno
import io
import os
import stat
import subprocess
import sys

import pytest

from gun101 import cli, config, handler

STRONG_PASSWORD = "Str0ngP@ssw0rd!"

UNSUPPORTED_HARDLINK_ERRNOS = sorted(
    {
        err
        for err in [
            errno.EPERM,
            errno.EXDEV,
            getattr(errno, "ENOTSUP", None),
            getattr(errno, "EOPNOTSUPP", None),
            getattr(errno, "EMLINK", None),
        ]
        if err is not None
    }
)


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
    def test_existing_output_fails_before_encrypt_stream(
        self, workdir, env_password, monkeypatch
    ):
        """An existing output must be rejected before encryption starts."""
        input_path = workdir / "plain.bin"
        output_path = workdir / "existing.enc"
        input_path.write_bytes(b"new data")
        output_path.write_bytes(b"existing container")

        calls = []

        def fake_encrypt_stream(*args, **kwargs):
            calls.append(True)
            raise AssertionError("Encryption should not start")

        monkeypatch.setattr(handler, "encrypt_stream", fake_encrypt_stream)

        args = make_arg(
            file=str(input_path),
            output=str(output_path),
            keyfile=None,
            force=False,
        )

        out, err, exc = run_func(cli.encrypt, args)

        assert exc is not None and exc.code == 1
        assert "Output file already exists" in err
        assert calls == []
        assert output_path.read_bytes() == b"existing container"

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

    def test_encrypt_explicit_output_normal_when_not_exists(self, workdir, env_password):
        """Encrypt with explicit --output when destination does not exist succeeds."""
        with open("doc.txt", "wb") as f:
            f.write(b"hello explicit")
        assert not os.path.exists("custom_target.enc")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="custom_target.enc", force=False)
        )
        assert exc is None
        assert os.path.exists("custom_target.enc")
        with open("custom_target.enc", "rb") as f:
            container = f.read()
        assert handler.decrypt_file(container, STRONG_PASSWORD) == b"hello explicit"

    def test_encrypt_with_force_when_output_does_not_exist(self, workdir, env_password):
        """Encrypt with --force when destination does not exist succeeds."""
        with open("doc.txt", "wb") as f:
            f.write(b"hello new with force")
        assert not os.path.exists("doc.txt.gun101")

        out, err, exc = run_func(cli.encrypt, make_arg(file="doc.txt", keyfile=None, output=None, force=True))
        assert exc is None
        assert os.path.exists("doc.txt.gun101")
        with open("doc.txt.gun101", "rb") as f:
            container = f.read()
        assert handler.decrypt_file(container, STRONG_PASSWORD) == b"hello new with force"

    def test_encrypt_escape_rejected_with_force(self, workdir, env_password):
        """--force must not bypass the output containment check."""
        with open("doc.txt", "wb") as f:
            f.write(b"data")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="../escape.bin", force=True)
        )

        assert exc is not None and exc.code == 1
        assert "escape" in err
        assert not (workdir.parent / "escape.bin").exists()

    def test_encrypt_output_symlink_rejected_with_force(self, workdir, env_password):
        """--force must not replace an output symlink."""
        with open("doc.txt", "wb") as f:
            f.write(b"data")
        with open("target.bin", "wb") as f:
            f.write(b"target contents")
        try:
            os.symlink("target.bin", "link.bin")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available on this platform")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="link.bin", force=True)
        )

        assert exc is not None and exc.code == 1
        assert "symlink" in err
        assert os.path.islink("link.bin")
        with open("target.bin", "rb") as f:
            assert f.read() == b"target contents"


# ---------------------------------------------------------------------------
# Encrypt input/output identity tests (GitHub Issue #35)
# ---------------------------------------------------------------------------


class TestEncryptInputOutputSameFile:
    def test_same_path_refused_even_with_force(self, workdir, env_password):
        """Encrypting a file onto itself must fail before the input is truncated."""
        payload = b"precious plaintext that must survive"
        with open("doc.txt", "wb") as f:
            f.write(payload)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="doc.txt", force=True)
        )

        assert exc is not None and exc.code == 1
        assert "Refusing to overwrite the input file" in err
        with open("doc.txt", "rb") as f:
            assert f.read() == payload

    def test_relative_alias_refused(self, workdir, env_password):
        """A different spelling of the same path must also be refused."""
        payload = b"still precious"
        with open("doc.txt", "wb") as f:
            f.write(payload)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="./doc.txt", force=True)
        )

        assert exc is not None and exc.code == 1
        assert "Refusing to overwrite the input file" in err
        with open("doc.txt", "rb") as f:
            assert f.read() == payload

    def test_symlink_to_input_refused(self, workdir, env_password):
        """An output symlink resolving to the input must be refused."""
        payload = b"do not clobber via symlink"
        with open("doc.txt", "wb") as f:
            f.write(payload)
        try:
            os.symlink("doc.txt", "alias.txt")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available on this platform")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="alias.txt", force=True)
        )

        assert exc is not None and exc.code == 1
        assert "Refusing to overwrite the input file" in err
        assert os.path.islink("alias.txt")
        with open("doc.txt", "rb") as f:
            assert f.read() == payload

    def test_hardlink_to_input_refused(self, workdir, env_password):
        """A hard link to the input is the same inode and must be refused."""
        payload = b"do not clobber via hardlink"
        with open("doc.txt", "wb") as f:
            f.write(payload)
        try:
            os.link("doc.txt", "hard.txt")
        except (OSError, NotImplementedError):
            pytest.skip("hard links are not available on this platform")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="doc.txt", keyfile=None, output="hard.txt", force=True)
        )

        assert exc is not None and exc.code == 1
        assert "Refusing to overwrite the input file" in err
        with open("doc.txt", "rb") as f:
            assert f.read() == payload
        with open("hard.txt", "rb") as f:
            assert f.read() == payload


# ---------------------------------------------------------------------------
# Encrypt atomicity tests (GitHub Issue #36)
# ---------------------------------------------------------------------------


class TestEncryptAtomicity:
    @staticmethod
    def _staging_leftovers():
        return [name for name in os.listdir(".") if ".tmp." in name]

    def test_failed_encrypt_preserves_existing_output(self, workdir, env_password, monkeypatch):
        """A write failure must not destroy a pre-existing container."""
        with open("plain.bin", "wb") as f:
            f.write(b"NEW PLAINTEXT")
        with open("existing.enc", "wb") as f:
            f.write(b"OLD VALUABLE CONTAINER")

        def boom(*args, **kwargs):
            raise OSError("simulated disk full")

        monkeypatch.setattr(handler, "encrypt_stream", boom)
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="plain.bin", keyfile=None, output="existing.enc", force=True)
        )

        assert exc is not None and exc.code == 1
        assert "simulated disk full" in err
        with open("existing.enc", "rb") as f:
            assert f.read() == b"OLD VALUABLE CONTAINER"
        assert self._staging_leftovers() == []

    def test_failed_encrypt_creates_no_output_when_absent(self, workdir, env_password, monkeypatch):
        """A failed first-time encryption must leave no partial output behind."""
        with open("plain.bin", "wb") as f:
            f.write(b"payload")

        def boom(*args, **kwargs):
            raise OSError("simulated disk full")

        monkeypatch.setattr(handler, "encrypt_stream", boom)
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="plain.bin", keyfile=None, output="new.enc", force=False)
        )

        assert exc is not None and exc.code == 1
        assert not os.path.exists("new.enc")
        assert self._staging_leftovers() == []

    def test_failed_replace_removes_reserved_output(self, workdir, env_password, monkeypatch):
        """If publishing fails, the placeholder created to reserve the name is removed."""
        with open("plain.bin", "wb") as f:
            f.write(b"payload")

        def boom(*args, **kwargs):
            raise OSError("simulated rename failure")

        monkeypatch.setattr(os, "replace", boom)
        monkeypatch.setattr(os, "rename", boom)
        monkeypatch.setattr(os, "link", boom)
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="plain.bin", keyfile=None, output="new.enc", force=False)
        )

        assert exc is not None and exc.code == 1
        assert "simulated rename failure" in err
        assert not os.path.exists("new.enc")
        assert self._staging_leftovers() == []

    def test_existing_output_without_force_is_preserved(self, workdir, env_password):
        """The completion-time reservation still refuses to overwrite without --force."""
        with open("plain.bin", "wb") as f:
            f.write(b"new payload")
        with open("existing.enc", "wb") as f:
            f.write(b"keep me")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="plain.bin", keyfile=None, output="existing.enc", force=False)
        )

        assert exc is not None and exc.code == 1
        assert "Output file already exists" in err
        with open("existing.enc", "rb") as f:
            assert f.read() == b"keep me"
        assert self._staging_leftovers() == []

    def test_successful_encrypt_publishes_staged_file(self, workdir, env_password):
        """Success publishes the container with owner-only mode and no temp leftovers."""
        with open("plain.bin", "wb") as f:
            f.write(b"hello atomic world")

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="plain.bin", keyfile=None, output="out.enc", force=False)
        )

        assert exc is None, err
        assert "Encrypted file written to: out.enc" in out
        assert self._staging_leftovers() == []
        with open("out.enc", "rb") as f:
            container = f.read()
        assert handler.decrypt_file(container, STRONG_PASSWORD) == b"hello atomic world"
        if os.name != "nt":
            mode = stat.S_IMODE(os.stat("out.enc").st_mode)
            assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


# ---------------------------------------------------------------------------
# Decrypt overwrite protection tests
# ---------------------------------------------------------------------------


class TestDecryptOverwriteProtection:
    def test_existing_output_fails_before_decrypt_stream(
        self, workdir, env_password, monkeypatch
    ):
        """An existing output must be rejected before decryption starts."""
        input_path = workdir / "encrypted.gun101"
        output_path = workdir / "existing.txt"
        input_path.write_bytes(b"encrypted input placeholder")
        output_path.write_bytes(b"existing plaintext")

        calls = []

        def fake_decrypt_stream(*args, **kwargs):
            calls.append(True)
            raise AssertionError("Decryption should not start")

        monkeypatch.setattr(handler, "decrypt_stream", fake_decrypt_stream)

        args = make_arg(
            file=str(input_path),
            output=str(output_path),
            keyfile=None,
            force=False,
        )

        out, err, exc = run_func(cli.decrypt, args)

        assert exc is not None and exc.code == 1
        assert "Output file already exists" in err
        assert calls == []
        assert output_path.read_bytes() == b"existing plaintext"

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

    def test_decrypt_explicit_output_normal_when_not_exists(self, workdir, env_password):
        """Decrypt with explicit --output when destination does not exist succeeds."""
        enc_file = self._create_container(payload=b"explicit target data", filename="notes.txt")
        assert not os.path.exists("custom_plain.txt")

        out, err, exc = run_func(
            cli.decrypt, make_arg(file=enc_file, keyfile=None, output="custom_plain.txt", force=False)
        )
        assert exc is None
        assert os.path.exists("custom_plain.txt")
        with open("custom_plain.txt", "rb") as f:
            assert f.read() == b"explicit target data"

    def test_decrypt_with_force_when_output_does_not_exist(self, workdir, env_password):
        """Decrypt with --force when destination does not exist succeeds."""
        enc_file = self._create_container(payload=b"fresh data force", filename="notes.txt")
        assert not os.path.exists("notes.txt")

        out, err, exc = run_func(cli.decrypt, make_arg(file=enc_file, keyfile=None, output=None, force=True))
        assert exc is None
        assert os.path.exists("notes.txt")
        with open("notes.txt", "rb") as f:
            assert f.read() == b"fresh data force"

    def test_decrypt_force_preserves_existing_destination_on_decryption_failure(
        self, workdir, monkeypatch
    ):
        """Decrypt with --force preserves existing destination if decryption fails."""
        container = handler.encrypt_file(b"payload", STRONG_PASSWORD)
        with open("secret.txt.gun101", "wb") as f:
            f.write(container)
        with open("secret.txt", "wb") as f:
            f.write(b"existing valuable data")

        monkeypatch.setenv("GUN101_PASSWORD", "Wr0ngP@ssw0rd!")
        out, err, exc = run_func(
            cli.decrypt, make_arg(file="secret.txt.gun101", keyfile=None, output=None, force=True)
        )
        assert exc is not None and exc.code == 1
        assert "Decryption failed" in err

        with open("secret.txt", "rb") as f:
            assert f.read() == b"existing valuable data"


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


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
class TestDecryptedOutputPermissions:
    """Regression: decrypted plaintext must not be world-readable.

    decrypt() streams plaintext into a staging file and then os.replace()s it
    into position. The staging file used to be created with open(path,'wb'),
    so it inherited the process umask (typically 0o644) and os.replace carried
    that mode onto the final output -- leaving decrypted secrets readable by
    every local user, while the container and keyfile were correctly 0o600.
    """

    @staticmethod
    def _run(workdir, argv, password="Str0ngP@ssw0rd!"):
        env = dict(os.environ, GUN101_PASSWORD=password)
        return subprocess.run(
            [sys.executable, "-m", "gun101.cli", *argv],
            cwd=str(workdir), env=env, capture_output=True, text=True,
        )

    def test_decrypted_output_is_owner_only(self, tmp_path):
        (tmp_path / "input.txt").write_bytes(b"top secret plaintext")
        assert self._run(tmp_path, ["encrypt", "input.txt"]).returncode == 0

        res = self._run(tmp_path, ["decrypt", "input.txt.gun101", "--output", "out.txt"])
        assert res.returncode == 0, res.stderr

        mode = stat.S_IMODE(os.stat(tmp_path / "out.txt").st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
        assert not mode & 0o077, f"output readable by group/other: {oct(mode)}"

    def test_decrypted_output_is_owner_only_with_force(self, tmp_path):
        """The --force path bypasses safe_open_write() and must still be 0o600."""
        (tmp_path / "input.txt").write_bytes(b"top secret plaintext")
        assert self._run(tmp_path, ["encrypt", "input.txt"]).returncode == 0
        (tmp_path / "out.txt").write_bytes(b"pre-existing")

        res = self._run(tmp_path, ["decrypt", "input.txt.gun101", "--output", "out.txt", "--force"])
        assert res.returncode == 0, res.stderr

        mode = stat.S_IMODE(os.stat(tmp_path / "out.txt").st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"

    def test_staging_file_is_not_world_readable_during_decryption(
        self, workdir, env_password, monkeypatch
    ):
        """The staging file holds plaintext while it is being written.

        Runs cli.decrypt in-process so the staging fd can be inspected directly;
        a subprocess would hide it behind a separate interpreter.
        """
        (workdir / "input.txt").write_bytes(b"top secret plaintext")
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="input.txt", keyfile=None, output=None, force=False)
        )
        assert exc is None, err

        seen = {}
        real_open = os.open

        def spy_open(path, flags, mode=0o777, *a, **kw):
            fd = real_open(path, flags, mode, *a, **kw)
            if isinstance(path, (str, bytes)) and b".tmp." in (
                path.encode() if isinstance(path, str) else path
            ):
                try:
                    seen["path"] = path
                    seen["mode"] = stat.S_IMODE(os.fstat(fd).st_mode)
                    seen["requested"] = mode
                except OSError:
                    pass
            return fd

        monkeypatch.setattr(os, "open", spy_open)
        out, err, exc = run_func(
            cli.decrypt, make_arg(file="input.txt.gun101", keyfile=None, output="out.txt", force=False)
        )

        assert exc is None, err
        assert "mode" in seen, "staging file was never observed"
        assert seen["requested"] == 0o600, f"staging file requested mode {oct(seen['requested'])}"
        assert not seen["mode"] & 0o077, f"staging file was {oct(seen['mode'])} while holding plaintext"

    def test_failed_decryption_does_not_leave_plaintext_staging_file(
        self, workdir, env_password, monkeypatch
    ):
        """A wrong password must not leave a readable staging file behind."""
        (workdir / "input.txt").write_bytes(b"top secret plaintext")
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="input.txt", keyfile=None, output=None, force=False)
        )
        assert exc is None, err

        monkeypatch.setenv("GUN101_PASSWORD", "Wr0ngP@ssw0rd!")
        out, err, exc = run_func(
            cli.decrypt, make_arg(file="input.txt.gun101", keyfile=None, output="out.txt", force=False)
        )

        assert exc is not None
        leftovers = [p.name for p in workdir.iterdir() if ".tmp." in p.name]
        assert not leftovers, f"staging files left behind: {leftovers}"
        assert not (workdir / "out.txt").exists()


class TestStagingPathSecurity:
    """Regression tests for GitHub Issue #39: Staging path construction security."""

    def test_decrypt_dot_gun101_default_output_rejected_before_staging(
        self, workdir, env_password, monkeypatch
    ):
        """Decrypting .gun101 with default output must be rejected before any staging file is created."""
        enc = handler.encrypt_file(b"secret payload", STRONG_PASSWORD)
        (workdir / ".gun101").write_bytes(enc)

        opened_paths = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            opened_paths.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        out, err, exc = run_func(
            cli.decrypt, make_arg(file=".gun101", keyfile=None, output=None, force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output path cannot be empty" in err
        # Assert rejection happened before any staging file was opened
        assert not any(".tmp." in p for p in opened_paths), f"Staging file opened: {opened_paths}"
        assert not list(workdir.glob("*.tmp.*"))
        assert not list(workdir.parent.glob("*.tmp.*"))

    def test_encrypt_explicit_empty_output_rejected_before_staging(
        self, workdir, env_password, monkeypatch
    ):
        """Explicit --output '' during encryption must be rejected before any staging."""
        (workdir / "in.txt").write_bytes(b"content")

        opened_paths = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            opened_paths.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output path cannot be empty" in err
        assert not any(".tmp." in p for p in opened_paths), f"Staging file opened: {opened_paths}"
        assert not (workdir / "in.txt.gun101").exists()

    def test_decrypt_explicit_empty_output_rejected_before_staging(
        self, workdir, env_password, monkeypatch
    ):
        """Explicit --output '' during decryption must be rejected before any staging."""
        enc = handler.encrypt_file(b"content", STRONG_PASSWORD)
        (workdir / "in.txt.gun101").write_bytes(enc)

        opened_paths = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            opened_paths.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        out, err, exc = run_func(
            cli.decrypt, make_arg(file="in.txt.gun101", keyfile=None, output="", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output path cannot be empty" in err
        assert not any(".tmp." in p for p in opened_paths), f"Staging file opened: {opened_paths}"
        assert not list(workdir.parent.glob("*.tmp.*"))

    def test_encrypt_and_decrypt_output_dot_rejected_before_staging(
        self, workdir, env_password, monkeypatch
    ):
        """--output '.' must be rejected before any staging file is created."""
        (workdir / "in.txt").write_bytes(b"content")
        enc = handler.encrypt_file(b"content", STRONG_PASSWORD)
        (workdir / "in.txt.gun101").write_bytes(enc)

        opened_paths = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            opened_paths.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        # Encrypt with output='.'
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output=".", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output path cannot be a directory" in err
        assert not any(".tmp." in p for p in opened_paths), f"Staging file opened: {opened_paths}"

        # Decrypt with output='.'
        opened_paths.clear()
        out, err, exc = run_func(
            cli.decrypt, make_arg(file="in.txt.gun101", keyfile=None, output=".", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output path cannot be a directory" in err
        assert not any(".tmp." in p for p in opened_paths), f"Staging file opened: {opened_paths}"
        assert not list(workdir.parent.glob("*.tmp.*"))

    def test_output_existing_directory_rejected_before_staging(
        self, workdir, env_password, monkeypatch
    ):
        """Existing directory output targets must be rejected before staging."""
        (workdir / "in.txt").write_bytes(b"content")
        target_dir = workdir / "target_dir"
        target_dir.mkdir()

        opened_paths = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            opened_paths.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output=str(target_dir), force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output path cannot be a directory" in err
        assert not any(".tmp." in p for p in opened_paths)

        # Path explicitly ending with separator
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output=f"{target_dir}{os.sep}", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "Output path cannot be a directory" in err
        assert not any(".tmp." in p for p in opened_paths)

    def test_long_output_basename_staging_success(
        self, workdir, env_password, monkeypatch
    ):
        """Valid long output basenames near NAME_MAX must succeed with fixed-length staging."""
        basename_240 = "a" * 240
        try:
            probe_path = workdir / basename_240
            probe_path.write_bytes(b"probe")
            probe_path.unlink()
        except OSError:
            pytest.skip("240-byte basenames not supported in this environment/filesystem")

        (workdir / "in.txt").write_bytes(b"payload 12345")
        opened_staging = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            if ".tmp." in str(path):
                opened_staging.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output=basename_240, force=False)
        )
        assert exc is None, err
        assert (workdir / basename_240).exists()
        assert len(opened_staging) == 1
        # Staging filename must be independent of the 240-byte basename (e.g. 44 bytes)
        staging_filename = os.path.basename(opened_staging[0])
        assert len(staging_filename) < 100
        assert len(staging_filename) == 44

    def test_staging_file_created_in_destination_parent_directory(
        self, workdir, env_password, monkeypatch
    ):
        """Staging files must be created in the destination's parent directory."""
        sub = workdir / "nested_dir"
        sub.mkdir()
        (workdir / "in.txt").write_bytes(b"payload")

        opened_staging = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            if ".tmp." in str(path):
                opened_staging.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        dest_file = sub / "encrypted.gun101"
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output=str(dest_file), force=False)
        )
        assert exc is None, err
        assert len(opened_staging) == 1
        staging_dir = os.path.dirname(os.path.abspath(opened_staging[0]))
        assert staging_dir == os.path.abspath(str(sub))
        assert not list(workdir.glob("*.tmp.*"))
        assert not list(workdir.parent.glob("*.tmp.*"))

    def test_staging_cleanup_after_failed_encryption_and_decryption(
        self, workdir, env_password, monkeypatch
    ):
        """Failed encryption and decryption must clean up staging files."""
        (workdir / "in.txt").write_bytes(b"payload")

        # Simulate encryption failure
        def mock_encrypt_fail(*args, **kwargs):
            raise RuntimeError("simulated encryption failure")

        monkeypatch.setattr(handler, "encrypt_stream", mock_encrypt_fail)
        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.gun101", force=False)
        )
        assert exc is not None
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]

        # Simulate decryption failure
        enc = handler.encrypt_file(b"valid", STRONG_PASSWORD)
        (workdir / "test.gun101").write_bytes(enc)
        monkeypatch.setenv("GUN101_PASSWORD", "WrongP@ssword1!")
        monkeypatch.undo()  # restore handler.encrypt_stream
        monkeypatch.setenv("GUN101_PASSWORD", "WrongP@ssword1!")

        out, err, exc = run_func(
            cli.decrypt, make_arg(file="test.gun101", keyfile=None, output="out.txt", force=False)
        )
        assert exc is not None
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]

    def test_staging_filename_fixed_length_independent_of_basename(
        self, workdir, env_password, monkeypatch
    ):
        """Staging filename must always have fixed length 44 independent of output basename."""
        (workdir / "in.txt").write_bytes(b"payload")
        opened_staging = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            if ".tmp." in str(path):
                opened_staging.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        for name in ["short.out", "somewhat_longer_filename_with_many_characters_123456789.out"]:
            opened_staging.clear()
            out, err, exc = run_func(
                cli.encrypt, make_arg(file="in.txt", keyfile=None, output=name, force=False)
            )
            assert exc is None, err
            assert len(opened_staging) == 1
            st_name = os.path.basename(opened_staging[0])
            assert len(st_name) == 44
            assert st_name.startswith(".gun101.tmp.")

    def test_normal_encryption_and_decryption_works(
        self, workdir, env_password
    ):
        """End-to-end encryption and decryption must succeed and preserve exact content."""
        payload = b"Hello, world! Safe staging test.\n" * 100
        (workdir / "plain.txt").write_bytes(payload)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="plain.txt", keyfile=None, output="plain.gun101", force=False)
        )
        assert exc is None, err
        assert (workdir / "plain.gun101").exists()

        out, err, exc = run_func(
            cli.decrypt, make_arg(file="plain.gun101", keyfile=None, output="decrypted.txt", force=False)
        )
        assert exc is None, err
        assert (workdir / "decrypted.txt").read_bytes() == payload

    def test_encrypt_fdopen_failure_closes_fd_and_cleans_up(
        self, workdir, env_password, monkeypatch
    ):
        """If os.fdopen fails in encrypt(), the specific temp_fd is closed and staging file removed."""
        (workdir / "in.txt").write_bytes(b"content")

        opened_staging_fds = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if ".tmp." in str(path):
                opened_staging_fds.append(fd)
            return fd

        monkeypatch.setattr(os, "open", spy_open)

        closed_fds = []
        real_close = os.close

        def spy_close(fd):
            closed_fds.append(fd)
            return real_close(fd)

        monkeypatch.setattr(os, "close", spy_close)

        def mock_fdopen(fd, mode="r", *args, **kwargs):
            raise OSError("simulated fdopen failure")

        monkeypatch.setattr(os, "fdopen", mock_fdopen)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.gun101", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "simulated fdopen failure" in err
        assert len(opened_staging_fds) == 1
        # Specifically verify the temporary staging descriptor was closed
        assert opened_staging_fds[0] in closed_fds
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]

    def test_decrypt_fdopen_failure_closes_fd_and_cleans_up(
        self, workdir, env_password, monkeypatch
    ):
        """If os.fdopen fails in decrypt(), the specific temp_fd is closed and staging file removed."""
        enc = handler.encrypt_file(b"content", STRONG_PASSWORD)
        (workdir / "in.txt.gun101").write_bytes(enc)

        opened_staging_fds = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if ".tmp." in str(path):
                opened_staging_fds.append(fd)
            return fd

        monkeypatch.setattr(os, "open", spy_open)

        closed_fds = []
        real_close = os.close

        def spy_close(fd):
            closed_fds.append(fd)
            return real_close(fd)

        monkeypatch.setattr(os, "close", spy_close)

        def mock_fdopen(fd, mode="r", *args, **kwargs):
            raise OSError("simulated fdopen failure")

        monkeypatch.setattr(os, "fdopen", mock_fdopen)

        out, err, exc = run_func(
            cli.decrypt, make_arg(file="in.txt.gun101", keyfile=None, output="out.txt", force=False)
        )
        assert exc is not None and exc.code == 1
        assert "simulated fdopen failure" in err
        assert len(opened_staging_fds) == 1
        # Specifically verify the temporary staging descriptor was closed
        assert opened_staging_fds[0] in closed_fds
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]

    def test_encrypt_keyboard_interrupt_cleans_up_staging_and_raises(
        self, workdir, env_password, monkeypatch
    ):
        """KeyboardInterrupt during encryption must clean up staging file and re-raise."""
        (workdir / "in.txt").write_bytes(b"content")

        def mock_encrypt_interrupt(*args, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(handler, "encrypt_stream", mock_encrypt_interrupt)

        with pytest.raises(KeyboardInterrupt):
            cli.encrypt(make_arg(file="in.txt", keyfile=None, output="out.gun101", force=False))

        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]
        assert not (workdir / "out.gun101").exists()

    def test_decrypt_keyboard_interrupt_cleans_up_staging_and_raises(
        self, workdir, env_password, monkeypatch
    ):
        """KeyboardInterrupt during decryption must clean up staging file and re-raise."""
        enc = handler.encrypt_file(b"content", STRONG_PASSWORD)
        (workdir / "in.txt.gun101").write_bytes(enc)

        def mock_decrypt_interrupt(*args, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(handler, "decrypt_stream", mock_decrypt_interrupt)

        with pytest.raises(KeyboardInterrupt):
            cli.decrypt(make_arg(file="in.txt.gun101", keyfile=None, output="out.txt", force=False))

        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]
        assert not (workdir / "out.txt").exists()

    def test_decrypt_keyboard_interrupt_preserves_existing_destination_with_force(
        self, workdir, env_password, monkeypatch
    ):
        """KeyboardInterrupt with force=True must not delete the existing destination file."""
        enc = handler.encrypt_file(b"content", STRONG_PASSWORD)
        (workdir / "in.txt.gun101").write_bytes(enc)
        existing_dest = workdir / "out.txt"
        existing_dest.write_bytes(b"PRESERVE THIS EXISTING CONTENT")

        def mock_decrypt_interrupt(*args, **kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(handler, "decrypt_stream", mock_decrypt_interrupt)

        with pytest.raises(KeyboardInterrupt):
            cli.decrypt(make_arg(file="in.txt.gun101", keyfile=None, output="out.txt", force=True))

        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]
        assert existing_dest.exists()
        assert existing_dest.read_bytes() == b"PRESERVE THIS EXISTING CONTENT"

    def test_encrypt_keyboard_interrupt_after_replace_preserves_published_output(
        self, workdir, env_password, monkeypatch
    ):
        """KeyboardInterrupt immediately after os.replace() must not delete the published output."""
        (workdir / "in.txt").write_bytes(b"important payload")

        real_publish = cli._publish_staging_file

        def publish_and_interrupt(src, dst, force=False):
            real_publish(src, dst, force=force)
            raise KeyboardInterrupt("simulated interrupt after replace")

        monkeypatch.setattr(cli, "_publish_staging_file", publish_and_interrupt)

        with pytest.raises(KeyboardInterrupt):
            cli.encrypt(make_arg(file="in.txt", keyfile=None, output="out.gun101", force=False))

        # Staging file is gone
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]
        # Published file exists and has non-zero size
        out_file = workdir / "out.gun101"
        assert out_file.exists()
        assert out_file.stat().st_size > 0

    def test_decrypt_keyboard_interrupt_after_replace_preserves_published_output(
        self, workdir, env_password, monkeypatch
    ):
        """KeyboardInterrupt immediately after os.replace() in decrypt() must not delete published output."""
        payload = b"top secret decrypted payload"
        enc = handler.encrypt_file(payload, STRONG_PASSWORD)
        (workdir / "in.txt.gun101").write_bytes(enc)

        real_publish = cli._publish_staging_file

        def publish_and_interrupt(src, dst, force=False):
            real_publish(src, dst, force=force)
            raise KeyboardInterrupt("simulated interrupt after replace")

        monkeypatch.setattr(cli, "_publish_staging_file", publish_and_interrupt)

        with pytest.raises(KeyboardInterrupt):
            cli.decrypt(make_arg(file="in.txt.gun101", keyfile=None, output="out.txt", force=False))

        # Staging file is gone
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]
        # Published file exists and contains exact plaintext
        out_file = workdir / "out.txt"
        assert out_file.exists()
        assert out_file.read_bytes() == payload

    def test_encrypt_cleanup_preserves_destination_replaced_during_failure(
        self, workdir, env_password, monkeypatch
    ):
        """Cleanup must never delete a destination file replaced by another process."""
        (workdir / "in.txt").write_bytes(b"payload")
        victim_file = workdir / "out.gun101"

        def publish_and_fail(src, dst, force=False):
            # Another process creates/replaces destination before cleanup
            victim_file.write_bytes(b"VICTIM DATA DO NOT DELETE")
            raise OSError("simulated rename failure")

        monkeypatch.setattr(cli, "_publish_staging_file", publish_and_fail)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.gun101", force=False)
        )

        assert exc is not None and exc.code == 1
        assert "simulated rename failure" in err
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]
        assert victim_file.exists()
        assert victim_file.read_bytes() == b"VICTIM DATA DO NOT DELETE"

    def test_decrypt_cleanup_preserves_destination_replaced_during_failure(
        self, workdir, env_password, monkeypatch
    ):
        """Decrypt cleanup must never delete a destination file replaced by another process."""
        enc = handler.encrypt_file(b"payload", STRONG_PASSWORD)
        (workdir / "in.txt.gun101").write_bytes(enc)
        victim_file = workdir / "out.txt"

        def publish_and_fail(src, dst, force=False):
            # Another process creates/replaces destination before cleanup
            victim_file.write_bytes(b"CRITICAL VICTIM DATA")
            raise OSError("simulated rename failure")

        monkeypatch.setattr(cli, "_publish_staging_file", publish_and_fail)

        out, err, exc = run_func(
            cli.decrypt, make_arg(file="in.txt.gun101", keyfile=None, output="out.txt", force=False)
        )

        assert exc is not None and exc.code == 1
        assert "simulated rename failure" in err
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]
        assert victim_file.exists()
        assert victim_file.read_bytes() == b"CRITICAL VICTIM DATA"

    def test_encrypt_concurrent_destination_creation_not_overwritten(
        self, workdir, env_password, monkeypatch
    ):
        """Destination created concurrently between validation and publication must not be overwritten."""
        (workdir / "in.txt").write_bytes(b"plaintext payload to encrypt")
        target_out = workdir / "out.gun101"

        real_publish = cli._publish_staging_file

        def raced_publish(staging_path, output_path, force=False):
            # Simulate a concurrent process creating the target right before publication
            target_out.write_bytes(b"CONCURRENT PROCESS CONTENT - DO NOT CLOBBER")
            return real_publish(staging_path, output_path, force=force)

        monkeypatch.setattr(cli, "_publish_staging_file", raced_publish)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.gun101", force=False)
        )

        assert exc is not None and exc.code == 1
        assert "already exists" in err
        # The concurrently created file must be preserved completely untouched
        assert target_out.exists()
        assert target_out.read_bytes() == b"CONCURRENT PROCESS CONTENT - DO NOT CLOBBER"
        # Staging file was cleaned up
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]

    def test_decrypt_concurrent_destination_creation_not_overwritten(
        self, workdir, env_password, monkeypatch
    ):
        """Decryption destination created concurrently between validation and publication must not be overwritten."""
        enc = handler.encrypt_file(b"secret plaintext", STRONG_PASSWORD)
        (workdir / "in.txt.gun101").write_bytes(enc)
        target_out = workdir / "out.txt"

        real_publish = cli._publish_staging_file

        def raced_publish(staging_path, output_path, force=False):
            # Simulate a concurrent process creating the target right before publication
            target_out.write_bytes(b"CONCURRENT VICTIM PLAINTEXT - DO NOT CLOBBER")
            return real_publish(staging_path, output_path, force=force)

        monkeypatch.setattr(cli, "_publish_staging_file", raced_publish)

        out, err, exc = run_func(
            cli.decrypt, make_arg(file="in.txt.gun101", keyfile=None, output="out.txt", force=False)
        )

        assert exc is not None and exc.code == 1
        assert "already exists" in err
        # The concurrently created file must be preserved completely untouched
        assert target_out.exists()
        assert target_out.read_bytes() == b"CONCURRENT VICTIM PLAINTEXT - DO NOT CLOBBER"
        # Staging file was cleaned up
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]

    def test_encrypt_concurrent_destination_creation_overwritten_with_force(
        self, workdir, env_password, monkeypatch
    ):
        """With force=True, publication succeeds and replaces a concurrently created destination."""
        (workdir / "in.txt").write_bytes(b"force overwrite payload")
        target_out = workdir / "out.gun101"

        real_publish = cli._publish_staging_file

        def raced_publish(staging_path, output_path, force=False):
            target_out.write_bytes(b"OLD CONTENT TO BE OVERWRITTEN")
            return real_publish(staging_path, output_path, force=force)

        monkeypatch.setattr(cli, "_publish_staging_file", raced_publish)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.gun101", force=True)
        )

        assert exc is None
        assert target_out.exists()
        assert target_out.read_bytes() != b"OLD CONTENT TO BE OVERWRITTEN"
        # Verify content is valid ciphertext that decrypts to original
        dec = handler.decrypt_file(target_out.read_bytes(), STRONG_PASSWORD)
        assert dec == b"force overwrite payload"

    @pytest.mark.parametrize("err_num", UNSUPPORTED_HARDLINK_ERRNOS)
    def test_posix_unsupported_hardlink_fails_safely_without_replace_fallback(
        self, workdir, env_password, monkeypatch, err_num
    ):
        """When hard links are unsupported on POSIX, publish must fail without falling back to os.replace()."""
        (workdir / "in.txt").write_bytes(b"content")
        target_out = workdir / "out.gun101"

        # Simulate POSIX
        monkeypatch.setattr(sys, "platform", "linux")

        replace_called = []
        real_replace = os.replace

        def spy_replace(src, dst):
            replace_called.append((src, dst))
            return real_replace(src, dst)

        def mock_link_unsupported(src, dst):
            # Simulate a concurrent process creating the target during link attempt
            target_out.write_bytes(b"EXISTING USER DATA")
            raise OSError(err_num, "Unsupported filesystem link")

        monkeypatch.setattr(os, "link", mock_link_unsupported)
        monkeypatch.setattr(os, "replace", spy_replace)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.gun101", force=False)
        )

        assert exc is not None and exc.code == 1
        assert "hard links are unsupported or prohibited" in err
        # Crucially: os.replace must NOT have been called to clobber destination without --force
        assert not replace_called
        assert target_out.read_bytes() == b"EXISTING USER DATA"
        assert not [p.name for p in workdir.iterdir() if ".tmp." in p.name]

    def test_posix_staging_unlink_failure_after_successful_link_preserves_published_output(
        self, workdir, env_password, monkeypatch
    ):
        """If os.link succeeds but unlinking the staging link fails, publication succeeds and output is kept."""
        (workdir / "in.txt").write_bytes(b"content to encrypt")
        target_out = workdir / "out.gun101"

        monkeypatch.setattr(sys, "platform", "linux")

        real_unlink = os.unlink

        def mock_link(src, dst):
            with open(src, "rb") as s, open(dst, "wb") as d:
                d.write(s.read())

        def mock_unlink(path):
            if ".tmp." in str(path):
                raise OSError("simulated staging unlink failure")
            return real_unlink(path)

        monkeypatch.setattr(os, "link", mock_link)
        monkeypatch.setattr(os, "unlink", mock_unlink)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.gun101", force=False)
        )

        assert exc is None
        assert "Encrypted file written to: out.gun101" in out
        assert target_out.exists()
        dec = handler.decrypt_file(target_out.read_bytes(), STRONG_PASSWORD)
        assert dec == b"content to encrypt"

        # Also verify decrypt succeeds when staging unlink fails after linking
        plain_out = workdir / "decrypted.txt"
        out, err, exc = run_func(
            cli.decrypt, make_arg(file="out.gun101", keyfile=None, output="decrypted.txt", force=False)
        )
        assert exc is None
        assert "Decrypted file written to: decrypted.txt" in out
        assert plain_out.exists()
        assert plain_out.read_bytes() == b"content to encrypt"

    def test_posix_unsupported_hardlink_with_force_uses_replace(
        self, workdir, env_password, monkeypatch
    ):
        """With force=True on POSIX, publication bypasses hard links and uses os.replace() directly."""
        (workdir / "in.txt").write_bytes(b"force payload")
        target_out = workdir / "out.gun101"
        target_out.write_bytes(b"OLD CONTENT")

        monkeypatch.setattr(sys, "platform", "linux")

        def mock_link_unsupported(src, dst):
            pytest.fail("os.link should not be called when force=True")

        monkeypatch.setattr(os, "link", mock_link_unsupported)

        out, err, exc = run_func(
            cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.gun101", force=True)
        )

        assert exc is None
        assert target_out.exists()
        assert target_out.read_bytes() != b"OLD CONTENT"
        dec = handler.decrypt_file(target_out.read_bytes(), STRONG_PASSWORD)
        assert dec == b"force payload"

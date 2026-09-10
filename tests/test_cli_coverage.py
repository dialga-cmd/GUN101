# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""In-process tests for the CLI, so that coverage can trace the cli module.

The existing subprocess-based CLI tests verify behavior end-to-end, but the
pytest-cov coverage tracer cannot follow code executed in subprocesses. These
tests call the cli functions directly (with GUN101_PASSWORD set) so that the
statement coverage of `cli.py` is measurable.
"""
import argparse
import contextlib
import io
import os
import sys

import pytest

from gun101 import cli, keyfile

STRONG_PASSWORD = "Str0ngP@ssw0rd!"


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Run every test inside an isolated temp working directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def env_password(monkeypatch):
    monkeypatch.setenv("GUN101_PASSWORD", STRONG_PASSWORD)
    yield
    monkeypatch.delenv("GUN101_PASSWORD", raising=False)


def make_arg(**kwargs):
    return argparse.Namespace(**kwargs)


def run(func, args):
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            func(args)
        return out.getvalue(), err.getvalue(), None
    except SystemExit as exc:
        return out.getvalue(), err.getvalue(), exc


class TestEncryptInProcess:
    def test_encrypt_success(self, workdir, env_password):
        with open("in.txt", "wb") as f:
            f.write(b"hello world")
        out, _, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output=None))
        assert exc is None
        assert "Encrypted file written to: in.txt.gun101" in out
        assert os.path.exists("in.txt.gun101")

    def test_encrypt_success_with_output(self, workdir, env_password):
        with open("in.txt", "wb") as f:
            f.write(b"data")
        out, _, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output="out.bin"))
        assert exc is None
        assert "out.bin" in out
        assert os.path.exists("out.bin")

    def test_encrypt_read_failure(self, workdir, env_password):
        _, err, exc = run(cli.encrypt, make_arg(file="missing.txt", keyfile=None, output=None))
        assert exc is not None and exc.code == 1
        assert "Error reading file" in err

    def test_encrypt_weak_password_fails(self, workdir, monkeypatch):
        monkeypatch.setenv("GUN101_PASSWORD", "weak")
        with open("in.txt", "wb") as f:
            f.write(b"data")
        _, err, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output=None))
        assert exc is not None and exc.code == 1
        assert "at least 10 characters" in err

    def test_encrypt_output_symlink_rejected(self, workdir, env_password):
        with open("in.txt", "wb") as f:
            f.write(b"data")
        with open("target.bin", "wb") as f:
            f.write(b"x")
        os.symlink("target.bin", "link.bin")
        _, err, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output="link.bin"))
        assert exc is not None and exc.code == 1
        assert "symlink" in err

    def test_encrypt_output_escape_rejected(self, workdir, env_password):
        with open("in.txt", "wb") as f:
            f.write(b"data")
        _, err, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile=None, output="../escape.bin"))
        assert exc is not None and exc.code == 1
        assert "escape" in err

    def test_encrypt_keyfile_roundtrip(self, workdir, env_password):
        keyfile.generate_keyfile("kf")
        with open("in.txt", "wb") as f:
            f.write(b"secret")
        out, _, exc = run(cli.encrypt, make_arg(file="in.txt", keyfile="kf", output=None))
        assert exc is None
        assert "in.txt.gun101" in out
        out, _, exc = run(cli.decrypt, make_arg(file="in.txt.gun101", keyfile="kf", output="out.txt"))
        assert exc is None
        with open("out.txt", "rb") as f:
            assert f.read() == b"secret"


class TestDecryptInProcess:
    def _encrypt(self, name="todo.txt"):
        with open(name, "wb") as f:
            f.write(b"payload")
        run(cli.encrypt, make_arg(file=name, keyfile=None, output=None))
        return name + ".gun101"

    def test_decrypt_success(self, workdir, env_password):
        enc = self._encrypt()
        out, _, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output="restored.txt"))
        assert exc is None
        assert "restored.txt" in out
        with open("restored.txt", "rb") as f:
            assert f.read() == b"payload"

    def test_decrypt_default_extension(self, workdir, env_password):
        enc = self._encrypt()
        out, _, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output=None))
        assert exc is None
        assert "todo.txt" in out
        assert os.path.exists("todo.txt")

    def test_decrypt_default_decrypted_suffix(self, workdir, env_password):
        with open("data.bin", "wb") as f:
            f.write(b"payload")
        run(cli.encrypt, make_arg(file="data.bin", keyfile=None, output=None))
        os.rename("data.bin.gun101", "container.custom")
        out, _, exc = run(cli.decrypt, make_arg(file="container.custom", keyfile=None, output=None))
        assert exc is None
        assert "container.custom.decrypted" in out
        assert os.path.exists("container.custom.decrypted")

    def test_decrypt_wrong_password_fails(self, workdir, env_password, monkeypatch):
        enc = self._encrypt()
        monkeypatch.setenv("GUN101_PASSWORD", "Different1!Pass")
        _, err, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output="x.txt"))
        assert exc is not None and exc.code == 1
        assert "Decryption failed" in err

    def test_decrypt_read_failure(self, workdir, env_password):
        _, err, exc = run(cli.decrypt, make_arg(file="missing.gun101", keyfile=None, output=None))
        assert exc is not None and exc.code == 1
        assert "Error reading file" in err

    def test_decrypt_output_symlink_rejected(self, workdir, env_password):
        enc = self._encrypt()
        with open("t.bin", "wb") as f:
            f.write(b"x")
        os.symlink("t.bin", "link.bin")
        _, err, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output="link.bin"))
        assert exc is not None and exc.code == 1
        assert "symlink" in err

    def test_decrypt_output_escape_rejected(self, workdir, env_password):
        enc = self._encrypt()
        _, err, exc = run(cli.decrypt, make_arg(file=enc, keyfile=None, output="../escape.txt"))
        assert exc is not None and exc.code == 1
        assert "escape" in err


class TestGenerateKeyfileInProcess:
    def test_generate_success(self, workdir):
        out, _, exc = run(cli.generate_keyfile, make_arg(path="kf"))
        assert exc is None
        assert "Keyfile generated at: kf" in out
        assert "Fingerprint (SHA-256):" in out
        assert os.path.exists("kf")

    def test_generate_existing_fails(self, workdir):
        with open("kf", "wb") as f:
            f.write(b"0" * 32)
        _, err, exc = run(cli.generate_keyfile, make_arg(path="kf"))
        assert exc is not None and exc.code == 1
        assert "already exists" in err

    def test_generate_symlink_rejected(self, workdir):
        os.symlink("nonexistent-target", "link")
        _, err, exc = run(cli.generate_keyfile, make_arg(path="link"))
        assert exc is not None and exc.code == 1
        assert "symlink" in err

    def test_generate_escape_rejected(self, workdir):
        _, err, exc = run(cli.generate_keyfile, make_arg(path="../outside.kf"))
        assert exc is not None and exc.code == 1
        assert "escape" in err


class TestKeyfileFingerprintInProcess:
    def test_fingerprint_success(self, workdir):
        keyfile.generate_keyfile("kf")
        out, _, exc = run(cli.keyfile_fingerprint, make_arg(path="kf"))
        assert exc is None
        assert "Fingerprint (SHA-256):" in out

    def test_fingerprint_missing_file_fails(self, workdir):
        _, err, exc = run(cli.keyfile_fingerprint, make_arg(path="nope"))
        assert exc is not None and exc.code == 1
        assert "Error reading keyfile" in err

    def test_fingerprint_wrong_size_fails(self, workdir):
        with open("kf", "wb") as f:
            f.write(b"short")
        _, err, exc = run(cli.keyfile_fingerprint, make_arg(path="kf"))
        assert exc is not None and exc.code == 1
        assert "Error:" in err


class TestInfoInProcess:
    def test_info_success(self):
        out, err, exc = run(cli.info, make_arg())
        assert exc is None
        assert err == ""
        lines = dict(line.split("=", 1) for line in out.strip().splitlines())
        assert lines["protocol"] == "GUN-101"
        assert lines["container_version"] == "2.1"
        assert lines["argon2_time_cost"] == "4"
        assert lines["argon2_memory_cost"] == "262144"
        assert lines["argon2_parallelism"] == "4"
        assert lines["argon2_hash_len"] == "32"
        assert lines["argon2_salt_len"] == "32"
        assert lines["cryptography_version"] != ""
        assert lines["argon2_cffi_version"] != ""
        assert lines["password_min_length"] == "10"
        assert lines["password_require_uppercase"] == "true"
        assert lines["password_require_lowercase"] == "true"
        assert lines["password_require_digit"] == "true"
        assert lines["password_require_special"] == "true"
        assert "password_policy" in lines

    def test_info_unknown_dependency_fallback(self, monkeypatch):
        import importlib.metadata

        def mock_version(pkg_name):
            raise importlib.metadata.PackageNotFoundError(pkg_name)

        monkeypatch.setattr(importlib.metadata, "version", mock_version)
        out, err, exc = run(cli.info, make_arg())
        assert exc is None
        assert err == ""
        lines = dict(line.split("=", 1) for line in out.strip().splitlines())
        assert lines["cryptography_version"] == "unknown"
        assert lines["argon2_cffi_version"] == "unknown"


def run_main():
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main()
        return out.getvalue(), err.getvalue(), None
    except SystemExit as exc:
        return out.getvalue(), err.getvalue(), exc


class TestMainDispatchInProcess:
    """Exercise main() and the argparse wiring so it is coverage-traceable."""

    def test_main_info(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["gun101", "info"])
        out, err, exc = run_main()
        assert exc is None
        assert err == ""
        assert "protocol=GUN-101" in out
        assert "container_version=2.1" in out
        assert "cryptography_version=" in out
        assert "argon2_cffi_version=" in out

    def test_main_encrypt(self, workdir, env_password, monkeypatch):
        with open("in.txt", "wb") as f:
            f.write(b"hello")
        monkeypatch.setattr(sys, "argv", ["gun101", "encrypt", "in.txt"])
        out, err, exc = run_main()
        assert exc is None
        assert os.path.exists("in.txt.gun101")

    def test_main_decrypt(self, workdir, env_password, monkeypatch):
        with open("in.txt", "wb") as f:
            f.write(b"payload")
        monkeypatch.setattr(sys, "argv", ["gun101", "encrypt", "in.txt"])
        run_main()
        monkeypatch.setattr(sys, "argv", ["gun101", "decrypt", "in.txt.gun101", "--output", "out.txt"])
        out, err, exc = run_main()
        assert exc is None
        with open("out.txt", "rb") as f:
            assert f.read() == b"payload"

    def test_main_generate_keyfile(self, workdir, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["gun101", "generate-keyfile", "my.kf"])
        out, err, exc = run_main()
        assert exc is None
        assert os.path.exists("my.kf")

    def test_main_keyfile_fingerprint(self, workdir, monkeypatch):
        keyfile.generate_keyfile("my.kf")
        monkeypatch.setattr(sys, "argv", ["gun101", "keyfile-fingerprint", "my.kf"])
        out, err, exc = run_main()
        assert exc is None
        assert "Fingerprint (SHA-256):" in out

    def test_main_unknown_subcommand(self, workdir, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["gun101", "frobnicate"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2

    def test_main_encrypt_with_keyfile(self, workdir, env_password, monkeypatch):
        keyfile.generate_keyfile("kf")
        with open("in.txt", "wb") as f:
            f.write(b"secret")
        monkeypatch.setattr(
            sys, "argv", ["gun101", "encrypt", "in.txt", "--keyfile", "kf"])
        out, err, exc = run_main()
        assert exc is None
        monkeypatch.setattr(
            sys, "argv", ["gun101", "decrypt", "in.txt.gun101", "--keyfile", "kf", "--output", "out.txt"])
        out, err, exc = run_main()
        assert exc is None
        with open("out.txt", "rb") as f:
            assert f.read() == b"secret"


class TestGetPasswordPathInProcess:
    def test_prompts_when_env_not_set(self, monkeypatch):
        monkeypatch.delenv("GUN101_PASSWORD", raising=False)
        monkeypatch.setattr("getpass.getpass", lambda prompt="Password: ": "M0nkeyP@ss!")
        password = cli.get_password()
        assert password == "M0nkeyP@ss!"

    def test_generate_keyfile_oserror_branch(self, workdir):
        with open("afile", "wb") as f:
            f.write(b"x")
        _, err, exc = run(cli.generate_keyfile, make_arg(path="afile/inner.kf"))
        assert exc is not None and exc.code == 1
        assert "Error creating keyfile" in err


class TestSafeOpenWritePathContainment:
    """Tests for safe_open_write path-containment and case sensitivity (Issue #10)."""

    def test_safe_open_write_relative_path(self, workdir):
        """Relative paths within cwd should be accepted."""
        with cli.safe_open_write("relative.bin") as f:
            f.write(b"data")
        assert os.path.exists("relative.bin")

        with keyfile.safe_open_write("relative_kf.bin") as f:
            f.write(b"data")
        assert os.path.exists("relative_kf.bin")

    def test_safe_open_write_relative_escape_rejected(self, workdir):
        """Path traversal outside cwd must be rejected."""
        with pytest.raises(ValueError, match="escape"):
            cli.safe_open_write("../evil.bin")
        with pytest.raises(ValueError, match="escape"):
            keyfile.safe_open_write("../evil_kf.bin")

    def test_safe_open_write_mixed_case_path_portable(self, workdir, monkeypatch):
        """Deterministic unit-level test verifying containment uses os.path.normcase across all OSes.

        Demonstrates that paths differing only by letter case are recognized as the
        same path under containment comparison when normalized with os.path.normcase().
        """
        real_cwd = os.path.realpath(os.getcwd())
        alt_cwd = "".join(c.lower() if c.isupper() else c.upper() for c in real_cwd)

        # 1. Demonstrate that raw commonpath without case-normalization fails on differing case
        import posixpath

        posix_cwd = "/mock/work/directory"
        posix_alt_path = "/MOCK/WORK/DIRECTORY/output.bin"
        assert posixpath.commonpath([posix_alt_path, posix_cwd]) != posix_cwd
        # With case-normalization, they match as the same directory
        assert posixpath.commonpath([posix_alt_path.lower(), posix_cwd.lower()]) == posix_cwd.lower()

        # 2. Verify safe_open_write in cli and keyfile invokes os.path.normcase and accepts differing case
        normcase_recorded = []

        def tracking_normcase(p):
            normcase_recorded.append(p)
            return p.lower()

        orig_realpath = os.path.realpath

        def mock_realpath(p):
            # Return alt_cwd when resolving target files, simulating case divergence
            if os.path.basename(p) in ("portable_cli.bin", "portable_kf.bin"):
                return os.path.join(alt_cwd, os.path.basename(p))
            return orig_realpath(p)

        monkeypatch.setattr(os.path, "normcase", tracking_normcase)
        monkeypatch.setattr(os.path, "realpath", mock_realpath)

        with cli.safe_open_write("portable_cli.bin") as f:
            f.write(b"cli_data")
        assert os.path.exists("portable_cli.bin")
        assert any("portable_cli.bin" in p for p in normcase_recorded)

        normcase_recorded.clear()
        with keyfile.safe_open_write("portable_kf.bin") as f:
            f.write(b"kf_data")
        assert os.path.exists("portable_kf.bin")
        assert any("portable_kf.bin" in p for p in normcase_recorded)

    def test_safe_open_write_mixed_case_path_native(self, workdir):
        """Native filesystem test on filesystems that are case-insensitive."""
        # Detect whether the actual filesystem at the temporary test location is case-insensitive
        probe = workdir / "case_sensitivity_probe.tmp"
        probe.write_text("probe")
        is_case_insensitive = (workdir / "CASE_SENSITIVITY_PROBE.TMP").exists()
        try:
            probe.unlink()
        except OSError:
            pass

        if not is_case_insensitive:
            pytest.skip("Filesystem at test location is case-sensitive")

        real_cwd = os.path.realpath(os.getcwd())
        alt_cwd = "".join(c.lower() if c.isupper() else c.upper() for c in real_cwd)

        if not os.path.exists(alt_cwd):
            pytest.skip("Working directory path is not accessible with alternated case")

        cli_alt_path = os.path.join(alt_cwd, "alt_case_cli.bin")
        with cli.safe_open_write(cli_alt_path) as f:
            f.write(b"data")
        assert os.path.exists(cli_alt_path)

        kf_alt_path = os.path.join(alt_cwd, "alt_case_kf.bin")
        with keyfile.safe_open_write(kf_alt_path) as f:
            f.write(b"data")
        assert os.path.exists(kf_alt_path)

    def test_safe_open_write_windows_drive_letter(self, workdir):
        """Windows drive-letter handling: case-insensitive match and cross-drive escape rejection."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific drive-letter test")

        real_cwd = os.path.realpath(os.getcwd())
        drive, rest = os.path.splitdrive(real_cwd)
        if not drive:
            pytest.skip("No drive letter in cwd")

        # Same drive, opposite case (e.g. C: vs c:)
        alt_drive = drive.lower() if drive.isupper() else drive.upper()
        same_drive_path = alt_drive + rest + r"\drive_case.bin"

        with cli.safe_open_write(same_drive_path) as f:
            f.write(b"data")
        assert os.path.exists(same_drive_path)

        with keyfile.safe_open_write(same_drive_path + ".kf") as f:
            f.write(b"data")
        assert os.path.exists(same_drive_path + ".kf")

        # Different drive letter must be rejected as an escape attempt
        other_drive = "Z:" if drive.upper() != "Z:" else "Y:"
        other_drive_path = other_drive + r"\escape_drive.bin"

        with pytest.raises(ValueError, match="escape"):
            cli.safe_open_write(other_drive_path)
        with pytest.raises(ValueError, match="escape"):
            keyfile.safe_open_write(other_drive_path)

    def test_is_case_insensitive_fs_detection_and_fallback(self, workdir, monkeypatch):
        """Verify _is_case_insensitive_fs behavior across Windows, POSIX detection, and fallback."""
        # 1. On Windows, returns True
        monkeypatch.setattr(os, "name", "nt")
        assert cli._is_case_insensitive_fs(str(workdir)) is True
        assert keyfile._is_case_insensitive_fs(str(workdir)) is True

        # 2. On POSIX with successful case alternation
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setattr(os.path, "samefile", lambda a, b: True)
        monkeypatch.setattr(os.path, "exists", lambda p: True)
        assert cli._is_case_insensitive_fs(str(workdir)) is True
        assert keyfile._is_case_insensitive_fs(str(workdir)) is True

        # 3. On POSIX fallback when case alternation does not match (case-sensitive)
        monkeypatch.setattr(os.path, "samefile", lambda a, b: False)
        assert cli._is_case_insensitive_fs(str(workdir)) is False
        assert keyfile._is_case_insensitive_fs(str(workdir)) is False

        # 4. Fail-closed on OSError
        def raise_oserror(a, b):
            raise OSError("permission denied")

        monkeypatch.setattr(os.path, "samefile", raise_oserror)
        assert cli._is_case_insensitive_fs(str(workdir)) is False
        assert keyfile._is_case_insensitive_fs(str(workdir)) is False

    def test_safe_open_write_case_sensitive_fallback_rejects_mixed_case(self, workdir, monkeypatch):
        """When filesystem is case-sensitive, paths differing in case must be rejected as escape attempts."""
        monkeypatch.setattr(cli, "_is_case_insensitive_fs", lambda _: False)
        monkeypatch.setattr(keyfile, "_is_case_insensitive_fs", lambda _: False)
        # On Windows, ntpath.normcase lowercases and realpath canonicalizes case; simulate POSIX case divergence
        monkeypatch.setattr(os.path, "normcase", lambda p: os.fspath(p))

        real_cwd = os.path.realpath(os.getcwd())
        alt_cwd = "".join(c.lower() if c.isupper() else c.upper() for c in real_cwd)
        if alt_cwd == real_cwd:
            pytest.skip("cwd has no letters to alternate case")

        orig_realpath = os.path.realpath

        def mock_realpath(p):
            if os.path.basename(p) in ("cs_cli.bin", "cs_kf.bin"):
                return os.path.join(alt_cwd, os.path.basename(p))
            return orig_realpath(p)

        monkeypatch.setattr(os.path, "realpath", mock_realpath)

        cli_alt_path = os.path.join(alt_cwd, "cs_cli.bin")
        with pytest.raises(ValueError, match="escape"):
            cli.safe_open_write(cli_alt_path)

        kf_alt_path = os.path.join(alt_cwd, "cs_kf.bin")
        with pytest.raises(ValueError, match="escape"):
            keyfile.safe_open_write(kf_alt_path)

    def test_safe_open_write_case_insensitive_escape_rejected(self, workdir, monkeypatch):
        """On case-insensitive filesystems, paths outside cwd must still be strictly rejected."""
        monkeypatch.setattr(cli, "_is_case_insensitive_fs", lambda _: True)
        monkeypatch.setattr(keyfile, "_is_case_insensitive_fs", lambda _: True)

        with pytest.raises(ValueError, match="escape"):
            cli.safe_open_write("../OUTSIDE.BIN")
        with pytest.raises(ValueError, match="escape"):
            keyfile.safe_open_write("../OUTSIDE_KF.BIN")

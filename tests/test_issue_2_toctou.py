# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Regression tests for GitHub Issue #2: TOCTOU symlink race in safe_open_write."""

import errno
import os
import stat
import tempfile
from unittest.mock import MagicMock

import pytest

from gun101 import cli


def _can_create_symlinks() -> bool:
    """Check if the current process and platform support creating symlinks."""
    with tempfile.TemporaryDirectory() as td:
        target = os.path.join(td, "target.txt")
        link = os.path.join(td, "link.txt")
        with open(target, "wb") as f:
            f.write(b"probe")
        try:
            os.symlink(target, link)
            return True
        except (OSError, NotImplementedError):
            return False


SYMLINKS_SUPPORTED = _can_create_symlinks()
symlink_test = pytest.mark.skipif(
    not SYMLINKS_SUPPORTED,
    reason="Symlinks cannot be created in this environment (requires POSIX or Windows Developer Mode/Admin)"
)


@pytest.fixture
def run_in_tmpdir():
    """Run test inside an isolated temporary directory, restoring cwd afterwards."""
    old_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as td:
        os.chdir(td)
        try:
            yield td
        finally:
            os.chdir(old_cwd)


class TestIssue2Regression:
    """Test suite verifying the Issue #2 TOCTOU fix in safe_open_write."""

    def test_1_normal_output_path_creates_regular_file(self, run_in_tmpdir):
        """1. Normal output path still works and creates a regular file with secure permissions."""
        filename = "normal_output.bin"
        payload = b"secure payload data"

        with cli.safe_open_write(filename) as f:
            f.write(payload)

        assert os.path.exists(filename)
        with open(filename, "rb") as f:
            assert f.read() == payload

        st = os.stat(filename)
        assert stat.S_ISREG(st.st_mode)
        # On POSIX, file permissions should be 0o600 (subject to standard umask)
        if os.name != "nt":
            assert (st.st_mode & 0o777) == 0o600

    @symlink_test
    def test_2_existing_symlink_output_is_rejected(self, run_in_tmpdir):
        """2. Existing symlink output path is rejected."""
        target = "target_file.bin"
        link = "link_to_target.bin"
        with open(target, "wb") as f:
            f.write(b"initial target content")
        os.symlink(target, link)

        with pytest.raises(ValueError, match="symlink"):
            cli.safe_open_write(link)

    @symlink_test
    def test_3_symlink_cannot_receive_write(self, run_in_tmpdir):
        """3. A symlink cannot receive the write; the target file remains completely untouched."""
        sensitive_target = "sensitive_database.bin"
        initial_data = b"CONFIDENTIAL DATA DO NOT OVERWRITE"
        with open(sensitive_target, "wb") as f:
            f.write(initial_data)

        link_path = "output_pointer.bin"
        os.symlink(sensitive_target, link_path)

        with pytest.raises(ValueError, match="symlink"):
            with cli.safe_open_write(link_path) as f:
                f.write(b"MALICIOUS OVERWRITE DATA")

        # Crucial security assertion: target was not modified or truncated
        with open(sensitive_target, "rb") as f:
            assert f.read() == initial_data

    def test_4_security_failure_eloop_handled(self, run_in_tmpdir, monkeypatch):
        """4a. Security failure path: os.open raising ELOOP is caught and converted to ValueError."""
        def mock_open(*args, **kwargs):
            raise OSError(errno.ELOOP, "Too many levels of symbolic links")

        monkeypatch.setattr(os, "open", mock_open)
        with pytest.raises(ValueError, match="symlink"):
            cli.safe_open_write("any_file.bin")

    def test_4_security_failure_emlink_handled(self, run_in_tmpdir, monkeypatch):
        """4b. Security failure path: os.open raising EMLINK is caught and converted to ValueError."""
        emlink = getattr(errno, "EMLINK", 31)
        def mock_open(*args, **kwargs):
            raise OSError(emlink, "Too many links")

        monkeypatch.setattr(os, "open", mock_open)
        with pytest.raises(ValueError, match="symlink"):
            cli.safe_open_write("any_file.bin")

    def test_4_security_failure_non_regular_file_rejected(self, run_in_tmpdir, monkeypatch):
        """4c. Security failure path: fstat detecting non-regular file (e.g. FIFO) is rejected."""
        mock_stat_res = MagicMock()
        # stat.S_IFIFO indicates a FIFO / named pipe
        mock_stat_res.st_mode = stat.S_IFIFO | 0o600
        mock_stat_res.st_ino = 1234
        mock_stat_res.st_dev = 5678

        real_open = os.open
        real_close = os.close
        opened_fds = []

        def spy_open(path, flags, mode=0o777):
            fd = real_open(path, flags, mode)
            opened_fds.append(fd)
            return fd

        monkeypatch.setattr(os, "open", spy_open)
        monkeypatch.setattr(os, "fstat", lambda fd: mock_stat_res)

        with pytest.raises(ValueError, match="not a regular file"):
            cli.safe_open_write("fifo_target.bin")

        # Verify the file descriptor was safely closed
        for fd in opened_fds:
            with pytest.raises(OSError):
                real_close(fd)

    def test_4_security_failure_inode_mismatch_detected(self, run_in_tmpdir, monkeypatch):
        """4d. Security failure path: file identity change between lstat and open is rejected."""
        filename = "existing_file.bin"
        with open(filename, "wb") as f:
            f.write(b"data")

        real_fstat = os.fstat

        def spoofed_fstat(fd):
            real_st = real_fstat(fd)
            mock_st = MagicMock()
            mock_st.st_mode = real_st.st_mode
            # Spoof different inode to simulate swapped file
            mock_st.st_ino = (real_st.st_ino + 999999) if real_st.st_ino != 0 else 999999
            mock_st.st_dev = real_st.st_dev
            return mock_st

        monkeypatch.setattr(os, "fstat", spoofed_fstat)

        with pytest.raises(ValueError, match="symlink"):
            cli.safe_open_write(filename, force=True)

    def test_5_overwrite_existing_regular_file_works(self, run_in_tmpdir):
        """5. Existing regular file overwrite behavior is preserved."""
        filename = "existing_to_overwrite.bin"
        with open(filename, "wb") as f:
            f.write(b"first version of content")

        with cli.safe_open_write(filename, force=True) as f:
            f.write(b"second version of content")

        with open(filename, "rb") as f:
            assert f.read() == b"second version of content"

    def test_6_cli_encrypt_decrypt_overwrite_roundtrip(self, run_in_tmpdir, monkeypatch):
        """6. Existing regular-file CLI overwrite behavior works as intended."""
        from gun101 import handler
        password = "Str0ngP@ssw0rd!"
        monkeypatch.setenv("GUN101_PASSWORD", password)

        plain_file = "input.txt"
        with open(plain_file, "wb") as f:
            f.write(b"secret payload")

        # Encrypt once
        container1 = handler.encrypt_file(b"secret payload", password, None)
        with cli.safe_open_write("input.txt.gun101") as f:
            f.write(container1)

        # Encrypt second time (overwrite)
        container2 = handler.encrypt_file(b"updated payload", password, None)
        with cli.safe_open_write("input.txt.gun101", force=True) as f:
            f.write(container2)

        # Decrypt to output file
        with open("input.txt.gun101", "rb") as f:
            c_data = f.read()
        decrypted = handler.decrypt_file(c_data, password, None)
        assert decrypted == b"updated payload"

    @symlink_test
    def test_7_toctou_race_boundary_symlink_swapped_after_check(self, run_in_tmpdir, monkeypatch):
        """7a. Real filesystem TOCTOU race: symlink created after preliminary islink check passes."""
        target_file = "victim_target.bin"
        with open(target_file, "wb") as f:
            f.write(b"original victim content")

        symlink_path = "swapped_link.bin"

        # Hook into os.path.realpath:
        # At the time realpath is called (after preliminary islink check), create the symlink!
        # This models the exact race window where an attacker creates/swaps in the symlink.
        orig_realpath = os.path.realpath

        def racing_realpath(path):
            res = orig_realpath(path)
            if os.path.basename(path) == symlink_path and not os.path.lexists(symlink_path):
                # Attacker swaps symlink into place right during the check window!
                os.symlink(target_file, symlink_path)
            return res

        monkeypatch.setattr(os.path, "realpath", racing_realpath)

        with pytest.raises(ValueError, match="symlink"):
            cli.safe_open_write(symlink_path)

        # Confirm the victim target file was NOT touched
        with open(target_file, "rb") as f:
            assert f.read() == b"original victim content"

    def test_7_toctou_race_boundary_portable_simulation(self, run_in_tmpdir, monkeypatch):
        """7b. Portable TOCTOU race simulation: initial check is bypassed, low-level open defends."""
        # Simulate preliminary check being raced/bypassed:
        # Initial os.path.islink call returns False.
        # But low-level os.open detects ELOOP (O_NOFOLLOW) or post-open verifies symlink.
        call_count = {"islink": 0}

        def racy_islink(path):
            call_count["islink"] += 1
            if call_count["islink"] == 1:
                return False  # Attacker race: preliminary check sees no symlink
            return True  # After open, the symlink is detected

        monkeypatch.setattr(os.path, "islink", racy_islink)

        with pytest.raises(ValueError, match="symlink"):
            cli.safe_open_write("raced_path.bin")

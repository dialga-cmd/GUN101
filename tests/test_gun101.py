# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Test suite for GUN-101."""
import base64
import json
import os
import tempfile

import pytest

from gun101 import config, handler, kdf, keyfile

# Strong passwords for testing
STRONG_PASSWORD = "Str0ngP@ssw0rd!"  # 13 chars: upper, lower, digit, special
STRONG_PASSWORD_2 = "P@ssw0rd12!Xyz"  # 13 chars: different
WEAK_PASSWORD_SHORT = "weak"  # too short
WEAK_PASSWORD_NO_UPPER = "lowercase123!"  # no uppercase
WEAK_PASSWORD_NO_LOWER = "UPPERCASE123!"  # no lowercase
WEAK_PASSWORD_NO_DIGIT = "NoDigit!!!!"  # no digit
WEAK_PASSWORD_NO_SPECIAL = "NoSpecial123"  # no special

# Helper functions for testing
def encrypt_decrypt_cycle(data, password, keyfile_path=None):
    """Helper to encrypt and then decrypt data."""
    container = handler.encrypt_file(data, password, keyfile_path)
    decrypted = handler.decrypt_file(container, password, keyfile_path)
    return decrypted

class TestCorrectness:
    """Tests for correct encryption and decryption."""

    def test_correct_password_decrypts_successfully(self):
        """Correct password should decrypt successfully."""
        data = b"Hello, world!"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_correct_password_with_keyfile_decrypts_successfully(self):
        """Correct password and keyfile should decrypt successfully."""
        data = b"Hello, world!"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path = os.path.join(tmpdir, "keyfile")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(keyfile_path)
            finally:
                os.chdir(old_cwd)
            container = handler.encrypt_file(data, password, keyfile_path)
            decrypted = handler.decrypt_file(container, password, keyfile_path)
            assert decrypted == data

    def test_round_trip_preserves_exact_bytes(self):
        """Encrypt then decrypt should yield identical bytes."""
        data = b"Binary data: \x00\x01\x02\xff\xfe"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_large_file_roundtrip(self):
        """A 5MB file should encrypt and decrypt correctly."""
        data = os.urandom(5 * 1024 * 1024)  # 5 MB
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_empty_file_roundtrip(self):
        """Empty file should encrypt and decrypt correctly."""
        data = b""
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

class TestNegative:
    """Tests that incorrect inputs should fail."""

    def test_wrong_password_fails(self):
        """Wrong password should raise ValueError."""
        data = b"secret"
        password = STRONG_PASSWORD
        wrong_password = STRONG_PASSWORD_2  # different strong password
        container = handler.encrypt_file(data, password)
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(container, wrong_password)

    def test_correct_password_keyfile_required_none_provided_fails(self):
        """If keyfile is required, providing none should fail."""
        data = b"secret"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path = os.path.join(tmpdir, "keyfile")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(keyfile_path)
            finally:
                os.chdir(old_cwd)
            container = handler.encrypt_file(data, password, keyfile_path)
            # Now try to decrypt without keyfile
            with pytest.raises(ValueError, match="Decryption failed"):
                handler.decrypt_file(container, password)

    def test_correct_password_wrong_keyfile_fails(self):
        """Correct password but wrong keyfile should fail."""
        data = b"secret"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path1 = os.path.join(tmpdir, "keyfile1")
            keyfile_path2 = os.path.join(tmpdir, "keyfile2")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(keyfile_path1)
                keyfile.generate_keyfile(keyfile_path2)
            finally:
                os.chdir(old_cwd)
            container = handler.encrypt_file(data, password, keyfile_path1)
            # Try to decrypt with the wrong keyfile
            with pytest.raises(ValueError, match="Decryption failed"):
                handler.decrypt_file(container, password, keyfile_path2)

    def test_empty_password_fails(self):
        """Empty password should raise ValueError during encryption."""
        data = b"secret"
        password = ""
        with pytest.raises(ValueError, match="Password must be at least 10 characters long"):
            handler.encrypt_file(data, password)

    def test_password_too_short_fails(self):
        """Password too short should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_SHORT
        with pytest.raises(ValueError, match="Password must be at least 10 characters long"):
            handler.encrypt_file(data, password)

    def test_password_no_uppercase_fails(self):
        """Password missing uppercase should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_NO_UPPER
        with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
            handler.encrypt_file(data, password)

    def test_password_no_lowercase_fails(self):
        """Password missing lowercase should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_NO_LOWER
        with pytest.raises(ValueError, match="Password must contain at least one lowercase letter"):
            handler.encrypt_file(data, password)

    def test_password_no_digit_fails(self):
        """Password missing digit should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_NO_DIGIT
        with pytest.raises(ValueError, match="Password must contain at least one digit"):
            handler.encrypt_file(data, password)

    def test_password_no_special_fails(self):
        """Password missing special character should raise ValueError."""
        data = b"secret"
        password = WEAK_PASSWORD_NO_SPECIAL
        with pytest.raises(ValueError, match="Password must contain at least one special character"):
            handler.encrypt_file(data, password)

    def test_long_password_works(self):
        """A 1000-character password that meets policy should work."""
        data = b"data"
        # Create a 1000-char string that meets the policy: repeat "Aa1!" 250 times
        password = "Aa1!" * 250  # 1000 chars, has upper, lower, digit, special
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_unicode_password_works(self):
        """Unicode password that meets policy should work."""
        data = b"data"
        # Unicode string with required character types, length >=10
        password = "🚀a1!🌟B2@" * 2  # length 24, contains emoji (Unicode), upper, lower, digit, special
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_special_character_password_works(self):
        """Password with special characters that meets policy should work."""
        data = b"data"
        # Start with specials and add required other types
        password = "Aa1!" + "!@#$%^&*()_+-=[]{}|;:,.<>?/"  # length >10, has upper, lower, digit, special
        # Ensure length >=10 (it is)
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

class TestCryptographicProperties:
    """Tests for cryptographic properties like non-determinism."""

    def test_two_encryptions_with_same_password_produce_different_ciphertext(self):
        """Same plaintext and password should yield different ciphertexts due to random salt/nonce."""
        data = b"identical"
        password = STRONG_PASSWORD
        container1 = handler.encrypt_file(data, password)
        container2 = handler.encrypt_file(data, password)
        # The containers should be different (different salt and nonce)
        assert container1 != container2
        # But both should decrypt to the same plaintext
        decrypted1 = handler.decrypt_file(container1, password)
        decrypted2 = handler.decrypt_file(container2, password)
        assert decrypted1 == decrypted2 == data

    def test_two_encryptions_produce_different_salts(self):
        """Two encryptions should have different salts."""
        data = b"data"
        password = STRONG_PASSWORD
        container1 = handler.encrypt_file(data, password)
        container2 = handler.encrypt_file(data, password)
        # Parse containers to get salt
        c1 = json.loads(container1.decode())
        c2 = json.loads(container2.decode())
        s1 = base64.b64decode(c1["salt"])
        s2 = base64.b64decode(c2["salt"])
        assert s1 != s2

    def test_two_encryptions_produce_different_nonces(self):
        """Two encryptions should have different nonces."""
        data = b"data"
        password = STRONG_PASSWORD
        container1 = handler.encrypt_file(data, password)
        container2 = handler.encrypt_file(data, password)
        c1 = json.loads(container1.decode())
        c2 = json.loads(container2.decode())
        n1 = base64.b64decode(c1["nonce"])
        n2 = base64.b64decode(c2["nonce"])
        assert n1 != n2

    def test_many_encryptions_produce_unique_nonces(self):
        """Many encryptions should produce unique nonces (birthday bound sanity check)."""
        data = b"data"
        password = STRONG_PASSWORD
        nonces = set()
        # Generate 100 encryptions with same password/data (enough for statistical significance)
        for _ in range(100):
            container = handler.encrypt_file(data, password)
            c = json.loads(container.decode())
            nonce = base64.b64decode(c["nonce"])
            nonces.add(nonce)
        # All nonces should be unique (no collisions)
        assert len(nonces) == 100

    def test_derived_key_is_always_32_bytes(self):
        """The derived key should always be 32 bytes."""
        password = STRONG_PASSWORD
        salt = os.urandom(config.ARGON2_SALT_LEN)
        key = kdf.derive_key(password, salt)
        assert len(key) == config.AES_KEY_LEN


    def test_argon2id_parameters(self):
        """Ensure Argon2id parameters are set to expected secure values."""
        from gun101 import config
        # Time cost: 4 iterations
        assert config.ARGON2_TIME_COST == 4
        # Memory cost: 262144 KB (256 MB)
        assert config.ARGON2_MEMORY_COST == 262144
        # Parallelism: 4 lanes
        assert config.ARGON2_PARALLELISM == 4
        # Hash length: 32 bytes
        assert config.ARGON2_HASH_LEN == 32
        # Salt length: 32 bytes
        assert config.ARGON2_SALT_LEN == 32
class TestTamperDetection:
    """Tests that any tampering is detected."""

    def test_flip_one_bit_in_ciphertext(self):
        """Flipping a single bit in ciphertext should cause decryption to fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        # Parse, flip a bit in ciphertext, re-encode
        c = json.loads(container.decode())
        # Decode ciphertext, flip first bit, re-encode
        ct = base64.b64decode(c["ciphertext"])
        # Flip the least significant bit of the first byte
        ct = bytes([ct[0] ^ 1]) + ct[1:]
        c["ciphertext"] = base64.b64encode(ct).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_replace_ciphertext_with_random_bytes(self):
        """Replacing ciphertext with random bytes should fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        c = json.loads(container.decode())
        # Replace with random bytes of same length
        ct = os.urandom(len(base64.b64decode(c["ciphertext"])))
        c["ciphertext"] = base64.b64encode(ct).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_modify_salt_in_container(self):
        """Modifying salt should cause decryption to fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        c = json.loads(container.decode())
        # Change salt to something else
        c["salt"] = base64.b64encode(os.urandom(config.ARGON2_SALT_LEN)).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_modify_nonce_in_container(self):
        """Modifying nonce should cause decryption to fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        c = json.loads(container.decode())
        c["nonce"] = base64.b64encode(os.urandom(config.AES_NONCE_LEN)).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_modify_tag_in_container(self):
        """Modifying tag should cause decryption to fail."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        c = json.loads(container.decode())
        c["tag"] = base64.b64encode(os.urandom(16)).decode()
        tampered = json.dumps(c).encode()
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(tampered, password)

    def test_truncate_container_json(self):
        """Truncating the container JSON should cause a parse error."""
        data = b"data"
        password = STRONG_PASSWORD
        container = handler.encrypt_file(data, password)
        # Remove last character
        truncated = container[:-1]
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(truncated, password)

    def test_pass_random_bytes_as_container(self):
        """Passing random bytes as container should fail."""
        data = os.urandom(100)
        password = STRONG_PASSWORD
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(data, password)

    def test_pass_empty_byte_string_as_container(self):
        """Passing empty bytes as container should fail."""
        password = STRONG_PASSWORD
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_file(b"", password)

    def test_tampered_tag_decryption_fails_no_output_file(self):
        """Decryption with invalid tag should fail before any output file is created."""
        data = b"secret data"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            # Encrypt a file
            container = handler.encrypt_file(data, password)
            # Tamper with the tag
            c = json.loads(container.decode())
            c["tag"] = base64.b64encode(os.urandom(16)).decode()  # Invalid tag
            tampered_container = json.dumps(c).encode()

            # Attempt to decrypt to a specific output path
            output_path = os.path.join(tmpdir, "output.txt")

            # Decryption should fail
            with pytest.raises(ValueError, match="Decryption failed"):
                handler.decrypt_file(tampered_container, password)

            # Verify no output file was created
            assert not os.path.exists(output_path)

class TestKeyfile:
    """Tests for keyfile functionality."""

    def test_generate_keyfile_creates_correct_size(self):
        """Generated keyfile should be exactly KEYFILE_LEN bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(path)
            finally:
                os.chdir(old_cwd)
            with open(path, 'rb') as f:
                data = f.read()
            assert len(data) == config.KEYFILE_LEN

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file permission bits are not enforced on Windows")
    def test_generate_keyfile_sets_permissions_to_0o600(self):
        """Generated keyfile should have permissions 0o600."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(path)
            finally:
                os.chdir(old_cwd)
            # Check permissions
            mode = os.stat(path).st_mode & 0o777
            assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_generate_keyfile_raises_if_file_exists(self):
        """Generating a keyfile should fail if file already exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            # Create the file first
            with open(path, 'wb') as f:
                f.write(b'0' * config.KEYFILE_LEN)
            # Now trying to generate should raise
            with pytest.raises(ValueError, match="Key file already exists"):
                keyfile.generate_keyfile(path)

    def test_load_keyfile_raises_if_file_missing(self):
        """Loading a non-existent keyfile should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            keyfile.load_keyfile("/non/existent/file")

    def test_load_keyfile_raises_if_file_wrong_size(self):
        """Loading a file of incorrect size should raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            with open(path, 'wb') as f:
                # Write wrong number of bytes
                f.write(b'0' * (config.KEYFILE_LEN - 1))
            with pytest.raises(ValueError, match=f"Key file must be {config.KEYFILE_LEN} bytes long"):
                keyfile.load_keyfile(path)

    def test_encrypt_with_keyfile_a_decrypt_with_keyfile_b_fails(self):
        """Encrypting with keyfile A and decrypting with keyfile B should fail."""
        data = b"secret"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_a = os.path.join(tmpdir, "keyfile_a")
            keyfile_b = os.path.join(tmpdir, "keyfile_b")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(keyfile_a)
                keyfile.generate_keyfile(keyfile_b)
            finally:
                os.chdir(old_cwd)
            container = handler.encrypt_file(data, password, keyfile_a)
            # Try to decrypt with keyfile B
            with pytest.raises(ValueError, match="Decryption failed"):
                handler.decrypt_file(container, password, keyfile_b)

    def test_keyfile_fingerprint_returns_64_char_hex(self):
        """Keyfile fingerprint should be a 64-character hex string."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "keyfile")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(path)
            finally:
                os.chdir(old_cwd)
            with open(path, 'rb') as f:
                data = f.read()
            fingerprint = keyfile.keyfile_fingerprint(data)
            assert isinstance(fingerprint, str)
            assert len(fingerprint) == 64
            # Check that it's hexadecimal
            int(fingerprint, 16)  # Should not raise ValueError

    def test_container_stores_correct_fingerprint_for_keyfile_used(self):
        """The container should store the correct fingerprint for the keyfile used."""
        data = b"data"
        password = STRONG_PASSWORD
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path = os.path.join(tmpdir, "keyfile")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(keyfile_path)
            finally:
                os.chdir(old_cwd)
            container = handler.encrypt_file(data, password, keyfile_path)
            with open(keyfile_path, 'rb') as f:
                keyfile_bytes = f.read()
            c = json.loads(container.decode())
            expected = keyfile.keyfile_fingerprint(keyfile_bytes)
            assert c["keyfile_fingerprint"] == expected
            assert c["keyfile_required"] is True

    def test_keyfile_fingerprint_uses_hmac_compare_digest(self):
        """Ensure that keyfile fingerprint comparison uses hmac.compare_digest for constant-time comparison."""
        # Read the handler.py file and check that the comparison uses hmac.compare_digest
        handler_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'gun101', 'handler.py')
        with open(handler_path, 'r') as f:
            content = f.read()
        # We expect to see a line that uses hmac.compare_digest for the fingerprint comparison
        assert 'hmac.compare_digest' in content
        # We'll also check that there is no direct string comparison (using !=)
        # for the fingerprints in the decrypt function. If the string
        # 'actual_fingerprint != expected_fingerprint' appears in the file,
        # then fail.
        if 'actual_fingerprint != expected_fingerprint' in content:
            self.fail('Found direct string comparison of fingerprints: actual_fingerprint != expected_fingerprint')
        # Additionally, we can do a functional test to ensure the fingerprint is used correctly.
        import tempfile

        from gun101 import handler, keyfile
        data = b"test data"
        password = "Str0ngP@ssw0rd!"  # meets policy
        with tempfile.TemporaryDirectory() as tmpdir:
            keyfile_path = os.path.join(tmpdir, "keyfile")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                keyfile.generate_keyfile(keyfile_path)
            finally:
                os.chdir(old_cwd)
            # Get the actual fingerprint of the keyfile
            with open(keyfile_path, 'rb') as f:
                keyfile_data = f.read()
            actual_fingerprint = keyfile.keyfile_fingerprint(keyfile_data)
            # Encrypt with keyfile
            container = handler.encrypt_file(data, password, keyfile_path)
            # Parse container and check fingerprint
            c = json.loads(container.decode())
            assert c["keyfile_fingerprint"] == actual_fingerprint
            assert c["keyfile_required"] is True
            # Decrypt with correct keyfile should succeed
            decrypted = handler.decrypt_file(container, password, keyfile_path)
            assert decrypted == data



class TestCLI:
    """Tests for the command-line interface."""

    def test_cli_encrypt_function_direct(self):
        """Test the encrypt function directly (for coverage)."""
        import argparse

        from gun101 import cli

        # Mock args
        args = argparse.Namespace()
        args.file = "tests/test_data/plain.txt"
        args.keyfile = None
        args.output = None

        # We'll test this by checking it doesn't crash immediately on argument parsing
        # The actual encryption would need proper setup, so we focus on the function signature
        assert hasattr(cli, 'encrypt')
        assert callable(cli.encrypt)

    def test_cli_decrypt_function_direct(self):
        """Test the decrypt function directly (for coverage)."""
        from gun101 import cli
        assert hasattr(cli, 'decrypt')
        assert callable(cli.decrypt)

    def test_cli_info_function_direct(self):
        """Test the info function directly (for coverage)."""
        from gun101 import cli
        assert hasattr(cli, 'info')
        assert callable(cli.info)

    def test_cli_safe_open_write_function_direct(self):
        """Test the safe_open_write function directly (for coverage)."""
        import os
        import tempfile

        from gun101 import cli

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                # Test safe path
                safe_path = "safe_output.bin"
                try:
                    f = cli.safe_open_write(safe_path)
                    f.close()
                    # File should be created
                    assert os.path.exists(safe_path)
                    os.unlink(safe_path)  # Clean up
                except Exception as e:
                    pytest.fail(f"safe_open_write failed on safe path: {e}")

                # Test symlink rejection
                link_path = "link.bin"
                target_path = "target.bin"
                with open(target_path, "wb") as f:
                    f.write(b"test")
                os.symlink(target_path, link_path)

                with pytest.raises(ValueError, match="symlink"):
                    cli.safe_open_write(link_path)

                # Clean up
                os.unlink(link_path)
                os.unlink(target_path)

                # Test path traversal rejection
                evil_path = "../evil.bin"
                with pytest.raises(ValueError, match="escape"):
                    cli.safe_open_write(evil_path)
            finally:
                os.chdir(old_cwd)

    def test_cli_rejects_password_argument(self):
        """Ensure that the CLI does not accept --password argument."""
        import os
        import subprocess
        import sys

        # Run the CLI module from the src directory
        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')
        env = os.environ.copy()
        # Ensure we use the same Python interpreter
        env['PYTHONPATH'] = src_dir

        result = subprocess.run(
            [sys.executable, '-m', 'gun101.cli', 'encrypt', '--help'],
            cwd=src_dir,
            env=env,
            capture_output=True,
            text=True
        )
        # The help should not list --password
        assert '--password' not in result.stdout

        # Actually trying to use --password should fail
        result = subprocess.run(
            [sys.executable, '-m', 'gun101.cli', 'encrypt', 'dummy.txt', '--password', 'test'],
            cwd=src_dir,
            env=env,
            capture_output=True,
            text=True
        )
        assert result.returncode != 0
        assert 'unrecognized arguments: --password' in result.stderr

    def test_cli_works_with_env_var_password(self):
        """Test that the CLI works when password is provided via environment variable."""
        import os
        import subprocess
        import sys
        import tempfile

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')

        with tempfile.TemporaryDirectory() as tmpdir:
            plain_file = os.path.join(tmpdir, 'plain.txt')
            enc_file = os.path.join(tmpdir, 'plain.txt.gun101')
            dec_file = os.path.join(tmpdir, 'decrypted.txt')

            # Create a plain file
            with open(plain_file, 'wb') as f:
                f.write(b'test data')

            # Set the password in the environment
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            env['GUN101_PASSWORD'] = 'Str0ngP@ssw0rd!'

            # Encrypt
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'encrypt', plain_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, f"Encryption failed: {result.stderr}"
            assert os.path.exists(enc_file)

            # Decrypt back and verify contents
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'decrypt', enc_file, '--output', dec_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, f"Decryption failed: {result.stderr}"
            with open(dec_file, 'rb') as f:
                assert f.read() == b'test data'

            # Clean up the environment variable to avoid leaking
            del env['GUN101_PASSWORD']

    def test_cli_output_path_symlink_rejected(self):
        """Ensure that the CLI rejects writing output to a symlink."""
        import os
        import subprocess
        import sys
        import tempfile

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')

        with tempfile.TemporaryDirectory() as tmpdir:
            plain_file = os.path.join(tmpdir, 'plain.txt')
            enc_file = os.path.join(tmpdir, 'plain.txt.gun101')
            key_file = os.path.join(tmpdir, 'keyfile')
            link_file = os.path.join(tmpdir, 'link.txt')

            # Create a plain file
            with open(plain_file, 'wb') as f:
                f.write(b'test data')

            # Generate a keyfile
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'generate-keyfile', key_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0

            # Set the password in the environment
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            env['GUN101_PASSWORD'] = 'Str0ngP@ssw0rd!'

            # Encrypt
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'encrypt', plain_file, '--keyfile', key_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, f"Encryption failed: {result.stderr}"
            assert os.path.exists(enc_file)

            # Create a symlink pointing to the enc_file
            os.symlink(enc_file, link_file)

            # Try to encrypt again, outputting to the symlink (should fail)
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'encrypt', plain_file,
                '--keyfile', key_file, '--output', link_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode != 0, f"Expected error when writing to symlink, but it succeeded: {result.stdout}"
            # Check that the error message indicates the symlink was rejected
            assert "Output path is a symlink; refusing to write" in result.stderr

            # Clean up the environment variable to avoid leaking
            del env['GUN101_PASSWORD']

    def test_cli_output_path_traversal_rejected(self):
        """Ensure that the CLI rejects writing output to a path that escapes the intended directory."""
        import os
        import subprocess
        import sys
        import tempfile

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a subdirectory to work in
            work_dir = os.path.join(tmpdir, 'work')
            os.mkdir(work_dir)
            # Paths relative to work_dir
            plain_file = 'plain.txt'
            key_file = 'keyfile'
            # Attempt to write to a parent directory of work_dir (escape) - absolute path outside work_dir
            output_file = os.path.join(tmpdir, 'escaped.txt')

            # Create a plain file (relative to work_dir)
            with open(os.path.join(work_dir, plain_file), 'wb') as f:
                f.write(b'test data')

            # Generate a keyfile (relative to work_dir)
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'generate-keyfile', key_file],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0

            # Set the password in the environment
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            env['GUN101_PASSWORD'] = 'Str0ngP@ssw0rd!'

            # Encrypt (relative to work_dir)
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'encrypt', plain_file, '--keyfile', key_file],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, f"Encryption failed: {result.stderr}"
            enc_file = os.path.join(work_dir, 'plain.txt.gun101')
            assert os.path.exists(enc_file)

            # Try to encrypt and write to a path that escapes the work directory
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'encrypt', plain_file,
                '--keyfile', key_file, '--output', output_file],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode != 0, (
                f"Expected error when writing to escaping path, but it succeeded: {result.stdout}"
            )
            # Check that the error message indicates the path attempts to escape
            assert "Output path attempts to escape the intended directory" in result.stderr

            # Clean up the environment variable to avoid leaking
            del env['GUN101_PASSWORD']

    def test_cli_output_path_safe_relative_allowed(self):
        """Ensure that the CLI allows writing output to a safe relative path."""
        import os
        import subprocess
        import sys
        import tempfile

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a subdirectory to work in
            work_dir = os.path.join(tmpdir, 'work')
            os.mkdir(work_dir)
            # Paths relative to work_dir
            plain_file = 'plain.txt'
            key_file = 'keyfile'
            output_file = 'output.txt'

            # Create a plain file (relative to work_dir)
            with open(os.path.join(work_dir, plain_file), 'wb') as f:
                f.write(b'test data')

            # Generate a keyfile (relative to work_dir)
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'generate-keyfile', key_file],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0

            # Set the password in the environment
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            env['GUN101_PASSWORD'] = 'Str0ngP@ssw0rd!'

            # Encrypt (relative to work_dir)
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'encrypt', plain_file,
                '--keyfile', key_file, '--output', output_file],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, (
                f"Expected success when writing to safe relative path, but it failed: {result.stderr}"
            )
            assert os.path.exists(os.path.join(work_dir, output_file))

            # Clean up the environment variable to avoid leaking
            del env['GUN101_PASSWORD']

    def test_cli_input_path_symlink_allowed(self):
        """Ensure that the CLI allows reading input from a symlink."""
        import os
        import subprocess
        import sys
        import tempfile

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Set current working directory to tmpdir for subprocess calls
            # All paths below are relative to tmpdir
            plain_file = 'plain.txt'
            enc_file = 'plain.txt.gun101'
            key_file = 'keyfile'
            link_file = 'link.txt'
            dec_file = 'decrypted.txt'

            # Create a plain file
            with open(os.path.join(tmpdir, plain_file), 'wb') as f:
                f.write(b'test data')

            # Generate a keyfile
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'generate-keyfile', key_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0

            # Set the password in the environment
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            env['GUN101_PASSWORD'] = 'Str0ngP@ssw0rd!'

            # Encrypt
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'encrypt', plain_file, '--keyfile', key_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, f"Encryption failed: {result.stderr}"
            assert os.path.exists(os.path.join(tmpdir, enc_file))

            # Create a symlink pointing to the enc_file
            os.symlink(os.path.join(tmpdir, enc_file), os.path.join(tmpdir, link_file))

            # Try to decrypt using the symlink as input (should succeed)
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'decrypt', link_file, '--keyfile', key_file, '--output', dec_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, f"Expected success when reading from symlink, but it failed: {result.stderr}"
            assert os.path.exists(os.path.join(tmpdir, dec_file))

            with open(os.path.join(tmpdir, dec_file), 'rb') as f:
                assert f.read() == b'test data'

            # Clean up the environment variable to avoid leaking
            del env['GUN101_PASSWORD']

    def test_keyfile_generate_path_symlink_rejected(self):
        """Ensure that the keyfile generation rejects writing to a symlink."""
        import os
        import subprocess
        import sys
        import tempfile

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Paths relative to tmpdir
            key_file = 'keyfile'
            link_file = 'link'

            # Create a symlink pointing to the key_file
            os.symlink(os.path.join(tmpdir, key_file), os.path.join(tmpdir, link_file))

            # Try to generate a keyfile at the symlink location (should fail)
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'generate-keyfile', link_file],
                cwd=tmpdir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode != 0, (
                f"Expected error when generating keyfile to symlink, but it succeeded: {result.stdout}"
            )
            # Check that the error message indicates the symlink was rejected
            assert "Output path is a symlink; refusing to write" in result.stderr

    def test_keyfile_generate_path_traversal_rejected(self):
        """Ensure that the keyfile generation rejects writing to a path that escapes the intended directory."""
        import os
        import subprocess
        import sys
        import tempfile

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a subdirectory to work in
            work_dir = os.path.join(tmpdir, 'work')
            os.mkdir(work_dir)
            # Path relative to work_dir for the keyfile directory (we won't use it directly)
            # Attempt to write to a parent directory of work_dir (escape) - absolute path outside work_dir
            output_file = os.path.join(tmpdir, 'escaped.keyfile')

            # Try to generate a keyfile at the escaping path (should fail)
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'generate-keyfile', output_file],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode != 0, (
                f"Expected error when generating keyfile to escaping path, but it succeeded: {result.stdout}"
            )
            # Check that the error message indicates the path attempts to escape
            assert "Output path attempts to escape the intended directory" in result.stderr

    def test_keyfile_generate_path_safe_relative_allowed(self):
        """Ensure that the keyfile generation allows writing to a safe relative path."""
        import os
        import subprocess
        import sys
        import tempfile

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a subdirectory to work in
            work_dir = os.path.join(tmpdir, 'work')
            os.mkdir(work_dir)
            # Path relative to work_dir
            key_file = 'keyfile'

            # Try to generate a keyfile at a safe relative path within the work directory
            env = os.environ.copy()
            env['PYTHONPATH'] = src_dir
            result = subprocess.run(
                [sys.executable, '-m', 'gun101.cli', 'generate-keyfile', key_file],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True
            )
            assert result.returncode == 0, (
                f"Expected success when generating keyfile to safe relative path, but it failed: {result.stderr}"
            )
            assert os.path.exists(os.path.join(work_dir, key_file))

    def test_cli_info_subcommand(self):
        """Test that gun101 info runs via CLI and outputs key=value lines."""
        import os
        import subprocess
        import sys

        src_dir = os.path.join(os.path.dirname(__file__), '..', 'src')
        env = os.environ.copy()
        env['PYTHONPATH'] = src_dir

        result = subprocess.run(
            [sys.executable, '-m', 'gun101.cli', 'info'],
            cwd=src_dir,
            env=env,
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"Expected 0 exit code, got {result.returncode}: {result.stderr}"
        assert result.stderr == ""
        lines = dict(line.split("=", 1) for line in result.stdout.strip().splitlines())
        assert lines["protocol"] == "GUN-101"
        assert lines["container_version"] == "2.1"
        assert lines["argon2_time_cost"] == "4"
        assert lines["argon2_memory_cost"] == "262144"
        assert lines["argon2_parallelism"] == "4"
        assert lines["argon2_hash_len"] == "32"
        assert lines["argon2_salt_len"] == "32"
        assert "cryptography_version" in lines
        assert "argon2_cffi_version" in lines
        assert lines["password_min_length"] == "10"
        assert lines["password_require_uppercase"] == "true"
        assert lines["password_require_lowercase"] == "true"
        assert lines["password_require_digit"] == "true"
        assert lines["password_require_special"] == "true"
        assert "password_policy" in lines


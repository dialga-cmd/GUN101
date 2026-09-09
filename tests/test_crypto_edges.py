# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Coverage for the validation branches of the crypto modules."""
import base64
import json
import os

import pytest

from gun101 import cipher, config, handler, kdf

KEY = b"k" * config.AES_KEY_LEN
NONCE = b"n" * config.AES_NONCE_LEN
SALT = b"s" * config.ARGON2_SALT_LEN


class TestCipherValidation:
    def test_encrypt_rejects_short_key(self):
        with pytest.raises(ValueError, match="Key must be"):
            cipher.encrypt(b"data", b"short", NONCE)

    def test_encrypt_rejects_short_nonce(self):
        with pytest.raises(ValueError, match="Nonce must be"):
            cipher.encrypt(b"data", KEY, b"short")

    def test_encrypt_rejects_non_bytes_plaintext(self):
        with pytest.raises(ValueError, match="Plaintext must be bytes"):
            cipher.encrypt("text", KEY, NONCE)

    def test_encrypt_rejects_non_bytes_aad(self):
        with pytest.raises(ValueError, match="Associated data must be bytes"):
            cipher.encrypt(b"data", KEY, NONCE, associated_data="header")

    def test_decrypt_rejects_short_key(self):
        with pytest.raises(ValueError, match="Key must be"):
            cipher.decrypt(NONCE, b"ct", b"t" * 16, b"short")

    def test_decrypt_rejects_short_nonce(self):
        with pytest.raises(ValueError, match="Nonce must be"):
            cipher.decrypt(b"short", b"ct", b"t" * 16, KEY)

    def test_decrypt_rejects_non_bytes_ciphertext(self):
        with pytest.raises(ValueError, match="Ciphertext must be bytes"):
            cipher.decrypt(NONCE, "ct", b"t" * 16, KEY)

    def test_decrypt_rejects_bad_tag_length(self):
        with pytest.raises(ValueError, match="Tag must be 16 bytes"):
            cipher.decrypt(NONCE, b"ct", b"short", KEY)

    def test_decrypt_rejects_non_bytes_aad(self):
        with pytest.raises(ValueError, match="Associated data must be bytes"):
            cipher.decrypt(NONCE, b"ct", b"t" * 16, KEY, associated_data="header")

    def test_decrypt_wrong_tag_fails_generic(self):
        ct, tag = cipher.encrypt(b"data", KEY, NONCE, None)
        with pytest.raises(ValueError, match="Decryption failed"):
            cipher.decrypt(NONCE, ct, b"x" * 16, KEY, None)


class TestKdfValidation:
    def test_derive_key_rejects_empty_password(self):
        with pytest.raises(ValueError, match="Password must be a non-empty string"):
            kdf.derive_key("", SALT)

    def test_derive_key_rejects_bad_salt_length(self):
        with pytest.raises(ValueError, match="Salt must be"):
            kdf.derive_key("Str0ngP@ssw0rd!", b"short")

    def test_derive_key_rejects_bad_keyfile_length(self):
        with pytest.raises(ValueError, match="Keyfile must be"):
            kdf.derive_key("Str0ngP@ssw0rd!", SALT, b"short")


class TestHandlerValidation:
    def test_encrypt_file_rejects_non_bytes(self):
        with pytest.raises(ValueError, match="File data must be bytes"):
            handler.encrypt_file("text", "Str0ngP@ssw0rd!")

    def test_decrypt_file_rejects_altered_salt_length(self):
        data = b"payload"
        password = "P" * 4 + "a" * 4 + "1" * 4 + "!"

        container = handler.encrypt_file(data, password)
        parsed = json.loads(container.decode())
        parsed["salt"] = base64.b64encode(b"short").decode()
        tampered = json.dumps(parsed).encode()
        with pytest.raises(ValueError, match="Salt must be"):
            handler.decrypt_file(tampered, password)

    def test_encrypt_key_material(self):
        """Sanity check: filling the SALT/KEY constants is internally consistent."""
        assert len(SALT) == config.ARGON2_SALT_LEN
        assert len(KEY) == config.AES_KEY_LEN
        assert len(NONCE) == config.AES_NONCE_LEN


class TestDecryptPasswordPolicyRegression:
    """Regression tests for GitHub Issue #4:
    decrypt should NOT enforce the password policy and should allow containers
    created with older/shorter passwords to be decrypted.
    """

    def test_decrypt_container_with_older_shorter_password(self, monkeypatch):
        """A container created using an older/shorter password policy can still be decrypted."""
        data = b"secret legacy message"
        short_password = "short"

        # Simulate creation of a container under an older/shorter password policy
        monkeypatch.setattr(handler, "validate_password", lambda p: None)
        container = handler.encrypt_file(data, short_password)
        monkeypatch.undo()

        # Decryption does not validate password policy, successfully decrypts
        decrypted = handler.decrypt_file(container, short_password)
        assert decrypted == data

    def test_decrypt_v20_container_with_legacy_password(self):
        """A legacy v2.0 container created with a shorter password decrypts cleanly."""
        data = b"v2.0 legacy payload"
        legacy_password = "oldpwd"
        salt = os.urandom(config.ARGON2_SALT_LEN)
        nonce = os.urandom(config.AES_NONCE_LEN)
        key = kdf.derive_key(legacy_password, salt)
        ciphertext, tag = cipher.encrypt(data, key, nonce, None)

        container_dict = {
            "protocol": config.PROTOCOL,
            "version": "2.0",
            "keyfile_required": False,
            "keyfile_fingerprint": None,
            "salt": base64.b64encode(salt).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }
        container = json.dumps(container_dict).encode("utf-8")
        decrypted = handler.decrypt_file(container, legacy_password)
        assert decrypted == data

    def test_decrypt_current_policy_password_succeeds(self):
        """A normal current-policy encrypted container still decrypts successfully."""
        data = b"modern payload"
        password = "P" * 4 + "a" * 4 + "1" * 4 + "!"
        container = handler.encrypt_file(data, password)
        decrypted = handler.decrypt_file(container, password)
        assert decrypted == data

    def test_decrypt_incorrect_password_fails_generic_error(self):
        """An incorrect password still fails with the existing generic 'Decryption failed' error."""
        data = b"confidential payload"
        password = "P" * 4 + "a" * 4 + "1" * 4 + "!"
        container = handler.encrypt_file(data, password)

        # Wrong strong password fails with generic "Decryption failed"
        with pytest.raises(ValueError, match="^Decryption failed$"):
            handler.decrypt_file(container, "W" * 4 + "o" * 4 + "2" * 4 + "@")

        # Wrong short password (violating policy) must also fail with generic "Decryption failed",
        # NOT a password policy ValueError
        with pytest.raises(ValueError, match="^Decryption failed$"):
            handler.decrypt_file(container, "wrong")

    def test_encrypt_still_rejects_policy_violating_passwords(self):
        """Encryption still enforces the current password policy."""
        data = b"payload"
        # Too short
        with pytest.raises(ValueError, match="Password must be at least 10 characters long"):
            handler.encrypt_file(data, "Sh0rt!")
        # Missing uppercase
        with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
            handler.encrypt_file(data, "lowercasewithdigit1!")
        # Missing lowercase
        with pytest.raises(ValueError, match="Password must contain at least one lowercase letter"):
            handler.encrypt_file(data, "UPPERCASEWITHDIGIT1!")
        # Missing digit
        with pytest.raises(ValueError, match="Password must contain at least one digit"):
            handler.encrypt_file(data, "NoDigitsHereEver!")
        # Missing special char
        with pytest.raises(ValueError, match="Password must contain at least one special character"):
            handler.encrypt_file(data, "NoSpecialChar1234")

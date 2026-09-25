# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Tests for bounded-memory streaming encryption and decryption."""
import argparse
import base64
import contextlib
import io
import json
import os

import pytest

from gun101 import cipher, cli, config, handler, kdf, keyfile

STRONG_PASSWORD = "Str0ngP@ssw0rd!"
STRONG_PASSWORD_2 = "Diff3rent!P@ss"


@pytest.fixture(autouse=True, scope="module")
def setup_fast_kdf():
    """Use fast KDF parameters to keep the streaming test suite fast."""
    orig_mem = config.ARGON2_MEMORY_COST
    orig_time = config.ARGON2_TIME_COST
    orig_par = config.ARGON2_PARALLELISM

    config.ARGON2_MEMORY_COST = 8
    config.ARGON2_TIME_COST = 1
    config.ARGON2_PARALLELISM = 1
    yield
    config.ARGON2_MEMORY_COST = orig_mem
    config.ARGON2_TIME_COST = orig_time
    config.ARGON2_PARALLELISM = orig_par


def make_arg(**kwargs):
    return argparse.Namespace(**kwargs)


def run_cli(func, args):
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            func(args)
        return out.getvalue(), err.getvalue(), None
    except SystemExit as exc:
        return out.getvalue(), err.getvalue(), exc


class TrackingStream(io.BytesIO):
    """Stream wrapper that monitors maximum buffer size read or written."""

    def __init__(self, initial_bytes=b""):
        super().__init__(initial_bytes)
        self.max_read_size = 0
        self.max_write_size = 0

    def read(self, size=-1):
        if size is not None and size > self.max_read_size:
            self.max_read_size = size
        return super().read(size)

    def write(self, b):
        if len(b) > self.max_write_size:
            self.max_write_size = len(b)
        return super().write(b)


class TestCipherStreaming:
    """Unit tests for StreamEncryptor and StreamDecryptor in cipher.py."""

    def test_stream_encryptor_decryptor_roundtrip(self):
        key = os.urandom(config.AES_KEY_LEN)
        nonce = os.urandom(config.AES_NONCE_LEN)
        aad = b"authenticated header data"
        data = b"Streaming cipher payload block test" * 50

        encryptor = cipher.StreamEncryptor(key, nonce, aad)
        ct1 = encryptor.update(data[:25])
        ct2 = encryptor.update(data[25:])
        final_ct, tag = encryptor.finalize()
        full_ct = ct1 + ct2 + final_ct

        # Decrypt with tag provided upfront
        decryptor = cipher.StreamDecryptor(key, nonce, tag=tag, associated_data=aad)
        pt1 = decryptor.update(full_ct[:30])
        pt2 = decryptor.update(full_ct[30:])
        final_pt = decryptor.finalize()
        assert pt1 + pt2 + final_pt == data

        # Decrypt with tag provided at finalization
        decryptor2 = cipher.StreamDecryptor(key, nonce, tag=None, associated_data=aad)
        pt = decryptor2.update(full_ct)
        final_pt2 = decryptor2.finalize(tag)
        assert pt + final_pt2 == data

    def test_stream_cipher_matches_oneshot(self):
        key = os.urandom(config.AES_KEY_LEN)
        nonce = os.urandom(config.AES_NONCE_LEN)
        aad = b"aad test"
        data = os.urandom(1024)

        # One-shot
        oneshot_ct, oneshot_tag = cipher.encrypt(data, key, nonce, aad)

        # Streaming
        encryptor = cipher.StreamEncryptor(key, nonce, aad)
        ct = encryptor.update(data)
        final_ct, tag = encryptor.finalize()
        assert ct + final_ct == oneshot_ct
        assert tag == oneshot_tag

    def test_stream_encryptor_validation(self):
        key = os.urandom(config.AES_KEY_LEN)
        nonce = os.urandom(config.AES_NONCE_LEN)

        with pytest.raises(ValueError, match="Key must be"):
            cipher.StreamEncryptor(b"short", nonce)
        with pytest.raises(ValueError, match="Nonce must be"):
            cipher.StreamEncryptor(key, b"short")
        with pytest.raises(ValueError, match="Associated data must be bytes"):
            cipher.StreamEncryptor(key, nonce, associated_data="not-bytes")

        enc = cipher.StreamEncryptor(key, nonce)
        with pytest.raises(ValueError, match="Plaintext must be bytes"):
            enc.update("text")

    def test_stream_decryptor_validation(self):
        key = os.urandom(config.AES_KEY_LEN)
        nonce = os.urandom(config.AES_NONCE_LEN)
        tag = os.urandom(16)

        with pytest.raises(ValueError, match="Key must be"):
            cipher.StreamDecryptor(b"short", nonce, tag)
        with pytest.raises(ValueError, match="Nonce must be"):
            cipher.StreamDecryptor(key, b"short", tag)
        with pytest.raises(ValueError, match="Tag must be 16 bytes"):
            cipher.StreamDecryptor(key, nonce, tag=b"short")
        with pytest.raises(ValueError, match="Associated data must be bytes"):
            cipher.StreamDecryptor(key, nonce, tag, associated_data="not-bytes")

        dec = cipher.StreamDecryptor(key, nonce, tag)
        with pytest.raises(ValueError, match="Ciphertext must be bytes"):
            dec.update("not-bytes")

        dec_notag = cipher.StreamDecryptor(key, nonce)
        with pytest.raises(ValueError, match="Tag must be 16 bytes"):
            dec_notag.finalize(b"bad-length")

    def test_stream_decryptor_tamper_fails(self):
        key = os.urandom(config.AES_KEY_LEN)
        nonce = os.urandom(config.AES_NONCE_LEN)
        aad = b"header"
        data = b"payload"

        encryptor = cipher.StreamEncryptor(key, nonce, aad)
        ct = encryptor.update(data)
        final_ct, tag = encryptor.finalize()
        full_ct = ct + final_ct

        # Tampered tag
        decryptor = cipher.StreamDecryptor(key, nonce, tag=os.urandom(16), associated_data=aad)
        decryptor.update(full_ct)
        with pytest.raises(ValueError, match="Decryption failed"):
            decryptor.finalize()

        # Tampered ciphertext
        tampered_ct = bytes([full_ct[0] ^ 1]) + full_ct[1:]
        decryptor2 = cipher.StreamDecryptor(key, nonce, tag=tag, associated_data=aad)
        decryptor2.update(tampered_ct)
        with pytest.raises(ValueError, match="Decryption failed"):
            decryptor2.finalize()

        # Tampered AAD
        decryptor3 = cipher.StreamDecryptor(key, nonce, tag=tag, associated_data=b"wrong-aad")
        decryptor3.update(full_ct)
        with pytest.raises(ValueError, match="Decryption failed"):
            decryptor3.finalize()


class TestHandlerStreaming:
    """Tests for handler.encrypt_stream and handler.decrypt_stream."""

    @pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 63, 64, 65, 500, 4096, 65536, 131072])
    def test_stream_roundtrip_various_sizes(self, size):
        data = os.urandom(size)
        in_stream = io.BytesIO(data)
        enc_stream = io.BytesIO()

        handler.encrypt_stream(in_stream, enc_stream, STRONG_PASSWORD, chunk_size=128)
        enc_bytes = enc_stream.getvalue()

        dec_stream = io.BytesIO()
        handler.decrypt_stream(io.BytesIO(enc_bytes), dec_stream, STRONG_PASSWORD, chunk_size=128)
        assert dec_stream.getvalue() == data

    @pytest.mark.parametrize("chunk_size", [1, 2, 3, 4, 7, 16, 64, 512, 4096])
    def test_stream_roundtrip_arbitrary_chunk_sizes(self, chunk_size):
        data = b"Testing arbitrary chunk sizes for Base64 and AES buffering." * 10
        in_stream = io.BytesIO(data)
        enc_stream = io.BytesIO()

        handler.encrypt_stream(in_stream, enc_stream, STRONG_PASSWORD, chunk_size=chunk_size)
        dec_stream = io.BytesIO()
        handler.decrypt_stream(io.BytesIO(enc_stream.getvalue()), dec_stream, STRONG_PASSWORD, chunk_size=chunk_size)
        assert dec_stream.getvalue() == data

    def test_cross_compatibility_oneshot_encrypt_stream_decrypt(self):
        """Container produced by handler.encrypt_file must decrypt with handler.decrypt_stream."""
        data = b"Cross-compatibility test data: oneshot to stream" * 20
        container_bytes = handler.encrypt_file(data, STRONG_PASSWORD)

        out_stream = io.BytesIO()
        handler.decrypt_stream(io.BytesIO(container_bytes), out_stream, STRONG_PASSWORD)
        assert out_stream.getvalue() == data

    def test_cross_compatibility_stream_encrypt_oneshot_decrypt(self):
        """Container produced by handler.encrypt_stream must decrypt with handler.decrypt_file."""
        data = b"Cross-compatibility test data: stream to oneshot" * 20
        enc_stream = io.BytesIO()
        handler.encrypt_stream(io.BytesIO(data), enc_stream, STRONG_PASSWORD)

        container_bytes = enc_stream.getvalue()
        decrypted = handler.decrypt_file(container_bytes, STRONG_PASSWORD)
        assert decrypted == data

    def test_stream_decrypt_legacy_v20(self):
        """Legacy v2.0 container decrypts cleanly with handler.decrypt_stream."""
        data = b"Legacy v2.0 stream test" * 10
        salt = os.urandom(config.ARGON2_SALT_LEN)
        nonce = os.urandom(config.AES_NONCE_LEN)
        key = kdf.derive_key(STRONG_PASSWORD, salt)
        ct, tag = cipher.encrypt(data, key, nonce, None)

        v20_container = {
            "protocol": config.PROTOCOL,
            "version": "2.0",
            "keyfile_required": False,
            "keyfile_fingerprint": None,
            "salt": base64.b64encode(salt).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ct).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }
        raw_json = json.dumps(v20_container).encode("utf-8")

        out_stream = io.BytesIO()
        handler.decrypt_stream(io.BytesIO(raw_json), out_stream, STRONG_PASSWORD)
        assert out_stream.getvalue() == data

    def test_stream_keyfile_roundtrip_and_validation(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        keyfile_path = "kf.bin"
        wrong_keyfile_path = "wrong_kf.bin"
        keyfile.generate_keyfile(keyfile_path)
        keyfile.generate_keyfile(wrong_keyfile_path)

        data = b"Two-factor streaming payload" * 15
        enc_stream = io.BytesIO()
        handler.encrypt_stream(io.BytesIO(data), enc_stream, STRONG_PASSWORD, keyfile_path=keyfile_path)
        enc_bytes = enc_stream.getvalue()

        # Decrypt with correct keyfile
        out_stream = io.BytesIO()
        handler.decrypt_stream(io.BytesIO(enc_bytes), out_stream, STRONG_PASSWORD, keyfile_path=keyfile_path)
        assert out_stream.getvalue() == data

        # Decrypt with wrong keyfile fails
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_stream(
                io.BytesIO(enc_bytes), io.BytesIO(), STRONG_PASSWORD, keyfile_path=wrong_keyfile_path
            )

        # Decrypt without keyfile fails
        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_stream(io.BytesIO(enc_bytes), io.BytesIO(), STRONG_PASSWORD, keyfile_path=None)

    def test_stream_tampered_ciphertext_fails(self):
        data = b"Sensitive payload" * 10
        enc_stream = io.BytesIO()
        handler.encrypt_stream(io.BytesIO(data), enc_stream, STRONG_PASSWORD)
        enc_bytes = bytearray(enc_stream.getvalue())

        idx = enc_bytes.find(b'ciphertext": "') + len(b'ciphertext": "')
        enc_bytes[idx] = ord(b"A") if enc_bytes[idx] != ord(b"A") else ord(b"B")

        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_stream(io.BytesIO(bytes(enc_bytes)), io.BytesIO(), STRONG_PASSWORD)

    def test_stream_tampered_tag_fails(self):
        data = b"Sensitive payload" * 10
        enc_stream = io.BytesIO()
        handler.encrypt_stream(io.BytesIO(data), enc_stream, STRONG_PASSWORD)
        c = json.loads(enc_stream.getvalue().decode("utf-8"))
        c["tag"] = base64.b64encode(os.urandom(16)).decode("utf-8")
        tampered = json.dumps(c).encode("utf-8")

        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_stream(io.BytesIO(tampered), io.BytesIO(), STRONG_PASSWORD)

    def test_stream_tampered_header_fails(self):
        data = b"Sensitive payload" * 10
        enc_stream = io.BytesIO()
        handler.encrypt_stream(io.BytesIO(data), enc_stream, STRONG_PASSWORD)
        c = json.loads(enc_stream.getvalue().decode("utf-8"))
        # Tamper with salt
        c["salt"] = base64.b64encode(os.urandom(config.ARGON2_SALT_LEN)).decode("utf-8")
        tampered = json.dumps(c).encode("utf-8")

        with pytest.raises(ValueError, match="Decryption failed"):
            handler.decrypt_stream(io.BytesIO(tampered), io.BytesIO(), STRONG_PASSWORD)

    def test_stream_missing_fields_fails(self):
        valid = {
            "protocol": config.PROTOCOL,
            "version": "2.1",
            "keyfile_required": False,
            "keyfile_fingerprint": None,
            "salt": base64.b64encode(b"s" * config.ARGON2_SALT_LEN).decode("utf-8"),
            "nonce": base64.b64encode(b"n" * config.AES_NONCE_LEN).decode("utf-8"),
            "ciphertext": base64.b64encode(b"c" * 32).decode("utf-8"),
            "tag": base64.b64encode(b"t" * 16).decode("utf-8"),
        }
        for req in ["protocol", "version", "salt", "nonce", "ciphertext", "tag"]:
            bad = valid.copy()
            del bad[req]
            with pytest.raises(ValueError, match="Decryption failed"):
                handler.decrypt_stream(io.BytesIO(json.dumps(bad).encode()), io.BytesIO(), STRONG_PASSWORD)

    def test_stream_malformed_json_fails(self):
        bad_inputs = [
            b"",
            b"not json",
            b"{truncated",
            b"[1, 2, 3]",
            b'"just a string"',
            b'{"protocol": "GUN-101", "ciphertext": "abc", "tag": "xyz"} extra',
            b'{"protocol": "GUN-101", "ciphertext": "abc", "tag": "xyz",}',
        ]
        for bad in bad_inputs:
            with pytest.raises(ValueError, match="Decryption failed"):
                handler.decrypt_stream(io.BytesIO(bad), io.BytesIO(), STRONG_PASSWORD)


class TestCLIStreamingIntegration:
    """End-to-end tests for CLI streaming file operations."""

    def test_cli_streaming_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("GUN101_PASSWORD", STRONG_PASSWORD)

        plain_file = "large_plain.bin"
        # 256 KB of pseudo-random binary data
        original_data = os.urandom(256 * 1024)
        with open(plain_file, "wb") as f:
            f.write(original_data)

        # Encrypt
        out, err, exc = run_cli(cli.encrypt, make_arg(file=plain_file, keyfile=None, output=None))
        assert exc is None
        assert "Encrypted file written to: large_plain.bin.gun101" in out
        assert os.path.exists("large_plain.bin.gun101")

        # Decrypt
        out, err, exc = run_cli(
            cli.decrypt,
            make_arg(file="large_plain.bin.gun101", keyfile=None, output="restored.bin"),
        )
        assert exc is None
        assert "Decrypted file written to: restored.bin" in out
        with open("restored.bin", "rb") as f:
            assert f.read() == original_data

    def test_cli_decrypt_invalid_tag_no_output_file_created(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("GUN101_PASSWORD", STRONG_PASSWORD)

        with open("source.txt", "wb") as f:
            f.write(b"Secret payload that must not be released on tag failure")

        run_cli(cli.encrypt, make_arg(file="source.txt", keyfile=None, output=None))

        # Tamper with the tag in the container
        with open("source.txt.gun101", "rb") as f:
            container = json.loads(f.read().decode("utf-8"))
        container["tag"] = base64.b64encode(os.urandom(16)).decode("utf-8")
        with open("source.txt.gun101", "wb") as f:
            f.write(json.dumps(container).encode("utf-8"))

        target_out = "destination.txt"
        out, err, exc = run_cli(
            cli.decrypt,
            make_arg(file="source.txt.gun101", keyfile=None, output=target_out),
        )
        assert exc is not None and exc.code == 1
        assert "Decryption failed" in err
        # Ensure no output file exists
        assert not os.path.exists(target_out)
        # Ensure no temporary staging files remain in directory
        remaining_files = os.listdir(tmp_path)
        assert not any(".tmp." in fn for fn in remaining_files)

    def test_bounded_memory_chunking(self):
        """Verify that streaming operations strictly read in bounded chunks."""
        data = os.urandom(256 * 1024)  # 256 KB
        in_stream = TrackingStream(data)
        out_stream = TrackingStream()

        chunk_size = 16384  # 16 KB
        handler.encrypt_stream(in_stream, out_stream, STRONG_PASSWORD, chunk_size=chunk_size)

        # in_stream should never have been read in chunks exceeding chunk_size
        assert in_stream.max_read_size <= chunk_size

        enc_bytes = out_stream.getvalue()
        dec_in = TrackingStream(enc_bytes)
        dec_out = TrackingStream()

        handler.decrypt_stream(dec_in, dec_out, STRONG_PASSWORD, chunk_size=chunk_size)
        assert dec_out.getvalue() == data
        assert dec_in.max_read_size <= chunk_size

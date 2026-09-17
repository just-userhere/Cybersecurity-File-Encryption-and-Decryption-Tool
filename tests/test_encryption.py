"""Automated tests for CipherGuard core encryption.

Run with:
    python -m pytest -v
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from encryption import (  # noqa: E402
    DecryptionFailedError,
    InvalidFileFormatError,
    InvalidPasswordError,
    decrypt_file,
    encrypt_file,
)

PASSWORD = "CorrectHorseBatteryStaple!123"
WRONG_PASSWORD = "TotallyWrongPassword!456"


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    target = tmp_path / name
    target.write_bytes(data)
    return str(target)


# Test 1 - Encryption creates an encrypted file.
def test_1_encryption_creates_file(tmp_path):
    src = _write(tmp_path, "hello.txt", b"Hello CipherGuard!")
    out = encrypt_file(src, PASSWORD)
    assert os.path.isfile(out)
    assert out.endswith(".enc")
    # Ciphertext must differ from plaintext.
    assert Path(out).read_bytes() != b"Hello CipherGuard!"


# Test 2 - Correct password restores the original byte-for-byte.
def test_2_decrypt_with_correct_password(tmp_path):
    original = b"Secret notes for the viva demo.\nLine 2.\n"
    src = _write(tmp_path, "notes.txt", original)
    enc = encrypt_file(src, PASSWORD)
    dec = decrypt_file(enc, PASSWORD)
    assert Path(dec).read_bytes() == original


# Test 3 - Wrong password fails safely (no output file, clear error).
def test_3_decrypt_with_wrong_password_fails(tmp_path):
    src = _write(tmp_path, "secret.txt", b"Top secret content")
    enc = encrypt_file(src, PASSWORD)
    with pytest.raises(DecryptionFailedError):
        decrypt_file(enc, WRONG_PASSWORD)


# Test 4 - Tampering with the encrypted file is detected.
def test_4_tampered_file_fails(tmp_path):
    src = _write(tmp_path, "data.txt", b"Integrity matters")
    enc = encrypt_file(src, PASSWORD)
    blob = bytearray(Path(enc).read_bytes())
    blob[-1] ^= 0x01  # flip one bit in the ciphertext/tag region
    Path(enc).write_bytes(bytes(blob))
    with pytest.raises(DecryptionFailedError):
        decrypt_file(enc, PASSWORD)


# Test 5 - Binary files (e.g. images) round-trip identically.
def test_5_binary_file_round_trip(tmp_path):
    binary = bytes(range(256)) * 4 + os.urandom(1024)  # PNG-like bytes
    src = _write(tmp_path, "photo.png", binary)
    enc = encrypt_file(src, PASSWORD)
    dec = decrypt_file(enc, PASSWORD)
    assert Path(dec).read_bytes() == binary


# Test 6 - Empty passwords are rejected for both operations.
def test_6_empty_password_rejected(tmp_path):
    src = _write(tmp_path, "a.txt", b"data")
    with pytest.raises(InvalidPasswordError):
        encrypt_file(src, "")
    with pytest.raises(InvalidPasswordError):
        encrypt_file(src, "   ")
    enc = encrypt_file(src, PASSWORD)
    with pytest.raises(InvalidPasswordError):
        decrypt_file(enc, "")


# Test 7 - A normal non-CipherGuard file cannot be "decrypted".
def test_7_invalid_encrypted_file_rejected(tmp_path):
    fake = _write(tmp_path, "plain.txt", b"I was never encrypted.")
    with pytest.raises(InvalidFileFormatError):
        decrypt_file(fake, PASSWORD)

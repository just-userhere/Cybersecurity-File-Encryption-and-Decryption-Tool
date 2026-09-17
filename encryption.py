"""CipherGuard cryptographic core.

Beginner-friendly but genuinely secure file encryption:

* Password -> key using PBKDF2-HMAC-SHA256 with a random 16-byte salt.
* Encryption using AES-256-GCM (authenticated encryption).
* Simple documented ``.enc`` file format::

      | MAGIC (4 bytes) | SALT (16 bytes) | NONCE (12 bytes) | CIPHERTEXT+TAG |

  - MAGIC  = b'CG01'  (format / version identifier)
  - SALT   = 16 cryptographically secure random bytes
  - NONCE  = 12 cryptographically secure random bytes (GCM nonce)
  - CIPHERTEXT+TAG = AES-256-GCM output (16-byte auth tag appended)

Security properties:
  - Never stores the password.
  - Never hardcodes a key or password.
  - Wrong password -> authentication failure, no output file created.
  - Tampered file  -> authentication failure, no output file created.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Format constants (easy to explain in a viva) ---------------------------
MAGIC: bytes = b"CG01"          # 4-byte format / version identifier
SALT_SIZE: int = 16             # 128-bit salt
NONCE_SIZE: int = 12            # 96-bit nonce (standard for GCM)
KEY_SIZE: int = 32              # 32 bytes = AES-256
KDF_ITERATIONS: int = 200_000   # PBKDF2 work factor (OWASP suggests >= 210k
                                # for PBKDF2-HMAC-SHA256; 200k keeps the
                                # mini-project fast while staying strong)
ENC_EXTENSION: str = ".enc"


class CipherGuardError(Exception):
    """Base error for all CipherGuard crypto failures."""


class InvalidPasswordError(CipherGuardError):
    """Raised when the password is empty."""


class InvalidFileFormatError(CipherGuardError):
    """Raised when a file is not a valid CipherGuard ``.enc`` file."""


class DecryptionFailedError(CipherGuardError):
    """Raised when decryption fails (wrong password or corrupted file)."""


def validate_password(password: str) -> None:
    """Reject empty / whitespace-only passwords."""
    if not password or not password.strip():
        raise InvalidPasswordError("Password cannot be empty.")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password and salt using PBKDF2."""
    validate_password(password)
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be {SALT_SIZE} bytes.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _unique_path(path: Path) -> Path:
    """Return ``path`` or a non-overwriting variant (file_1.ext, ...)."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    parent = path.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def build_encrypted_path(input_path: str | os.PathLike) -> Path:
    """``photo.jpg`` -> ``photo.jpg.enc`` (never overwrites silently)."""
    candidate = Path(str(input_path)).with_suffix(Path(str(input_path)).suffix + ENC_EXTENSION)
    # Path("resume.pdf").with_suffix(".pdf.enc") gives "resume.pdf.enc". For
    # files without suffix, e.g. "notes" -> "notes.enc".
    if Path(str(input_path)).suffix == "":
        candidate = Path(str(input_path) + ENC_EXTENSION)
    return _unique_path(candidate)


def build_decrypted_path(enc_path: str | os.PathLike) -> Path:
    """``photo.jpg.enc`` -> ``photo_decrypted.jpg`` (safe, no overwrite).

    If the name already exists, ``_1``, ``_2`` ... suffixes are appended.
    """
    enc = Path(str(enc_path))
    name = enc.name
    if name.endswith(ENC_EXTENSION):
        name = name[: -len(ENC_EXTENSION)]  # strip ".enc" -> "photo.jpg"
    inner = Path(name)
    if inner.suffix:
        decrypted_name = f"{inner.stem}_decrypted{inner.suffix}"
    else:
        decrypted_name = f"{name}_decrypted"
    return _unique_path(enc.parent / decrypted_name)


def encrypt_file(
    input_path: str | os.PathLike,
    password: str,
    output_path: str | os.PathLike | None = None,
) -> str:
    """Encrypt any file with a password. Returns the output path (str).

    Raises:
        InvalidPasswordError: if the password is empty.
        FileNotFoundError: if the input file does not exist.
        CipherGuardError: for read/write failures.
    """
    validate_password(password)
    src = Path(str(input_path))
    if not src.is_file():
        raise FileNotFoundError(f"Input file not found: {src}")

    try:
        plaintext = src.read_bytes()
    except OSError as exc:
        raise CipherGuardError(f"Could not read input file: {exc}") from exc

    salt = os.urandom(SALT_SIZE)    # secure random salt
    nonce = os.urandom(NONCE_SIZE)  # secure random nonce
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    blob = MAGIC + salt + nonce + ciphertext

    dest = Path(str(output_path)) if output_path else build_encrypted_path(src)
    try:
        dest.write_bytes(blob)
    except OSError as exc:
        raise CipherGuardError(f"Could not write encrypted file: {exc}") from exc
    return str(dest)


def decrypt_file(
    enc_path: str | os.PathLike,
    password: str,
    output_path: str | os.PathLike | None = None,
) -> str:
    """Decrypt a ``.enc`` file. Returns the output path (str).

    On wrong password / tampering / bad format, raises
    :class:`DecryptionFailedError` or :class:`InvalidFileFormatError`
    and NEVER creates a partial output file.

    Raises:
        InvalidPasswordError: if the password is empty.
        FileNotFoundError: if the encrypted file does not exist.
    """
    validate_password(password)
    src = Path(str(enc_path))
    if not src.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {src}")

    try:
        blob = src.read_bytes()
    except OSError as exc:
        raise CipherGuardError(f"Could not read encrypted file: {exc}") from exc

    # --- Parse & validate the file format ----------------------------------
    min_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 1
    if len(blob) < min_size or blob[: len(MAGIC)] != MAGIC:
        raise InvalidFileFormatError(
            "Not a valid CipherGuard encrypted file. "
            "It may be a normal file or from another program."
        )

    salt = blob[len(MAGIC): len(MAGIC) + SALT_SIZE]
    nonce = blob[len(MAGIC) + SALT_SIZE: len(MAGIC) + SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[len(MAGIC) + SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        # Wrong password OR tampered file -> identical safe failure.
        raise DecryptionFailedError(
            "Decryption failed. Incorrect password or corrupted file."
        ) from exc

    dest = Path(str(output_path)) if output_path else build_decrypted_path(src)
    try:
        dest.write_bytes(plaintext)
    except OSError as exc:
        raise CipherGuardError(f"Could not write decrypted file: {exc}") from exc
    return str(dest)

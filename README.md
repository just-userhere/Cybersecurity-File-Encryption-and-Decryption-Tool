# 🔐 CipherGuard

### Cybersecurity File Encryption & Decryption Tool

A beginner-friendly desktop tool that encrypts any file with a password and restores it later with the same password. Built with Python, Tkinter, and the `cryptography` library (AES-256-GCM + PBKDF2). Small enough to explain in a viva, secure enough to demonstrate real cybersecurity fundamentals.

---

## Overview

CipherGuard lets you pick a file (TXT, PDF, JPG, PNG, DOCX, CSV — any binary or text file), enter a password, and produce a protected `.enc` file. Later, you select the `.enc` file, enter the same password, and get the original file back byte-for-byte.

No homemade ciphers. No passwords stored anywhere. Just a standard library doing standard cryptography behind a simple GUI.

## Problem Statement

Laptops get lost, pen drives get shared, and files get emailed. Anyone who obtains the file can read it. Sensitive documents — IDs, marksheets, resumes, photos, project reports — need protection so that only someone with the password can open them.

## Objective

Give students a simple, working example of **password-based file encryption**: turn any file into unreadable ciphertext, and turn it back only with the correct password — while showing exactly how salts, key derivation, nonces, and authenticated encryption fit together.

## Features

- 🔒 File encryption with a password
- 🔓 File decryption with the same password
- 🔑 Password-based key derivation (PBKDF2-HMAC-SHA256, 200,000 iterations)
- 🧂 Secure random 16-byte salt per file
- ✅ Integrity/authentication protection (AES-256-GCM auth tag)
- 🖥️ Clean Tkinter GUI with a dark cybersecurity style
- 📁 Binary file support (TXT, PDF, JPG, PNG, DOCX, CSV, …)
- 💪 Simple password-strength hint
- 🛡️ Friendly error handling (wrong password, corrupted file, missing file, …)

## Technologies

- **Python 3.10+** (standard library + Tkinter)
- **`cryptography`** — reputable Python crypto library (PBKDF2 + AES-GCM)
- **`pytest`** — automated tests (dev/test dependency)

## How It Works

**Encryption**

```
Select File → Enter Password → Encrypt
  1. Generate random 16-byte salt + 12-byte nonce (os.urandom)
  2. Derive 32-byte key: PBKDF2-HMAC-SHA256(password, salt, 200_000 iterations)
  3. Encrypt bytes with AES-256-GCM → ciphertext + auth tag
  4. Write file: MAGIC + salt + nonce + ciphertext  (e.g. resume.pdf.enc)
```

**Decryption**

```
Select .enc File → Enter Password → Decrypt
  1. Read + validate file (check MAGIC "CG01")
  2. Extract salt + nonce
  3. Re-derive the key from password + stored salt
  4. AES-GCM decrypt + verify the auth tag
  5. Success → write photo_decrypted.jpg | Failure → safe error, no output file
```

### Encrypted file format (`.enc`)

| Field | Size | Description |
|---|---|---|
| MAGIC | 4 bytes | `CG01` — format/version identifier |
| Salt | 16 bytes | Random per-file salt for PBKDF2 |
| Nonce | 12 bytes | Random per-file nonce for AES-GCM |
| Ciphertext + tag | variable | AES-256-GCM output (16-byte auth tag included) |

The password is **never** stored in the file. Only the salt/nonce needed for legitimate decryption are stored.

### Filename behavior

- `resume.pdf` → encrypt → `resume.pdf.enc`
- `resume.pdf.enc` → decrypt → `resume_decrypted.pdf`
- Originals are **never** overwritten or deleted.
- If a name already exists, `_1`, `_2`, … is appended automatically.

## Architecture

```
        GUI (main.py)
            ↓  calls clean functions
  Encryption Module (encryption.py)
            ↓  PBKDF2 + AES-GCM
  Cryptographic Functions (cryptography lib)
            ↓
     Encrypted File (.enc)
```

- `main.py` — Tkinter interface only (no crypto code).
- `encryption.py` — salt generation, key derivation, encrypt/decrypt, format handling, errors.

## Installation

Requires Python 3.10+.

```bash
# 1. Clone the repository
git clone https://github.com/just-userhere/CyberCybersecurity-File-Encryption-and-Decryption-Tool.git
cd CyberCybersecurity-File-Encryption-and-Decryption-Tool

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
# Windows (PowerShell):
venv\Scripts\Activate.ps1
# Windows (cmd):
venv\Scripts\activate.bat
# macOS / Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

## Running

```bash
python main.py
```

Then:

1. **Encrypt:** Select File → type a password → Encrypt File.
2. **Decrypt:** Select Encrypted File (.enc) → type the same password → Decrypt File.

## Testing

```bash
python -m pytest -v
```

Covered scenarios:

| # | Test | Expected |
|---|---|---|
| 1 | Encryption | `.enc` file is created |
| 2 | Correct password | Decrypted file matches original byte-for-byte |
| 3 | Wrong password | Decryption fails safely, no output file |
| 4 | Tampering | Flipping one bit → decryption fails safely |
| 5 | Binary file | Image-like bytes round-trip identically |
| 6 | Empty password | Operation rejected |
| 7 | Invalid file | Plain non-`.enc` file rejected with a clear error |

## Security Notes

- Passwords are **never stored, logged, or printed**.
- Encryption keys are **derived from the password** (PBKDF2-HMAC-SHA256) and kept only in memory.
- A fresh **random salt + nonce** is generated for every encryption (`os.urandom`).
- AES-256-GCM provides **confidentiality + authentication**: tampering or a wrong password fails verification instead of producing garbage.
- The password itself is never written into the `.enc` file.
- If you **lose the password, the file cannot be recovered** — there is no backdoor.
- Educational project: it demonstrates real fundamentals but is **not a replacement for enterprise key-management systems**.

## Limitations

- Password must be remembered — no recovery mechanism.
- One file at a time (no folder encryption).
- No progress bar for very large files (whole file is processed in memory).
- No drag-and-drop; file selection via dialog only.
- Anyone with the password can decrypt — there is no user management.

## Future Improvements

- Folder encryption
- Drag-and-drop support
- Stronger password-strength meter
- Progress indicator for large files
- Secure key-management integration

(Deliberately not implemented — this stays a mini project.)

### Automated Repository Maintenance

CipherGuard includes a GitHub Actions maintenance workflow that periodically updates repository maintenance metadata approximately every five days (120 hours). The workflow creates a maintenance commit when the metadata changes.

Details:

- Workflow: `.github/workflows/maintenance.yml`
- Schedule: calendar-based five-day cadence — days 1, 6, 11, 16, 21, 26, and 31 of each month at 04:37 UTC (`37 4 1,6,11,16,21,26,31 * *`), roughly 6 runs per month ≈ once every five days. GitHub Actions cron has no native "every 120 hours" interval, so this calendar pattern is used instead. Scheduled runs can occasionally be delayed during periods of high Actions load.
- Manual runs are also supported via `workflow_dispatch`.
- Each run refreshes the `last_updated` timestamp in `maintenance/status.json` and pushes a `chore: update automated maintenance status` commit to `master` only when the file actually changed (no empty commits).
- These commits update maintenance metadata only and do not represent new application features. Core files (`encryption.py`, `main.py`, tests, cryptographic parameters) are never touched by automation.

## Project Structure

```
CipherGuard/
├── main.py
├── encryption.py
├── requirements.txt
├── README.md
├── .gitignore
├── LICENSE
├── .github/
│   └── workflows/
│       └── maintenance.yml
├── maintenance/
│   └── status.json
├── tests/
│   └── test_encryption.py
└── assets/
    └── README.md
```

## Viva Questions & Answers

1. **What is cybersecurity?**
   Protecting computers, files, and networks from unauthorized access, theft, or damage. CipherGuard is a small example: it protects files so only the password holder can read them.

2. **What is encryption?**
   Converting readable data (plaintext) into unreadable data (ciphertext) using a key, so outsiders cannot understand it.

3. **What is decryption?**
   The reverse: converting ciphertext back into the original plaintext using the correct key/password.

4. **What is symmetric encryption?**
   Encryption where the **same key** encrypts and decrypts. CipherGuard is symmetric: one password-derived key does both jobs.

5. **Why is encryption useful?**
   A stolen or shared encrypted file is useless without the password — it provides confidentiality for documents, backups, and shared drives.

6. **Why should we use a standard cryptographic library?**
   Cryptography is easy to get subtly wrong (bad randomness, broken modes, timing leaks). Libraries like `cryptography` are written, reviewed, and tested by experts. Homemade ciphers are almost always breakable.

7. **What is a salt?**
   A random value mixed with the password before key derivation. CipherGuard stores a fresh 16-byte salt in every `.enc` file.

8. **Why is a salt used?**
   So the same password produces a **different key** for each file. Attackers cannot precompute one table (rainbow table) for all files, and identical files encrypt differently.

9. **How is a password converted into an encryption key?**
   With a **KDF (key derivation function)** — here PBKDF2-HMAC-SHA256 with 200,000 iterations. It stretches the password into a 32-byte AES key, deliberately slowly to resist brute force.

10. **Why should passwords not be stored directly?**
    Anyone who reads the storage learns every password. CipherGuard never stores the password at all — it only stores the salt, and re-derives the key each time.

11. **What happens if the wrong password is entered?**
    A different key is derived, GCM authentication fails, and the app shows "Decryption failed. Incorrect password or corrupted file." No output file is created.

12. **What happens if the encrypted file is modified?**
    The GCM authentication tag no longer matches, so decryption fails safely with the same error — tampering is detected, not silently accepted.

13. **What is the difference between encryption and hashing?**
    Encryption is **reversible** (with the key you get data back). Hashing is **one-way** (used to verify, e.g. password checks, never to recover data).

14. **Why is Base64 not encryption?**
    Base64 is just an **encoding** — anyone can decode it, no key needed. It hides nothing; it only changes representation.

15. **What are the limitations of CipherGuard?**
    Lost password = lost file; one file at a time; no user accounts or key recovery; whole file in memory; educational scope, not enterprise key management.

## License

MIT — see [LICENSE](LICENSE).

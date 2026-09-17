"""CipherGuard desktop GUI (Tkinter).

Clean, beginner-friendly interface. All cryptography lives in
``encryption.py`` - this file only handles file selection, password
input, status messages, and error dialogs.
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

from encryption import (
    CipherGuardError,
    DecryptionFailedError,
    InvalidFileFormatError,
    InvalidPasswordError,
    decrypt_file,
    encrypt_file,
)

# --- Dark cybersecurity-inspired theme --------------------------------------
BG = "#0f172a"          # dark navy background
CARD = "#1e293b"        # card background
ACCENT = "#38bdf8"      # cyan accent
ACCENT_DARK = "#0e7490"
TEXT = "#e2e8f0"        # light text
MUTED = "#94a3b8"       # muted text
SUCCESS = "#22c55e"
ERROR = "#ef4444"
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_SUB = ("Segoe UI", 10)
FONT_BODY = ("Segoe UI", 10)


class CipherGuardApp(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("CipherGuard — Cybersecurity File Encryption Tool")
        self.geometry("560x640")
        self.minsize(520, 600)
        self.configure(bg=BG)

        self.encrypt_path: str = ""
        self.decrypt_path: str = ""

        self._build_header()
        self._build_encrypt_card()
        self._build_decrypt_card()
        self._build_status_area()

    # -- layout helpers ------------------------------------------------------
    def _card(self, parent: tk.Widget, title: str) -> tuple[tk.Frame, tk.Frame]:
        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="x", padx=18, pady=8)
        inner = tk.Frame(outer, bg=CARD, padx=16, pady=14,
                         highlightbackground=ACCENT_DARK,
                         highlightthickness=1)
        inner.pack(fill="x")
        tk.Label(inner, text=title, font=("Segoe UI", 12, "bold"),
                 bg=CARD, fg=ACCENT).pack(anchor="w", pady=(0, 10))
        return outer, inner

    def _styled_button(self, parent: tk.Widget, text: str,
                       command) -> tk.Button:
        return tk.Button(
            parent, text=text, command=command,
            bg=ACCENT, fg="#082f49", activebackground="#7dd3fc",
            activeforeground="#082f49", relief="flat",
            font=("Segoe UI", 10, "bold"), padx=12, pady=6,
            cursor="hand2",
        )

    def _file_label(self, parent: tk.Widget) -> tk.Label:
        return tk.Label(parent, text="No file selected.",
                        font=FONT_BODY, bg=CARD, fg=MUTED,
                        wraplength=460, justify="left")

    # -- sections ------------------------------------------------------------
    def _build_header(self) -> None:
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=18, pady=(16, 4))
        tk.Label(header, text="🔐 CipherGuard", font=FONT_TITLE,
                 bg=BG, fg=ACCENT).pack(anchor="w")
        tk.Label(header, text="Cybersecurity File Encryption & Decryption Tool",
                 font=FONT_SUB, bg=BG, fg=MUTED).pack(anchor="w")

    def _build_encrypt_card(self) -> None:
        _, card = self._card(self, "🔒 Encrypt File")
        self._styled_button(card, "Select File",
                            self.on_select_encrypt).pack(anchor="w")
        self.encrypt_file_label = self._file_label(card)
        self.encrypt_file_label.pack(anchor="w", pady=(6, 8))

        tk.Label(card, text="Password:", font=FONT_BODY,
                 bg=CARD, fg=TEXT).pack(anchor="w")
        self.encrypt_pw = tk.Entry(card, show="•", width=40, font=FONT_BODY,
                                   bg="#0b1220", fg=TEXT,
                                   insertbackground=TEXT, relief="flat",
                                   highlightbackground=ACCENT_DARK,
                                   highlightthickness=1)
        self.encrypt_pw.pack(anchor="w", pady=(2, 4))
        self.encrypt_strength = tk.Label(card, text="", font=("Segoe UI", 9),
                                         bg=CARD, fg=MUTED)
        self.encrypt_strength.pack(anchor="w")
        self.encrypt_pw.bind("<KeyRelease>", self._update_strength)

        self._styled_button(card, "Encrypt File",
                            self.on_encrypt).pack(anchor="w", pady=(8, 0))

    def _build_decrypt_card(self) -> None:
        _, card = self._card(self, "🔓 Decrypt File")
        self._styled_button(card, "Select Encrypted File (.enc)",
                            self.on_select_decrypt).pack(anchor="w")
        self.decrypt_file_label = self._file_label(card)
        self.decrypt_file_label.pack(anchor="w", pady=(6, 8))

        tk.Label(card, text="Password:", font=FONT_BODY,
                 bg=CARD, fg=TEXT).pack(anchor="w")
        self.decrypt_pw = tk.Entry(card, show="•", width=40, font=FONT_BODY,
                                   bg="#0b1220", fg=TEXT,
                                   insertbackground=TEXT, relief="flat",
                                   highlightbackground=ACCENT_DARK,
                                   highlightthickness=1)
        self.decrypt_pw.pack(anchor="w", pady=(2, 8))

        self._styled_button(card, "Decrypt File",
                            self.on_decrypt).pack(anchor="w")

    def _build_status_area(self) -> None:
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="both", expand=True, padx=18, pady=8)
        tk.Label(frame, text="Status:", font=("Segoe UI", 10, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w")
        self.status = tk.Label(frame, text="Ready. Select a file to begin.",
                               font=FONT_BODY, bg=BG, fg=MUTED,
                               wraplength=500, justify="left")
        self.status.pack(anchor="w", pady=(2, 0))

    # -- helpers --------------------------------------------------------------
    def set_status(self, message: str, ok: bool | None = None) -> None:
        color = MUTED if ok is None else (SUCCESS if ok else ERROR)
        self.status.config(text=message, fg=color)
        self.update_idletasks()

    @staticmethod
    def password_strength(password: str) -> str:
        """Very simple strength hint (length + character variety)."""
        if len(password) < 6:
            return "Weak: use at least 8 characters."
        score = sum([
            len(password) >= 8,
            len(password) >= 12,
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ])
        if score <= 2:
            return "Weak password."
        if score <= 4:
            return "Medium password."
        return "Strong password."

    def _update_strength(self, _event=None) -> None:
        pw = self.encrypt_pw.get()
        self.encrypt_strength.config(
            text="" if not pw else self.password_strength(pw))

    # -- event handlers --------------------------------------------------------
    def on_select_encrypt(self) -> None:
        path = filedialog.askopenfilename(title="Select a file to encrypt")
        if not path:  # user cancelled - not an error
            self.set_status("File selection cancelled.")
            return
        self.encrypt_path = path
        self.encrypt_file_label.config(
            text=f"Selected: {os.path.basename(path)}", fg=TEXT)
        self.set_status("File selected successfully.", ok=True)

    def on_select_decrypt(self) -> None:
        path = filedialog.askopenfilename(
            title="Select an encrypted file",
            filetypes=[("CipherGuard files", "*.enc"), ("All files", "*.*")])
        if not path:
            self.set_status("File selection cancelled.")
            return
        self.decrypt_path = path
        self.decrypt_file_label.config(
            text=f"Selected: {os.path.basename(path)}", fg=TEXT)
        self.set_status("Encrypted file selected successfully.", ok=True)

    def on_encrypt(self) -> None:
        password = self.encrypt_pw.get()
        if not self.encrypt_path:
            self.set_status("Please select a file.", ok=False)
            messagebox.showwarning("No file", "Please select a file first.")
            return
        if not password or not password.strip():
            self.set_status("Password cannot be empty.", ok=False)
            messagebox.showwarning("Empty password",
                                   "Password cannot be empty.")
            return
        if not Path(self.encrypt_path).is_file():
            self.set_status("Selected file no longer exists.", ok=False)
            messagebox.showerror("Missing file",
                                 "The selected file no longer exists.")
            return
        try:
            out = encrypt_file(self.encrypt_path, password)
        except InvalidPasswordError:
            self.set_status("Password cannot be empty.", ok=False)
            messagebox.showwarning("Empty password",
                                   "Password cannot be empty.")
        except FileNotFoundError:
            self.set_status("Selected file no longer exists.", ok=False)
            messagebox.showerror("Missing file",
                                 "The selected file no longer exists.")
        except CipherGuardError as exc:
            self.set_status(f"Encryption failed: {exc}", ok=False)
            messagebox.showerror("Encryption failed", str(exc))
        except OSError as exc:  # permission errors, etc.
            self.set_status(f"Encryption failed: {exc}", ok=False)
            messagebox.showerror("Encryption failed", str(exc))
        except Exception as exc:  # never crash on user mistakes
            self.set_status(f"Unexpected error: {exc}", ok=False)
            messagebox.showerror("Unexpected error",
                                 f"Something went wrong: {exc}")
        else:
            self.set_status(
                f"Encryption completed successfully.\nSaved: {out}", ok=True)
            messagebox.showinfo("Success",
                                f"File encrypted successfully.\nSaved as:\n{out}")
            self.encrypt_pw.delete(0, tk.END)

    def on_decrypt(self) -> None:
        password = self.decrypt_pw.get()
        if not self.decrypt_path:
            self.set_status("Please select a file.", ok=False)
            messagebox.showwarning("No file",
                                   "Please select an encrypted file first.")
            return
        if not password or not password.strip():
            self.set_status("Password cannot be empty.", ok=False)
            messagebox.showwarning("Empty password",
                                   "Password cannot be empty.")
            return
        if not Path(self.decrypt_path).is_file():
            self.set_status("Selected file no longer exists.", ok=False)
            messagebox.showerror("Missing file",
                                 "The selected file no longer exists.")
            return
        try:
            out = decrypt_file(self.decrypt_path, password)
        except InvalidPasswordError:
            self.set_status("Password cannot be empty.", ok=False)
            messagebox.showwarning("Empty password",
                                   "Password cannot be empty.")
        except FileNotFoundError:
            self.set_status("Selected file no longer exists.", ok=False)
            messagebox.showerror("Missing file",
                                 "The selected file no longer exists.")
        except (DecryptionFailedError, InvalidFileFormatError):
            self.set_status(
                "Decryption failed. Incorrect password or corrupted file.",
                ok=False)
            messagebox.showerror(
                "Decryption failed",
                "Decryption failed. Incorrect password or corrupted file.")
        except CipherGuardError as exc:
            self.set_status(f"Decryption failed: {exc}", ok=False)
            messagebox.showerror("Decryption failed", str(exc))
        except OSError as exc:
            self.set_status(f"Decryption failed: {exc}", ok=False)
            messagebox.showerror("Decryption failed", str(exc))
        except Exception as exc:
            self.set_status(f"Unexpected error: {exc}", ok=False)
            messagebox.showerror("Unexpected error",
                                 f"Something went wrong: {exc}")
        else:
            self.set_status(
                f"Decryption completed successfully.\nSaved: {out}", ok=True)
            messagebox.showinfo("Success",
                                f"File decrypted successfully.\nSaved as:\n{out}")
            self.decrypt_pw.delete(0, tk.END)


def main() -> None:
    app = CipherGuardApp()
    app.mainloop()


if __name__ == "__main__":
    main()

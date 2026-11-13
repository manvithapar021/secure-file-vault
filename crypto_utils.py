"""Encryption helpers for Secure File Vault.

One idea, kept simple on purpose: every uploaded file is encrypted
with AES (Fernet = AES-128-CBC + HMAC) *before* it is written to disk,
and decrypted only when an authorised download happens. The key lives
in instance/vault.key, which is never committed to git (see
.gitignore). If the key file is lost, the stored files cannot be
recovered — that is the point of encryption, and it is also why this
project has no key-rotation or breach-recovery yet (see README).
"""
import os

from cryptography.fernet import Fernet, InvalidToken

KEY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "instance", "vault.key"
)


def get_key() -> bytes:
    """Load the vault key, creating and saving a fresh one if needed."""
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key


def get_fernet() -> Fernet:
    return Fernet(get_key())


def encrypt_bytes(data: bytes) -> bytes:
    """Encrypt raw bytes. Returns bytes that are safe to store on disk."""
    return get_fernet().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    """Decrypt bytes produced by encrypt_bytes. Raises InvalidToken
    if the data was tampered with or the key is wrong."""
    return get_fernet().decrypt(token)

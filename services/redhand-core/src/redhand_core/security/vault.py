"""
AES-256-GCM envelope encryption for customer-supplied Enterprise credentials
(SIEM HEC tokens, TAXII passwords, BYOK Cyber-Model API keys).

Keys come from `ENTERPRISE_SECRETS_KEY` (base64-encoded 32-byte key stored in
GCP Secret Manager). Outside development/test, missing keys fail closed.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from redhand_core.config import get_settings

_DEV_PROCESS_KEY: bytes | None = None
_PREFIX = "v1:"


class SecretVaultError(RuntimeError):
    """Raised when encryption/decryption fails or master key is unavailable."""


def _master_key() -> bytes:
    global _DEV_PROCESS_KEY
    settings = get_settings()
    raw = settings.ENTERPRISE_SECRETS_KEY.get_secret_value() if settings.ENTERPRISE_SECRETS_KEY else None
    if raw:
        try:
            decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except (ValueError, binascii.Error) as exc:
            raise SecretVaultError("ENTERPRISE_SECRETS_KEY is not valid base64.") from exc
        if len(decoded) != 32:
            raise SecretVaultError("ENTERPRISE_SECRETS_KEY must decode to exactly 32 bytes (AES-256).")
        return decoded

    if settings.ENVIRONMENT in ("development", "test"):
        if _DEV_PROCESS_KEY is None:
            _DEV_PROCESS_KEY = secrets.token_bytes(32)
        return _DEV_PROCESS_KEY

    raise SecretVaultError(
        "ENTERPRISE_SECRETS_KEY must be configured in GCP Secret Manager outside development/test."
    )


def encrypt_secret(plaintext: str, *, aad: str) -> str:
    """Encrypts plaintext bound to tenant `aad` (organization_id)."""
    if not plaintext:
        raise SecretVaultError("Secret cannot be empty.")
    key = _master_key()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))
    token = base64.urlsafe_b64encode(nonce + ct).decode("ascii").rstrip("=")
    return f"{_PREFIX}{token}"


def decrypt_secret(ciphertext: str, *, aad: str) -> str:
    """Decrypts a `v1:` token, verifying `aad` matches the owning tenant."""
    if not ciphertext.startswith(_PREFIX):
        raise SecretVaultError("Unsupported secret ciphertext format.")
    key = _master_key()
    body = ciphertext[len(_PREFIX) :]
    try:
        blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        if len(blob) < 28:
            raise ValueError("Truncated AES-GCM payload.")
        nonce, ct = blob[:12], blob[12:]
        plain = AESGCM(key).decrypt(nonce, ct, aad.encode("utf-8"))
        return plain.decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - never expose low-level crypto padding details
        raise SecretVaultError("Could not decrypt stored credential.") from exc


def mask_secret(plaintext: str) -> str:
    """Returns a non-reversible masked suffix suitable for UI display."""
    cleaned = plaintext.strip()
    if len(cleaned) <= 4:
        return "••••"
    return f"••••{cleaned[-4:]}"

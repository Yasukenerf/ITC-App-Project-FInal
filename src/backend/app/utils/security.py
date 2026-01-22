from __future__ import annotations

import base64
import os

import pyotp


def generate_totp_secret() -> str:
    # 160-bit random secret, Base32 for authenticator apps
    return pyotp.random_base32()


def totp_uri(username: str, secret: str, issuer: str = "Secure Phishing Detector") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, token: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(token, valid_window=1)
    except Exception:
        return False


def random_secret_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")

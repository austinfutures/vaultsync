"""Identity management: each user has an X25519 (encryption) + Ed25519 (signing) keypair.

Private keys are stored PKCS8-encrypted with a passphrase (scrypt-derived by the
`cryptography` BestAvailableEncryption). Public keys are exported as a single
JSON "identity card" that peers can import.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())


def _raw(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(enc_pub: bytes, sig_pub: bytes) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(enc_pub + sig_pub)
    d = h.finalize().hex()
    return ":".join(d[i : i + 4] for i in range(0, 32, 4))  # first 128 bits


@dataclass
class Identity:
    name: str
    enc_priv: X25519PrivateKey
    sig_priv: Ed25519PrivateKey

    @property
    def enc_pub(self) -> X25519PublicKey:
        return self.enc_priv.public_key()

    @property
    def sig_pub(self) -> Ed25519PublicKey:
        return self.sig_priv.public_key()

    @property
    def fingerprint(self) -> str:
        return fingerprint(_raw(self.enc_pub), _raw(self.sig_pub))

    def public_card(self) -> dict:
        return {
            "name": self.name,
            "enc_pub": _b64(_raw(self.enc_pub)),
            "sig_pub": _b64(_raw(self.sig_pub)),
            "fingerprint": self.fingerprint,
        }


@dataclass
class PeerCard:
    name: str
    enc_pub: X25519PublicKey
    sig_pub: Ed25519PublicKey
    fingerprint: str

    @classmethod
    def from_dict(cls, d: dict) -> "PeerCard":
        enc_raw, sig_raw = _unb64(d["enc_pub"]), _unb64(d["sig_pub"])
        fp = fingerprint(enc_raw, sig_raw)
        if fp != d.get("fingerprint"):
            raise ValueError("identity card fingerprint mismatch (corrupted/tampered)")
        return cls(
            name=d["name"],
            enc_pub=X25519PublicKey.from_public_bytes(enc_raw),
            sig_pub=Ed25519PublicKey.from_public_bytes(sig_raw),
            fingerprint=fp,
        )


def generate_identity(name: str) -> Identity:
    return Identity(name, X25519PrivateKey.generate(), Ed25519PrivateKey.generate())


def _write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def save_identity(ident: Identity, directory: Path, passphrase: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    enc = serialization.BestAvailableEncryption(passphrase)
    pkcs8 = serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8
    _write_secret(directory / "enc.key.pem", ident.enc_priv.private_bytes(*pkcs8, enc))
    _write_secret(directory / "sig.key.pem", ident.sig_priv.private_bytes(*pkcs8, enc))
    (directory / "identity.json").write_text(json.dumps(ident.public_card(), indent=2))


def load_identity(directory: Path, passphrase: bytes) -> Identity:
    card = json.loads((directory / "identity.json").read_text())
    try:
        enc_priv = serialization.load_pem_private_key(
            (directory / "enc.key.pem").read_bytes(), passphrase
        )
        sig_priv = serialization.load_pem_private_key(
            (directory / "sig.key.pem").read_bytes(), passphrase
        )
    except (ValueError, TypeError) as e:
        raise ValueError("could not decrypt private keys (wrong passphrase?)") from e
    return Identity(card["name"], enc_priv, sig_priv)  # type: ignore[arg-type]


def load_peer_card(path: Path) -> PeerCard:
    return PeerCard.from_dict(json.loads(path.read_text()))
"""Core cryptographic primitives: hybrid encryption with chunked AES-256-GCM.

Design
------
Each file gets a fresh random 256-bit File Encryption Key (FEK). The file is split
into fixed-size chunks; each chunk is encrypted with AES-256-GCM using a nonce
derived from a per-file random prefix + chunk counter, and the chunk index and a
"final chunk" flag are bound in as AAD. That prevents chunk reordering,
truncation, and cross-file splicing.

The FEK is then wrapped for a recipient using an ephemeral X25519 ECDH exchange
(ECIES-style): shared secret -> HKDF-SHA256 -> AES-256-GCM key-wrap. An RSA-2048
OAEP wrap is provided as an alternative for interop.
"""
from __future__ import annotations

import os
import struct
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK_SIZE = 1024 * 1024  # 1 MiB plaintext per chunk
KEY_LEN = 32
NONCE_PREFIX_LEN = 4  # 4-byte random prefix + 8-byte counter = 12-byte GCM nonce
TAG_LEN = 16
MAGIC = b"VSYNC1"


class CryptoError(Exception):
    """Raised on any authentication / integrity / format failure."""


# --------------------------------------------------------------------------- #
# Chunked authenticated file encryption
# --------------------------------------------------------------------------- #
def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + struct.pack(">Q", index)


def _aad(file_id: bytes, index: int, is_final: bool) -> bytes:
    return MAGIC + file_id + struct.pack(">QB", index, 1 if is_final else 0)


def _read_chunks(src: BinaryIO, size: int) -> Iterator[tuple[bytes, bool]]:
    """Yield (chunk, is_final). Uses one-chunk lookahead so the last chunk is flagged."""
    current = src.read(size)
    while True:
        nxt = src.read(size)
        yield current, not nxt
        if not nxt:
            return
        current = nxt


def encrypt_stream(
    src: BinaryIO,
    fek: bytes,
    file_id: bytes,
    nonce_prefix: bytes,
    chunk_size: int = CHUNK_SIZE,
) -> Iterator[bytes]:
    """Yield encrypted chunks (ciphertext || tag). Never holds more than ~2 chunks."""
    aes = AESGCM(fek)
    index = 0
    for chunk, is_final in _read_chunks(src, chunk_size):
        yield aes.encrypt(
            _nonce(nonce_prefix, index), chunk, _aad(file_id, index, is_final)
        )
        index += 1


def decrypt_chunk(
    fek: bytes,
    file_id: bytes,
    nonce_prefix: bytes,
    index: int,
    is_final: bool,
    blob: bytes,
) -> bytes:
    try:
        return AESGCM(fek).decrypt(
            _nonce(nonce_prefix, index), blob, _aad(file_id, index, is_final)
        )
    except InvalidTag as e:
        raise CryptoError(f"chunk {index} failed authentication") from e


def new_file_material() -> tuple[bytes, bytes, bytes]:
    """Return (fek, file_id, nonce_prefix), all fresh random."""
    return os.urandom(KEY_LEN), os.urandom(16), os.urandom(NONCE_PREFIX_LEN)


# --------------------------------------------------------------------------- #
# Key wrapping: X25519 ECIES-style
# --------------------------------------------------------------------------- #
def _derive_wrap_key(shared: bytes, eph_pub: bytes, rcpt_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=b"vaultsync-x25519-wrap-v1" + eph_pub + rcpt_pub,
    ).derive(shared)


def _raw_pub(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def wrap_key_x25519(fek: bytes, recipient_pub: X25519PublicKey) -> bytes:
    """Return eph_pub(32) || nonce(12) || ct+tag(48)."""
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_pub(eph.public_key())
    shared = eph.exchange(recipient_pub)
    wk = _derive_wrap_key(shared, eph_pub, _raw_pub(recipient_pub))
    nonce = os.urandom(12)
    ct = AESGCM(wk).encrypt(nonce, fek, eph_pub)
    return eph_pub + nonce + ct


def unwrap_key_x25519(wrapped: bytes, recipient_priv: X25519PrivateKey) -> bytes:
    if len(wrapped) != 32 + 12 + KEY_LEN + TAG_LEN:
        raise CryptoError("malformed wrapped key")
    eph_pub, nonce, ct = wrapped[:32], wrapped[32:44], wrapped[44:]
    shared = recipient_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    wk = _derive_wrap_key(shared, eph_pub, _raw_pub(recipient_priv.public_key()))
    try:
        return AESGCM(wk).decrypt(nonce, ct, eph_pub)
    except InvalidTag as e:
        raise CryptoError("key unwrap failed (wrong key or tampered)") from e


# --------------------------------------------------------------------------- #
# Key wrapping: RSA-2048 OAEP (alternative)
# --------------------------------------------------------------------------- #
def generate_rsa_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def wrap_key_rsa(fek: bytes, pub: rsa.RSAPublicKey) -> bytes:
    return pub.encrypt(fek, _OAEP)


def unwrap_key_rsa(wrapped: bytes, priv: rsa.RSAPrivateKey) -> bytes:
    try:
        return priv.decrypt(wrapped, _OAEP)
    except ValueError as e:
        raise CryptoError("RSA unwrap failed") from e


# --------------------------------------------------------------------------- #
# Ed25519 signatures
# --------------------------------------------------------------------------- #
def sign(priv: Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)


def verify(pub: Ed25519PublicKey, sig: bytes, data: bytes) -> None:
    try:
        pub.verify(sig, data)
    except InvalidSignature as e:
        raise CryptoError("signature verification failed") from e
import io
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vaultsync import crypto


def _roundtrip(data: bytes, chunk: int):
    fek, fid, pre = crypto.new_file_material()
    blobs = list(crypto.encrypt_stream(io.BytesIO(data), fek, fid, pre, chunk))
    out = b"".join(
        crypto.decrypt_chunk(fek, fid, pre, i, i == len(blobs) - 1, b)
        for i, b in enumerate(blobs)
    )
    return fek, fid, pre, blobs, out


@pytest.mark.parametrize("size", [0, 1, 15, 16, 1000, 4096, 10_000])
def test_roundtrip_sizes(size):
    data = os.urandom(size)
    assert _roundtrip(data, 1024)[4] == data


def test_tamper_detected():
    fek, fid, pre, blobs, _ = _roundtrip(os.urandom(5000), 1024)
    bad = bytearray(blobs[1]); bad[0] ^= 1
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_chunk(fek, fid, pre, 1, False, bytes(bad))


def test_reorder_detected():
    fek, fid, pre, blobs, _ = _roundtrip(os.urandom(5000), 1024)
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_chunk(fek, fid, pre, 0, False, blobs[1])


def test_truncation_detected():
    """Dropping the true final chunk and treating the previous as final must fail."""
    fek, fid, pre, blobs, _ = _roundtrip(os.urandom(5000), 1024)
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_chunk(fek, fid, pre, len(blobs) - 2, True, blobs[-2])


def test_x25519_wrap():
    priv = X25519PrivateKey.generate()
    fek = os.urandom(32)
    assert crypto.unwrap_key_x25519(crypto.wrap_key_x25519(fek, priv.public_key()), priv) == fek


def test_x25519_wrong_key():
    fek = os.urandom(32)
    w = crypto.wrap_key_x25519(fek, X25519PrivateKey.generate().public_key())
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_key_x25519(w, X25519PrivateKey.generate())


def test_rsa_wrap():
    priv = crypto.generate_rsa_keypair()
    fek = os.urandom(32)
    assert crypto.unwrap_key_rsa(crypto.wrap_key_rsa(fek, priv.public_key()), priv) == fek


def test_signature():
    k = Ed25519PrivateKey.generate()
    sig = crypto.sign(k, b"hello")
    crypto.verify(k.public_key(), sig, b"hello")
    with pytest.raises(crypto.CryptoError):
        crypto.verify(k.public_key(), sig, b"hellp")
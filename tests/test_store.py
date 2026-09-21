import os

import pytest

from vaultsync import crypto, keys
from vaultsync.store import Store


@pytest.fixture
def store(tmp_path):
    ident = keys.generate_identity("alice")
    s = Store(tmp_path / "vault", ident)
    yield s
    s.close()


def test_add_get_roundtrip_multichunk(store, tmp_path):
    data = os.urandom(50_000)
    src = tmp_path / "in.bin"; src.write_bytes(data)
    store.add(src, "in.bin", chunk_size=4096)
    out = tmp_path / "out.bin"
    store.get("in.bin", out)
    assert out.read_bytes() == data
    assert store.list()[0]["chunk_count"] > 1


def test_empty_file(store, tmp_path):
    src = tmp_path / "e"; src.write_bytes(b"")
    store.add(src, "e")
    out = tmp_path / "e.out"; store.get("e", out)
    assert out.read_bytes() == b""


def test_disk_tamper_detected(store, tmp_path):
    src = tmp_path / "f"; src.write_bytes(os.urandom(10_000))
    fid = store.add(src, "f", chunk_size=2048)
    p = store._blob_path(fid, 1)
    b = bytearray(p.read_bytes()); b[5] ^= 0xFF; p.write_bytes(bytes(b))
    with pytest.raises(crypto.CryptoError):
        store.get("f", tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_metadata_tamper_detected(store, tmp_path):
    src = tmp_path / "f"; src.write_bytes(b"secret")
    store.add(src, "f")
    with store.db.tx() as c:
        c.execute("UPDATE files SET plaintext_size=999")
    with pytest.raises(crypto.CryptoError):
        store.get("f", tmp_path / "out")


def test_remove(store, tmp_path):
    src = tmp_path / "f"; src.write_bytes(b"x")
    store.add(src, "f")
    store.remove("f")
    assert store.list() == []
"""Encrypted file store: add / get / list / remove, streaming all the way through."""
from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import BinaryIO

from . import crypto
from .db import DB
from .keys import Identity, PeerCard


def _manifest(row: dict) -> bytes:
    """Canonical bytes that the owner signs. Binds every security-relevant field."""
    return b"".join(
        [
            crypto.MAGIC,
            row["file_id"],
            row["nonce_prefix"],
            row["wrapped_fek"],
            struct.pack(">QQQ", row["plaintext_size"], row["chunk_count"], row["chunk_size"]),
            bytes.fromhex(row["plaintext_sha256"]),
            row["name"].encode(),
        ]
    )


class Store:
    def __init__(self, root: Path, identity: Identity):
        self.root = root
        self.blobs = root / "blobs"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.db = DB(root / "state.db")
        self.identity = identity

    # ------------------------------------------------------------------ #
    def _blob_path(self, file_id: bytes, idx: int) -> Path:
        return self.blobs / file_id.hex() / f"{idx:08d}.chunk"

    def add(self, src_path: Path, name: str | None = None,
            chunk_size: int = crypto.CHUNK_SIZE) -> bytes:
        name = name or src_path.name
        fek, file_id, prefix = crypto.new_file_material()
        wrapped = crypto.wrap_key_x25519(fek, self.identity.enc_pub)
        (self.blobs / file_id.hex()).mkdir(parents=True, exist_ok=True)

        sha = hashlib.sha256()
        total = 0
        chunk_rows: list[tuple[int, int, str]] = []

        class _Hashing:
            """Wrap the source so we hash plaintext as it streams (single pass)."""
            def __init__(self, f: BinaryIO):
                self.f = f
            def read(self, n: int = -1) -> bytes:
                nonlocal total
                b = self.f.read(n)
                sha.update(b)
                total += len(b)
                return b

        with open(src_path, "rb") as f:
            for idx, blob in enumerate(
                crypto.encrypt_stream(_Hashing(f), fek, file_id, prefix, chunk_size)
            ):
                self._blob_path(file_id, idx).write_bytes(blob)
                chunk_rows.append((idx, len(blob), hashlib.sha256(blob).hexdigest()))

        row = {
            "name": name, "file_id": file_id, "nonce_prefix": prefix,
            "wrapped_fek": wrapped, "plaintext_size": total,
            "plaintext_sha256": sha.hexdigest(), "chunk_count": len(chunk_rows),
            "chunk_size": chunk_size, "owner_fp": self.identity.fingerprint,
        }
        row["signature"] = crypto.sign(self.identity.sig_priv, _manifest(row))

        with self.db.tx() as c:
            cur = c.execute(
                """INSERT INTO files (name,file_id,nonce_prefix,wrapped_fek,plaintext_size,
                   plaintext_sha256,chunk_count,chunk_size,owner_fp,signature)
                   VALUES (:name,:file_id,:nonce_prefix,:wrapped_fek,:plaintext_size,
                   :plaintext_sha256,:chunk_count,:chunk_size,:owner_fp,:signature)""",
                row,
            )
            c.executemany(
                "INSERT INTO chunks (file_row,idx,size,sha256) VALUES (?,?,?,?)",
                [(cur.lastrowid, i, s, h) for i, s, h in chunk_rows],
            )
        return file_id

    # ------------------------------------------------------------------ #
    def list(self) -> list[dict]:
        return [dict(r) for r in self.db.conn.execute(
            "SELECT id,name,file_id,plaintext_size,chunk_count,owner_fp,created_at "
            "FROM files ORDER BY id")]

    def _find(self, name_or_id: str) -> dict:
        r = self.db.conn.execute(
            "SELECT * FROM files WHERE name=? OR hex(file_id)=upper(?) "
            "ORDER BY id DESC LIMIT 1", (name_or_id, name_or_id)).fetchone()
        if not r:
            raise KeyError(f"no such file: {name_or_id}")
        return dict(r)

    # ------------------------------------------------------------------ #
    def trust_peer(self, card: PeerCard, card_json: str) -> None:
        with self.db.tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO peers (fingerprint,name,card_json) VALUES (?,?,?)",
                (card.fingerprint, card.name, card_json),
            )

    def _resolve_verifier(self, row: dict, owner_sig_pub=None):
        """Pick the key to verify the manifest signature with."""
        if owner_sig_pub is not None:
            return owner_sig_pub
        if row["owner_fp"] == self.identity.fingerprint:
            return self.identity.sig_pub
        peer = self.db.conn.execute(
            "SELECT card_json FROM peers WHERE fingerprint=?", (row["owner_fp"],)
        ).fetchone()
        if not peer:
            raise crypto.CryptoError(
                f"file was signed by unknown peer {row['owner_fp']}; "
                f"run `vaultsync trust <their-card.json>` first"
            )
        return PeerCard.from_dict(json.loads(peer[0])).sig_pub

    def get(self, name_or_id: str, dest: Path, owner_sig_pub=None) -> None:
        """Verify signature, unwrap key, decrypt chunk-by-chunk to dest (streaming)."""
        row = self._find(name_or_id)
        verifier = self._resolve_verifier(row, owner_sig_pub)
        crypto.verify(verifier, row["signature"], _manifest(row))

        fek = crypto.unwrap_key_x25519(row["wrapped_fek"], self.identity.enc_priv)
        sha = hashlib.sha256()
        tmp = dest.with_suffix(dest.suffix + ".part")
        try:
            with open(tmp, "wb") as out:
                for idx in range(row["chunk_count"]):
                    blob = self._blob_path(row["file_id"], idx).read_bytes()
                    expected = self.db.conn.execute(
                        "SELECT sha256 FROM chunks WHERE file_row=? AND idx=?",
                        (row["id"], idx)).fetchone()[0]
                    if hashlib.sha256(blob).hexdigest() != expected:
                        raise crypto.CryptoError(f"chunk {idx} hash mismatch on disk")
                    pt = crypto.decrypt_chunk(
                        fek, row["file_id"], row["nonce_prefix"], idx,
                        idx == row["chunk_count"] - 1, blob)
                    sha.update(pt)
                    out.write(pt)
            if sha.hexdigest() != row["plaintext_sha256"]:
                raise crypto.CryptoError("final plaintext hash mismatch")
            os.replace(tmp, dest)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    def remove(self, name_or_id: str) -> None:
        row = self._find(name_or_id)
        d = self.blobs / row["file_id"].hex()
        for p in d.glob("*.chunk"):
            p.unlink()
        d.rmdir()
        with self.db.tx() as c:
            c.execute("DELETE FROM files WHERE id=?", (row["id"],))

    def close(self) -> None:
        self.db.close()

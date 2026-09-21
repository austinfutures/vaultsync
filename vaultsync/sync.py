"""Public-key sync engine: push encrypted chunks to a peer's vault.

Flow
----
1. Sender looks up which files the peer is missing (by file_id) and, for files
   the peer already has partially, which chunk indices are missing (resume).
2. For a *new* file, the sender re-wraps the FEK for the peer's X25519 key
   (the sender must hold the FEK: it unwraps with its own private key first).
3. Only ciphertext chunks cross the wire; each chunk's SHA-256 is verified by
   the receiver against the manifest, then GCM authenticates on read.
4. The manifest is signed by the *sender's* Ed25519 key. The receiver verifies
   the signature against the sender's pinned peer card before accepting.

Transport here is a local directory (the peer's vault path) to keep the project
self-contained; the `Transport` seam makes swapping in TCP/HTTP straightforward.
"""
from __future__ import annotations

import hashlib
import shutil
import struct
from pathlib import Path

from . import crypto
from .keys import PeerCard
from .store import Store, _manifest


def _resign_for_peer(src: Store, row: dict, peer: PeerCard) -> tuple[bytes, bytes]:
    """Unwrap FEK with our key, re-wrap for peer, sign new manifest. Returns (wrapped, sig)."""
    fek = crypto.unwrap_key_x25519(row["wrapped_fek"], src.identity.enc_priv)
    wrapped = crypto.wrap_key_x25519(fek, peer.enc_pub)
    m = dict(row)
    m["wrapped_fek"] = wrapped
    return wrapped, crypto.sign(src.identity.sig_priv, _manifest(m))


def push(src: Store, dst_root: Path, dst_identity_pub_card: PeerCard) -> dict:
    """Push all of src's files to the vault at dst_root, addressed to dst's public key.

    The receiving vault is opened *without* its private key: the sender only
    writes ciphertext + metadata. Returns a stats dict.
    """
    from .db import DB

    dst_db = DB(dst_root / "state.db")
    blobs = dst_root / "blobs"
    blobs.mkdir(parents=True, exist_ok=True)
    stats = {"files_new": 0, "chunks_sent": 0, "chunks_skipped": 0}

    try:
        for row in src.db.conn.execute("SELECT * FROM files ORDER BY id"):
            row = dict(row)
            existing = dst_db.conn.execute(
                "SELECT id FROM files WHERE file_id=?", (row["file_id"],)).fetchone()

            if existing:
                dst_row_id = existing[0]
            else:
                wrapped, sig = _resign_for_peer(src, row, dst_identity_pub_card)
                with dst_db.tx() as c:
                    cur = c.execute(
                        """INSERT INTO files (name,file_id,nonce_prefix,wrapped_fek,
                           plaintext_size,plaintext_sha256,chunk_count,chunk_size,
                           owner_fp,signature)
                           VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (row["name"], row["file_id"], row["nonce_prefix"], wrapped,
                         row["plaintext_size"], row["plaintext_sha256"],
                         row["chunk_count"], row["chunk_size"],
                         src.identity.fingerprint, sig))
                    dst_row_id = cur.lastrowid
                stats["files_new"] += 1

            have = {r[0] for r in dst_db.conn.execute(
                "SELECT idx FROM chunks WHERE file_row=?", (dst_row_id,))}
            (blobs / row["file_id"].hex()).mkdir(parents=True, exist_ok=True)

            for ch in src.db.conn.execute(
                    "SELECT idx,size,sha256 FROM chunks WHERE file_row=? ORDER BY idx",
                    (row["id"],)):
                if ch["idx"] in have:
                    stats["chunks_skipped"] += 1
                    continue
                s = src._blob_path(row["file_id"], ch["idx"])
                d = blobs / row["file_id"].hex() / f"{ch['idx']:08d}.chunk"
                tmp = d.with_suffix(".tmp")
                shutil.copyfile(s, tmp)  # streamed by the OS, not loaded into RAM
                h = hashlib.sha256()
                with open(tmp, "rb") as f:
                    for block in iter(lambda: f.read(65536), b""):
                        h.update(block)
                if h.hexdigest() != ch["sha256"]:
                    tmp.unlink()
                    raise crypto.CryptoError(f"chunk {ch['idx']} corrupted in transit")
                tmp.replace(d)
                with dst_db.tx() as c:
                    c.execute("INSERT INTO chunks (file_row,idx,size,sha256) VALUES (?,?,?,?)",
                              (dst_row_id, ch["idx"], ch["size"], ch["sha256"]))
                stats["chunks_sent"] += 1

            with src.db.tx() as c:
                c.execute("INSERT INTO sync_log (peer_fp,file_id,chunks_sent) VALUES (?,?,?)",
                          (dst_identity_pub_card.fingerprint, row["file_id"], stats["chunks_sent"]))
    finally:
        dst_db.close()
    return stats
import os

from vaultsync import keys, sync
from vaultsync.store import Store


def test_push_and_recipient_decrypts(tmp_path):
    alice_id = keys.generate_identity("alice")
    bob_id = keys.generate_identity("bob")

    alice = Store(tmp_path / "alice", alice_id)
    data = os.urandom(20_000)
    src = tmp_path / "doc.bin"; src.write_bytes(data)
    alice.add(src, "doc.bin", chunk_size=4096)

    bob_card = keys.PeerCard.from_dict(bob_id.public_card())
    stats = sync.push(alice, tmp_path / "bob", bob_card)
    assert stats["files_new"] == 1 and stats["chunks_sent"] > 1

    bob = Store(tmp_path / "bob", bob_id)
    out = tmp_path / "out.bin"
    bob.get("doc.bin", out, owner_sig_pub=alice_id.sig_pub)
    assert out.read_bytes() == data

    # idempotent resume: second push sends nothing
    again = sync.push(alice, tmp_path / "bob", bob_card)
    assert again["files_new"] == 0 and again["chunks_sent"] == 0
    alice.close(); bob.close()


def test_wrong_recipient_cannot_decrypt(tmp_path):
    import pytest
    from vaultsync import crypto
    alice_id, bob_id, eve_id = (keys.generate_identity(n) for n in ("a", "b", "e"))
    alice = Store(tmp_path / "alice", alice_id)
    src = tmp_path / "s"; src.write_bytes(b"top secret")
    alice.add(src, "s")
    sync.push(alice, tmp_path / "bob", keys.PeerCard.from_dict(bob_id.public_card()))
    eve = Store(tmp_path / "bob", eve_id)  # Eve opens Bob's vault with her own key
    with pytest.raises(crypto.CryptoError):
        eve.get("s", tmp_path / "o", owner_sig_pub=alice_id.sig_pub)
    alice.close(); eve.close()

def test_recipient_needs_trusted_peer(tmp_path):
    import json
    import pytest
    from vaultsync import crypto
    alice_id, bob_id = keys.generate_identity("alice"), keys.generate_identity("bob")
    alice = Store(tmp_path / "alice", alice_id)
    src = tmp_path / "s"; src.write_bytes(b"hi")
    alice.add(src, "s")
    sync.push(alice, tmp_path / "bob", keys.PeerCard.from_dict(bob_id.public_card()))

    bob = Store(tmp_path / "bob", bob_id)
    with pytest.raises(crypto.CryptoError, match="unknown peer"):
        bob.get("s", tmp_path / "o")            # not trusted yet -> refuse

    card = alice_id.public_card()
    bob.trust_peer(keys.PeerCard.from_dict(card), json.dumps(card))
    bob.get("s", tmp_path / "o")                # now works
    assert (tmp_path / "o").read_bytes() == b"hi"
    alice.close(); bob.close()
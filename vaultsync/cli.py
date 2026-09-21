"""vaultsync command-line interface."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import crypto, keys, sync
from .store import Store

DEFAULT_HOME = Path(".vault")


def _pass(args) -> bytes:
    import os
    env = os.environ.get("VAULTSYNC_PASSPHRASE")
    return (env or getpass.getpass("Passphrase: ")).encode()


def _open(args) -> Store:
    home = Path(args.home)
    ident = keys.load_identity(home / "identity", _pass(args))
    return Store(home, ident)


def cmd_init(args) -> None:
    home = Path(args.home)
    if (home / "identity" / "identity.json").exists():
        sys.exit("vault already initialised")
    ident = keys.generate_identity(args.name)
    keys.save_identity(ident, home / "identity", _pass(args))
    print(f"Initialised vault at {home}")
    print(f"Fingerprint: {ident.fingerprint}")


def cmd_export_card(args) -> None:
    card = json.loads((Path(args.home) / "identity" / "identity.json").read_text())
    Path(args.out).write_text(json.dumps(card, indent=2))
    print(f"Wrote public identity card to {args.out}")


def cmd_add(args) -> None:
    s = _open(args)
    fid = s.add(Path(args.file), args.name)
    print(f"Encrypted and stored {args.file} (id={fid.hex()})")
    s.close()


def cmd_ls(args) -> None:
    s = _open(args)
    for r in s.list():
        print(f"{r['file_id'].hex()[:12]}  {r['plaintext_size']:>12}B  "
              f"{r['chunk_count']:>4} chunks  {r['name']}")
    s.close()


def cmd_get(args) -> None:
    s = _open(args)
    s.get(args.name, Path(args.out))
    print(f"Decrypted, verified, wrote {args.out}")
    s.close()


def cmd_rm(args) -> None:
    s = _open(args)
    s.remove(args.name)
    print(f"Removed {args.name}")
    s.close()


def cmd_push(args) -> None:
    s = _open(args)
    peer = keys.load_peer_card(Path(args.peer_card))
    print(f"Pushing to {peer.name} ({peer.fingerprint})")
    stats = sync.push(s, Path(args.dest), peer)
    print(json.dumps(stats, indent=2))
    s.close()

def cmd_trust(args) -> None:
    s = _open(args)
    path = Path(args.card)
    card = keys.load_peer_card(path)
    s.trust_peer(card, path.read_text())
    print(f"Trusted {card.name}")
    print(f"Fingerprint: {card.fingerprint}")
    print("Verify this fingerprint with them out-of-band (call, in person) before relying on it.")
    s.close()

def main() -> None:
    p = argparse.ArgumentParser(prog="vaultsync", description=__doc__)
    p.add_argument("--home", default=str(DEFAULT_HOME), help="vault directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("init", help="create identity + vault"); a.add_argument("name")
    a.set_defaults(fn=cmd_init)

    a = sub.add_parser("export-card", help="export public identity card")
    a.add_argument("out"); a.set_defaults(fn=cmd_export_card)

    a = sub.add_parser("add", help="encrypt a file into the vault")
    a.add_argument("file"); a.add_argument("--name"); a.set_defaults(fn=cmd_add)

    a = sub.add_parser("ls", help="list vault contents"); a.set_defaults(fn=cmd_ls)

    a = sub.add_parser("get", help="decrypt a file out of the vault")
    a.add_argument("name"); a.add_argument("out"); a.set_defaults(fn=cmd_get)

    a = sub.add_parser("rm", help="remove a file"); a.add_argument("name")
    a.set_defaults(fn=cmd_rm)

    a = sub.add_parser("push", help="sync encrypted chunks to a peer vault")
    a.add_argument("peer_card"); a.add_argument("dest"); a.set_defaults(fn=cmd_push)

    a = sub.add_parser("trust", help="pin a peer's public identity card")
    a.add_argument("card"); a.set_defaults(fn=cmd_trust)
    
    args = p.parse_args()
    try:
        args.fn(args)
    except (crypto.CryptoError, KeyError, ValueError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
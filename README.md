<!-- STREAMING_CHUNK:Introducing VaultSync and core overview... -->
# vaultsync

Encrypted local file store and public-key sync engine.

`vaultsync` encrypts files at rest with authenticated chunked AES-256-GCM, wraps each file's key to recipients using X25519, signs file manifests with Ed25519, and syncs only ciphertext between vaults. State is tracked in SQLite, and files are streamed in chunks so they are never loaded into memory in full.

<!-- STREAMING_CHUNK:Listing key security and performance features... -->
## Features

- **Hybrid encryption.** Each file gets a fresh random 256-bit key. That key is wrapped per recipient with ephemeral X25519 ECDH + HKDF-SHA256 and AES-256-GCM. An RSA-2048 OAEP wrap is also included for interop.
- **Chunked streaming AEAD.** Files are split into 1 MiB chunks, each encrypted with AES-256-GCM. The chunk index and a final-chunk flag are bound in as associated data, which prevents chunk reordering, truncation, and splicing across files.
- **Signed manifests.** Every file has an Ed25519 signature over a canonical manifest (file ID, nonce prefix, wrapped key, sizes, plaintext hash, name). Metadata tampering is detected before any decryption happens.
- **Peer pinning.** Recipients import a sender's public identity card and verify signatures against the pinned key. Files from unknown signers are refused.
- **Passphrase-protected keys.** Private keys are stored as PKCS8 PEM encrypted under your passphrase, with `0600` file permissions.
- **Resumable, idempotent sync.** SQLite (WAL mode) tracks files, per-chunk SHA-256 hashes, peers, and a sync log. Re-running a push sends only missing chunks.
- **Defense in depth on read.** Manifest signature, per-chunk on-disk hash, per-chunk GCM authentication, and a final whole-file hash are all checked. A failed read never leaves a partial output file behind.

<!-- STREAMING_CHUNK:Providing installation instructions... -->
## Install

Requires Python 3.10+.

```bash
git clone https://github.com/<austinfutures>/vaultsync.git
cd vaultsync
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

<!-- STREAMING_CHUNK:Outlining quick start walk-through... -->
## Quick start

Alice encrypts a file and syncs it to Bob. Bob pins Alice's identity, then decrypts.

```bash
export VAULTSYNC_PASSPHRASE='correct horse battery staple'

# Each party creates an identity
vaultsync --home alice init alice
vaultsync --home bob   init bob

# Exchange public identity cards (safe to share; contain public keys only)
vaultsync --home alice export-card alice.card.json
vaultsync --home bob   export-card bob.card.json

# Alice encrypts a file and pushes ciphertext to Bob's vault
echo "hello vault" > note.txt
vaultsync --home alice add note.txt
vaultsync --home alice ls
vaultsync --home alice push bob.card.json bob

# Bob refuses until he pins Alice's identity
vaultsync --home bob get note.txt note.out.txt     # Error: unknown peer
vaultsync --home bob trust alice.card.json
vaultsync --home bob get note.txt note.out.txt
cat note.out.txt                                   # hello vault
```

If `VAULTSYNC_PASSPHRASE` is not set, `vaultsync` prompts for the passphrase interactively.

<!-- STREAMING_CHUNK:Detailing CLI command reference... -->
## Commands

| Command | Description |
| --- | --- |
| `init <name>` | Create an identity (X25519 + Ed25519 keypairs) and vault |
| `export-card <out>` | Write your public identity card to a JSON file |
| `add <file> [--name N]` | Encrypt a file into the vault |
| `ls` | List vault contents |
| `get <name> <out>` | Verify, decrypt, and write a file out |
| `rm <name>` | Remove a file from the vault |
| `push <peer-card> <dest>` | Sync encrypted chunks to a peer's vault directory |
| `trust <card>` | Pin a peer's public identity card |

*Use `--home <dir>` before the command to select a custom vault directory (default is `.vault`).*

<!-- STREAMING_CHUNK:Explaining underlying architectural workflow... -->
## How it works

- **Encrypting a file.** A random file key (FEK), file ID, and nonce prefix are generated. The file is read in 1 MiB chunks. Each chunk is encrypted with AES-256-GCM using nonce = 4-byte prefix + 8-byte counter, with associated data binding the file ID, chunk index, and whether it is the final chunk. The FEK is wrapped to the owner's X25519 public key. The owner signs a manifest covering all security-relevant fields.
- **Syncing to a peer.** The sender unwraps the FEK with its own private key, re-wraps it for the recipient's X25519 public key, signs a new manifest, and copies only the chunks the recipient is missing. Each chunk is hash-checked after copy. Only ciphertext and metadata cross the boundary.
- **Reading a file.** The recipient looks up the signer in its pinned peers and verifies the manifest signature. It then unwraps the FEK, and for each chunk checks the stored hash, authenticates and decrypts with GCM, and streams plaintext to a temporary file. The whole-file hash is verified before the temp file is atomically renamed into place.

<!-- STREAMING_CHUNK:Structuring project file layout... -->
## Project layout

```text
vaultsync/
├── crypto.py    # Chunked AES-256-GCM, X25519/RSA key wrap, Ed25519 sign/verify
├── keys.py      # Identity generation, encrypted key storage, peer cards, fingerprints
├── store.py     # Encrypted file store (add/get/list/remove), manifest signing, peer pinning
├── db.py        # SQLite schema and transaction helper
├── sync.py      # Push engine: re-wrap keys, resumable chunk transfer
├── cli.py       # Command-line interface
└── tests/       # Crypto, store, and sync tests
```

<!-- STREAMING_CHUNK:Describing testing procedures and security coverage... -->
## Tests

```bash
pytest -v
```

The test suite covers round-trips across chunk boundaries, empty files, ciphertext tampering, chunk reordering, truncation, wrong-key unwrap, on-disk corruption, metadata tampering, wrong-recipient decryption, unpinned senders, and idempotent resume.

<!-- STREAMING_CHUNK:Documenting threat model and security guarantees... -->
## Threat model

### Protects against:
- An attacker who reads vault storage or intercepts synced chunks (ciphertext only).
- Modification, reordering, truncation, or splicing of chunks (GCM with index and final-flag AAD, plus per-chunk hashes).
- Tampering with file metadata (Ed25519-signed manifest).
- A recipient other than the intended one decrypting a synced file (per-recipient key wrapping).
- Files from senders the recipient has not pinned.

### Does not protect against:
- Key compromise or a weak passphrase. Private keys are only as strong as the passphrase protecting them.
- Fingerprint substitution at pinning time. Peers are trusted on first use, so verify fingerprints out-of-band (in person or over a call).
- Metadata leakage. File names, sizes, and chunk counts are visible in the SQLite state.
- Rollback or replay of an older valid version of a file.
- Forward secrecy for data at rest, key rotation, or key revocation.

<!-- STREAMING_CHUNK:Listing system limitations and licensing information... -->
## Limitations

- Sync transport is currently a local directory. The push logic is isolated in `sync.py`, so a network transport (TCP/HTTP) can be added without touching the crypto or store layers.
- The sender must hold the file key to re-wrap it for a recipient.
- Not independently audited. Intended as an educational and portfolio project; do not use it to protect data you cannot afford to lose.

## License

[MIT](LICENSE)

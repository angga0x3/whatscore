#!/usr/bin/env python3
"""Independent X3DH vector generator for WhatsCore.

Implements PF-050..PF-052 from the finding text using `cryptography`
(X25519 + HKDF-SHA256). Synthetic keys from fixed public seed bytes only.
Regenerate with:

    python3 tests/fixtures/generate_signal_vectors.py \
        > tests/fixtures/signal_vectors.json
"""

import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SALT = None
INFO = b"WhisperText"
LENGTH = 64
RAW = serialization.Encoding.Raw
PUBLIC = serialization.PublicFormat.Raw
PRIVATE = serialization.PrivateFormat.Raw


def private(seed):
    return X25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def public(key):
    return key.public_key().public_bytes(RAW, PUBLIC)


def exchange(key, peer_public):
    return key.exchange(X25519PublicKey.from_public_bytes(peer_public))


def main():
    alice = private(0x11)
    bob = private(0x22)
    signed = private(0x33)
    one_time = private(0x44)
    ephemeral = private(0x55)

    dh1 = exchange(alice, public(signed))
    dh2 = exchange(ephemeral, public(bob))
    dh3 = exchange(ephemeral, public(signed))
    dh4 = exchange(ephemeral, public(one_time))
    master = b"\xff" * 32 + dh1 + dh2 + dh3 + dh4
    derived = HKDF(
        algorithm=hashes.SHA256(), length=LENGTH, salt=SALT, info=INFO
    ).derive(master)

    vector = {
        "name": "with one-time prekey",
        "alice_identity_priv": alice.private_bytes(RAW, PRIVATE, serialization.NoEncryption()).hex(),
        "alice_identity_pub": public(alice).hex(),
        "bob_identity_priv": bob.private_bytes(RAW, PRIVATE, serialization.NoEncryption()).hex(),
        "bob_identity_pub": public(bob).hex(),
        "bob_signed_priv": signed.private_bytes(RAW, PRIVATE, serialization.NoEncryption()).hex(),
        "bob_signed_pub": public(signed).hex(),
        "bob_one_time_priv": one_time.private_bytes(RAW, PRIVATE, serialization.NoEncryption()).hex(),
        "bob_one_time_pub": public(one_time).hex(),
        "ephemeral_priv": ephemeral.private_bytes(RAW, PRIVATE, serialization.NoEncryption()).hex(),
        "ephemeral_pub": public(ephemeral).hex(),
        "dh1": dh1.hex(),
        "dh2": dh2.hex(),
        "dh3": dh3.hex(),
        "dh4": dh4.hex(),
        "root_key": derived[:32].hex(),
        "chain_key": derived[32:].hex(),
    }
    print(json.dumps({"info": INFO.decode(), "vectors": [vector]}, indent=2))


if __name__ == "__main__":
    main()

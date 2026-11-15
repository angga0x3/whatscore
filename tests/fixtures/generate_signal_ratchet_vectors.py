#!/usr/bin/env python3
"""Independent Double Ratchet key-schedule vectors for WhatsCore.

Implements PF-054..PF-056 with X25519 + HKDF-SHA256 + HMAC-SHA256 from fixed
synthetic keys. Regenerate with:

    python3 tests/fixtures/generate_signal_ratchet_vectors.py \
        > tests/fixtures/signal_ratchet_vectors.json
"""

import hashlib
import hmac
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RAW = serialization.Encoding.Raw
PRIVATE = serialization.PrivateFormat.Raw
PUBLIC = serialization.PublicFormat.Raw
RATCHET_INFO = b"WhisperRatchet"
MESSAGE_INFO = b"WhisperMessageKeys"


def private(seed):
    return X25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def public(key):
    return key.public_key().public_bytes(RAW, PUBLIC)


def hkdf(secret, salt, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def chain_mac(chain, seed):
    return hmac.new(chain, bytes([seed]), hashlib.sha256).digest()


def main():
    root = bytes([0x66]) * 32
    alice = private(0x77)
    bob = private(0x88)

    shared = alice.exchange(X25519PublicKey.from_public_bytes(public(bob)))
    derived = hkdf(shared, root, RATCHET_INFO, 64)
    next_root, chain = derived[:32], derived[32:]
    start_chain = chain

    steps = []
    for index in range(3):
        message_key = chain_mac(chain, 1)
        material = hkdf(message_key, None, MESSAGE_INFO, 80)
        steps.append(
            {
                "index": index,
                "message_key": message_key.hex(),
                "next_chain": chain_mac(chain, 2).hex(),
                "cipher_key": material[:32].hex(),
                "mac_key": material[32:64].hex(),
                "iv": material[64:80].hex(),
            }
        )
        chain = chain_mac(chain, 2)

    document = {
        "root_key": root.hex(),
        "alice_ratchet_priv": alice.private_bytes(RAW, PRIVATE, serialization.NoEncryption()).hex(),
        "alice_ratchet_pub": public(alice).hex(),
        "bob_ratchet_priv": bob.private_bytes(RAW, PRIVATE, serialization.NoEncryption()).hex(),
        "bob_ratchet_pub": public(bob).hex(),
        "shared_secret": shared.hex(),
        "next_root_key": next_root.hex(),
        "chain_key": start_chain.hex(),
        "steps": steps,
    }
    print(json.dumps(document, indent=2))


if __name__ == "__main__":
    main()

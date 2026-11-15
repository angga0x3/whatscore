#!/usr/bin/env python3
"""Independent SignalMessage vector generator for WhatsCore.

Implements PF-060..PF-062 (protobuf envelope, truncated MAC, AES-CBC payload)
with fixed synthetic keys. Regenerate with:

    python3 tests/fixtures/generate_signal_message_vectors.py \
        > tests/fixtures/signal_message_vectors.json
"""

import hashlib
import hmac
import json

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CIPHER_KEY = bytes([0xAA]) * 32
MAC_KEY = bytes([0xBB]) * 32
IV = bytes([0xCC]) * 16
RATCHET = bytes([0xDD]) * 32
SENDER = bytes([0x11]) * 32
RECEIVER = bytes([0x22]) * 32
COUNTER = 5
PREVIOUS = 2
PLAINTEXT = b"halo signal"


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field_bytes(number, value):
    return bytes([(number << 3) | 2]) + varint(len(value)) + value


def field_varint(number, value):
    return bytes([(number << 3) | 0]) + varint(value)


def main():
    padder = padding.PKCS7(128).padder()
    padded = padder.update(PLAINTEXT) + padder.finalize()
    encryptor = Cipher(algorithms.AES(CIPHER_KEY), modes.CBC(IV)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    envelope = (
        field_bytes(1, b"\x05" + RATCHET)
        + field_varint(2, COUNTER)
        + field_varint(3, PREVIOUS)
        + field_bytes(4, ciphertext)
    )
    body = b"\x33" + envelope
    mac = hmac.new(
        MAC_KEY, b"\x05" + SENDER + b"\x05" + RECEIVER + body, hashlib.sha256
    ).digest()[:8]

    print(
        json.dumps(
            {
                "cipher_key": CIPHER_KEY.hex(),
                "mac_key": MAC_KEY.hex(),
                "iv": IV.hex(),
                "ratchet_key": RATCHET.hex(),
                "sender_identity": SENDER.hex(),
                "receiver_identity": RECEIVER.hex(),
                "counter": COUNTER,
                "previous_counter": PREVIOUS,
                "plaintext": PLAINTEXT.hex(),
                "ciphertext": ciphertext.hex(),
                "wire": (body + mac).hex(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

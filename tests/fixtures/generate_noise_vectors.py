#!/usr/bin/env python3
"""Independent reference vector generator for the WhatsCore Noise handshake.

SYNTHETIC test data only: every key below is derived from a fixed public
seed string; nothing here is or was ever a real WhatsApp credential.

This script implements the algorithm documented in docs/protocol/noise.md
findings PF-004..PF-008 directly from the finding text (it is written
independently of the Go implementation and shares no code with it):

  PF-004  h0 = raw 32 bytes "Noise_XX_25519_AESGCM_SHA256\\0\\0\\0\\0"
          (never re-hashed); hash chain h = SHA256(h || data) over the
          connection header, both ephemerals, and every handshake
          ciphertext.
  PF-005  handshake AEAD = AES-256-GCM, key starts as h0, nonce =
          12 bytes: bytes 0-7 zero, bytes 8-11 big-endian shared
          encrypt/decrypt counter, AAD = running hash; counter resets on
          every key mix.
  PF-006  after each DH: (write, read) = HKDF-SHA256(ikm=X25519(priv,
          pub), salt=salt, info=empty, L=64); salt = write; key = read.
  PF-007  message order ee / es / se with the ciphertexts of
          serverHello.static, serverHello.payload, clientFinish.static,
          clientFinish.payload.
  PF-008  final transport keys (write, read) = HKDF-SHA256(ikm=empty,
          salt=salt, info=empty, L=64); post-handshake frames use the
          same counter-IV layout with empty AAD.

Both roles (client and server) are simulated independently; the emitted
JSON records the chain values, the key schedule after every mix, the four
handshake ciphertexts, the final transport keys, and one post-handshake
transport frame per direction. A Go test (protocol/noise) asserts that
the implementation reproduces every value byte-for-byte.

Requires the `cryptography` package for AES-256-GCM (HKDF is stdlib
hmac/hashlib). X25519 uses the library when available but is additionally
cross-checked against the RFC 7748 reference Montgomery ladder implemented
below, so the scalar multiplication rests on two independent
implementations.
"""

import hashlib
import hmac
import json
import os
import sys

PATTERN = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"  # PF-004, raw 32 bytes
CONN_HEADER = bytes([0x57, 0x41, 0x06, 0x03])
SEED_PREFIX = b"whatscore-vector-seed-"
CLIENT_PAYLOAD = b"whatscore-vector-client-payload-1"
CERT_PAYLOAD = b"whatscore-vector-synthetic-cert-chain-payload"
BASEPOINT = (9).to_bytes(32, "little")

_P = 2**255 - 19


def x25519_ladder(k: bytes, u: bytes) -> bytes:
    """RFC 7748 §5 reference Montgomery ladder, self-contained."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(bytes(k), "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = k_t
        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = (x1 * pow((da - cb) % _P, 2, _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + 121665 * e) % _P)) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    def aead_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    def x25519(priv: bytes, pub: bytes) -> bytes:
        via_lib = X25519PrivateKey.from_private_bytes(priv).exchange(
            X25519PublicKey.from_public_bytes(pub)
        )
        via_ladder = x25519_ladder(priv, pub)
        if via_lib != via_ladder:
            raise SystemExit("internal error: cryptography X25519 disagrees with RFC 7748 ladder")
        return via_lib

    BACKEND = "python-cryptography + rfc7748-ladder-crosscheck"
except ImportError:
    raise SystemExit("AES-256-GCM requires the `cryptography` package; pip install it first")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256, implemented directly on stdlib hmac."""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def clamped_scalar(label: bytes) -> bytes:
    """Deterministic RFC 7748-clamped scalar from a fixed public seed."""
    k = bytearray(hashlib.sha256(SEED_PREFIX + label).digest())
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def iv(counter: int) -> bytes:
    """PF-005/PF-008 nonce: 8 zero bytes + big-endian uint32 counter."""
    return b"\x00" * 8 + counter.to_bytes(4, "big")


class Handshake:
    """One role's view of the PF-004..PF-006 state machine."""

    def __init__(self):
        self.hash = PATTERN  # raw, not re-hashed (PF-004)
        self.salt = PATTERN
        self.key = PATTERN  # handshake key starts as h0 (PF-005)
        self.counter = 0

    def authenticate(self, data: bytes, label: str, chain: dict) -> None:
        self.hash = hashlib.sha256(self.hash + data).digest()  # PF-004
        chain[label] = self.hash.hex()

    def encrypt(self, plaintext: bytes) -> bytes:
        ct = aead_seal(self.key, iv(self.counter), plaintext, self.hash)  # PF-005
        self.hash = hashlib.sha256(self.hash + ct).digest()
        self.counter += 1
        return ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        pt = aead_open(self.key, iv(self.counter), ciphertext, self.hash)  # PF-005
        self.hash = hashlib.sha256(self.hash + ciphertext).digest()
        self.counter += 1
        return pt

    def mix_into_key(self, dh_secret: bytes, label: str, mixes: list) -> None:
        okm = hkdf_sha256(dh_secret, self.salt, b"", 64)  # PF-006
        write, read = okm[:32], okm[32:]
        self.salt = write
        self.key = read
        self.counter = 0
        mixes.append(
            {
                "label": label,
                "dh_secret": dh_secret.hex(),
                "write": write.hex(),
                "read": read.hex(),
            }
        )

    def finish(self) -> tuple:
        okm = hkdf_sha256(b"", self.salt, b"", 64)  # PF-008
        return okm[:32], okm[32:]


def hexs(b: bytes) -> str:
    return b.hex()


def main() -> int:
    chain: dict = {}
    mixes: list = []

    # Deterministic synthetic keys (PF-004..PF-008 vector inputs).
    client_eph_priv = clamped_scalar(b"client-ephemeral-1")
    server_eph_priv = clamped_scalar(b"server-ephemeral-1")
    server_static_priv = clamped_scalar(b"server-static-1")
    client_noise_priv = clamped_scalar(b"client-noise-1")
    client_eph_pub = x25519(client_eph_priv, BASEPOINT)
    server_eph_pub = x25519(server_eph_priv, BASEPOINT)
    server_static_pub = x25519(server_static_priv, BASEPOINT)
    client_noise_pub = x25519(client_noise_priv, BASEPOINT)

    # ---- client role -----------------------------------------------------
    client = Handshake()
    client.authenticate(CONN_HEADER, "after_conn_header", chain)  # PF-004
    client.authenticate(client_eph_pub, "after_client_ephemeral", chain)  # PF-004

    # ---- server role (msg2) ----------------------------------------------
    server = Handshake()
    server.authenticate(CONN_HEADER, "server_after_conn_header", chain)
    server.authenticate(client_eph_pub, "server_after_client_ephemeral", chain)
    server.authenticate(server_eph_pub, "after_server_ephemeral", chain)  # PF-004

    server.mix_into_key(x25519(server_eph_priv, client_eph_pub), "ee", mixes)  # PF-006
    ct_server_static = server.encrypt(server_static_pub)
    chain["after_server_static_ciphertext"] = server.hash.hex()
    server.mix_into_key(x25519(server_static_priv, client_eph_pub), "es", mixes)
    ct_cert = server.encrypt(CERT_PAYLOAD)
    chain["after_server_payload_ciphertext"] = server.hash.hex()

    # ---- client consumes msg2 ---------------------------------------------
    client.authenticate(server_eph_pub, "client_after_server_ephemeral", chain)
    client.mix_into_key(x25519(client_eph_priv, server_eph_pub), "client_ee", mixes)
    assert chain["after_server_ephemeral"] == chain["client_after_server_ephemeral"]
    dec_server_static = client.decrypt(ct_server_static)
    chain["client_after_server_static_ciphertext"] = client.hash.hex()
    assert dec_server_static == server_static_pub
    client.mix_into_key(x25519(client_eph_priv, server_static_pub), "client_es", mixes)
    dec_cert = client.decrypt(ct_cert)
    chain["client_after_server_payload_ciphertext"] = client.hash.hex()
    assert dec_cert == CERT_PAYLOAD

    # ---- client produces msg3 ---------------------------------------------
    ct_client_static = client.encrypt(client_noise_pub)
    chain["after_client_static_ciphertext"] = client.hash.hex()
    client.mix_into_key(x25519(client_noise_priv, server_eph_pub), "se", mixes)
    ct_client_payload = client.encrypt(CLIENT_PAYLOAD)
    chain["after_client_payload_ciphertext"] = client.hash.hex()

    # ---- server consumes msg3 ----------------------------------------------
    dec_client_static = server.decrypt(ct_client_static)
    assert server.hash.hex() == chain["after_client_static_ciphertext"]
    assert dec_client_static == client_noise_pub
    server.mix_into_key(x25519(server_eph_priv, client_noise_pub), "server_se", mixes)
    dec_client_payload = server.decrypt(ct_client_payload)
    assert server.hash.hex() == chain["after_client_payload_ciphertext"]
    assert dec_client_payload == CLIENT_PAYLOAD

    # ---- final transport keys (PF-008) --------------------------------------
    # Both roles run the identical HKDF over the identical salt, so the raw
    # halves are equal; the server *uses* them swapped (PF-008: server
    # perspective swaps write/read): it reads with the first half and
    # writes with the second.
    client_write, client_read = client.finish()
    server_raw_write, server_raw_read = server.finish()
    assert client_write == server_raw_write
    assert client_read == server_raw_read

    # ---- post-handshake transport frames (PF-008) ---------------------------
    frame_plain_c2s = b"whatscore-vector-transport-frame-client-1"
    frame_plain_s2c = b"whatscore-vector-transport-frame-server-1"
    n0 = iv(0)
    ct_frame_c2s = aead_seal(client_write, n0, frame_plain_c2s, b"")
    ct_frame_s2c = aead_seal(client_read, n0, frame_plain_s2c, b"")
    # The server opens client->server frames with the first half (its read
    # key after the swap) and seals server->client frames with the second.
    assert aead_open(client_write, n0, ct_frame_c2s, b"") == frame_plain_c2s
    assert aead_open(client_read, n0, ct_frame_s2c, b"") == frame_plain_s2c

    vectors = {
        "meta": {
            "generator": "tests/fixtures/generate_noise_vectors.py",
            "backend": BACKEND,
            "findings": ["PF-004", "PF-005", "PF-006", "PF-007", "PF-008"],
            "note": (
                "SYNTHETIC deterministic vectors: all keys derive from the fixed "
                "public seed 'whatscore-vector-seed-*'; they are not credentials. "
                "Algorithm per docs/protocol/noise.md PF-004..PF-008."
            ),
        },
        "inputs": {
            "conn_header": hexs(CONN_HEADER),
            "client_ephemeral_priv": hexs(client_eph_priv),
            "client_ephemeral_pub": hexs(client_eph_pub),
            "server_ephemeral_priv": hexs(server_eph_priv),
            "server_ephemeral_pub": hexs(server_eph_pub),
            "server_static_priv": hexs(server_static_priv),
            "server_static_pub": hexs(server_static_pub),
            "client_noise_priv": hexs(client_noise_priv),
            "client_noise_pub": hexs(client_noise_pub),
            "client_payload": hexs(CLIENT_PAYLOAD),
            "server_cert_payload": hexs(CERT_PAYLOAD),
        },
        "hash_chain": chain,
        "mixes": mixes,
        "handshake_ciphertexts": {
            "server_hello_static": {
                "nonce": hexs(iv(0)),
                "ciphertext": hexs(ct_server_static),
            },
            "server_hello_payload": {
                "nonce": hexs(iv(0)),
                "ciphertext": hexs(ct_cert),
            },
            "client_finish_static": {
                "nonce": hexs(iv(1)),
                "ciphertext": hexs(ct_client_static),
            },
            "client_finish_payload": {
                "nonce": hexs(iv(0)),
                "ciphertext": hexs(ct_client_payload),
            },
        },
        "final_keys": {
            "client_write": hexs(client_write),
            "client_read": hexs(client_read),
        },
        "transport_frames": [
            {
                "direction": "client_to_server",
                "key": "client_write",
                "counter": 0,
                "plaintext": hexs(frame_plain_c2s),
                "nonce": hexs(n0),
                "ciphertext": hexs(ct_frame_c2s),
            },
            {
                "direction": "server_to_client",
                "key": "client_read",
                "counter": 0,
                "plaintext": hexs(frame_plain_s2c),
                "nonce": hexs(n0),
                "ciphertext": hexs(ct_frame_s2c),
            },
        ],
    }

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "noise_vectors.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"wrote {out} (backend: {BACKEND})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

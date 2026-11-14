#!/usr/bin/env python3
"""Independent reference encoder for the WhatsCore binary node format.

Implements docs/protocol/binary.md PF-010..PF-014 from the finding text,
shares no code with the Go implementation, and emits synthetic vectors only.
Regenerate with:

    python3 tests/fixtures/generate_binary_vectors.py \
        > tests/fixtures/binary_vectors.json
"""

import base64
import json

SINGLE = ["", "s.whatsapp.net", "type", "id", "message", "from", "to", "get"]
DOUBLE = [["read-self", "reaction"], ["w:gp2"], [], []]

SINGLE_IDX = {token: index for index, token in enumerate(SINGLE) if token}
DOUBLE_IDX = {
    token: (dictionary, index)
    for dictionary, tokens in enumerate(DOUBLE)
    for index, token in enumerate(tokens)
    if token
}

LIST_EMPTY = 0x00
DICTIONARY_0 = 0xEC
DICTIONARY_1 = 0xED
DICTIONARY_2 = 0xEE
DICTIONARY_3 = 0xEF
JID_PAIR = 0xFA
HEX_8 = 0xFB
BINARY_8 = 0xFC
BINARY_20 = 0xFD
BINARY_32 = 0xFE
NIBBLE_8 = 0xFF
LIST_8 = 0xF8
LIST_16 = 0xF9
PACKED_MAX = 127


def is_nibble(value):
    if not value or len(value) > PACKED_MAX:
        return False
    return all(("0" <= char <= "9") or char in "-." for char in value)


def is_hex(value):
    if not value or len(value) > PACKED_MAX:
        return False
    return all(("0" <= char <= "9") or ("A" <= char <= "F") for char in value)


def pack_nibble(char):
    if "0" <= char <= "9":
        return ord(char) - ord("0")
    if char == "-":
        return 10
    if char == ".":
        return 11
    return 15


def pack_hex(char):
    if "0" <= char <= "9":
        return ord(char) - ord("0")
    if "A" <= char <= "F":
        return 10 + ord(char) - ord("A")
    return 15


def split_jid(value):
    if value.count("@") != 1:
        return None
    user, server = value.split("@")
    if not server or any(char in value for char in " \t\r\n"):
        return None
    return user, server


def write_byte_length(out, length):
    if length < 256:
        out.extend([BINARY_8, length])
    elif length < 1 << 20:
        out.extend([BINARY_20, (length >> 16) & 0x0F, (length >> 8) & 0xFF, length & 0xFF])
    else:
        out.extend(
            [
                BINARY_32,
                (length >> 24) & 0xFF,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            ]
        )


def write_packed(out, value, tag):
    out.append(tag)
    rounded = (len(value) + 1) // 2
    if len(value) % 2:
        rounded |= 0x80
    out.append(rounded)
    pack = pack_nibble if tag == NIBBLE_8 else pack_hex
    for index in range(0, len(value), 2):
        high = pack(value[index]) << 4
        low = pack(value[index + 1]) if index + 1 < len(value) else 15
        out.append(high | low)


def write_string(out, value):
    if value == "":
        write_byte_length(out, 0)
        return
    if value in SINGLE_IDX:
        out.append(SINGLE_IDX[value])
        return
    if value in DOUBLE_IDX:
        dictionary, index = DOUBLE_IDX[value]
        out.extend([DICTIONARY_0 + dictionary, index])
        return
    if is_nibble(value):
        write_packed(out, value, NIBBLE_8)
        return
    if is_hex(value):
        write_packed(out, value, HEX_8)
        return
    jid = split_jid(value)
    if jid:
        user, server = jid
        out.append(JID_PAIR)
        if user:
            write_string(out, user)
        else:
            out.append(LIST_EMPTY)
        write_string(out, server)
        return
    raw = value.encode("utf-8")
    write_byte_length(out, len(raw))
    out.extend(raw)


def write_list_start(out, size):
    if size == 0:
        out.append(LIST_EMPTY)
    elif size < 256:
        out.extend([LIST_8, size])
    else:
        out.extend([LIST_16, (size >> 8) & 0xFF, size & 0xFF])


def write_node(out, node):
    attrs = node.get("attrs") or {}
    children = node.get("children") or []
    has_bytes = "bytes_base64" in node
    size = 1 + 2 * len(attrs) + (1 if children or has_bytes else 0)
    write_list_start(out, size)
    write_string(out, node["tag"])
    for key in sorted(attrs):
        write_string(out, key)
        write_string(out, attrs[key])
    if children:
        write_list_start(out, len(children))
        for child in children:
            write_node(out, child)
    elif has_bytes:
        raw = base64.b64decode(node["bytes_base64"])
        write_byte_length(out, len(raw))
        out.extend(raw)


def encode(node):
    out = bytearray([0])
    write_node(out, node)
    return bytes(out)


VECTORS = [
    ("tag only", {"tag": "ping"}),
    ("single-byte token tag", {"tag": "message"}),
    (
        "double-byte token and hex value",
        {"tag": "message", "attrs": {"id": "ABC123", "type": "read-self"}},
    ),
    (
        "nibble and hex values",
        {"tag": "message", "attrs": {"id": "DEADBEEF", "type": "123-45.6"}},
    ),
    (
        "children",
        {
            "tag": "iq",
            "children": [{"tag": "ping"}, {"tag": "get", "attrs": {"id": ""}}],
        },
    ),
    (
        "bytes content",
        {"tag": "media", "bytes_base64": base64.b64encode(bytes([0, 255, 16])).decode()},
    ),
    ("empty bytes content", {"tag": "media", "bytes_base64": ""}),
    (
        "jid pair",
        {"tag": "message", "attrs": {"to": "628123@s.whatsapp.net"}},
    ),
    (
        "empty jid user",
        {"tag": "message", "attrs": {"from": "@s.whatsapp.net"}},
    ),
    (
        "raw and unicode strings",
        {"tag": "message", "attrs": {"message": "halo dunia ✓"}},
    ),
    (
        "second double-byte dictionary",
        {"tag": "iq", "attrs": {"to": "w:gp2"}},
    ),
]


def main():
    document = {
        "finding": "PF-010..PF-014",
        "dictionary": {"single": SINGLE, "double": DOUBLE},
        "vectors": [
            {"name": name, "hex": encode(node).hex(), "node": node}
            for name, node in VECTORS
        ],
    }
    print(json.dumps(document, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

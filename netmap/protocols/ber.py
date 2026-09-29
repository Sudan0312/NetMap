"""Minimal BER (X.690) codec used by the built-in SNMP client.

Implemented from scratch so NetMap's SNMP enumeration has no third-party
dependency. Covers exactly the types that appear in SNMPv1/v2c messages:
INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE, the application
tags (IpAddress, Counter32, Gauge32, TimeTicks, Opaque, Counter64) and the
context-specific PDU tags.
"""

from __future__ import annotations

from typing import Any, Iterator

# universal
EOC = 0x00
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
SEQUENCE = 0x30

# snmp application types
IP_ADDRESS = 0x40
COUNTER32 = 0x41
GAUGE32 = 0x42
TIME_TICKS = 0x43
OPAQUE = 0x44
COUNTER64 = 0x46
U64 = 0x47
NO_SUCH_OBJECT = 0x80
NO_SUCH_INSTANCE = 0x81
END_OF_MIB_VIEW = 0x82

# snmp context-specific PDUs
GET_REQUEST = 0xA0
GET_NEXT_REQUEST = 0xA1
GET_RESPONSE = 0xA2
SET_REQUEST = 0xA3
GET_BULK = 0xA5
INFORM = 0xA6
SNMPV2_TRAP = 0xA7
REPORT = 0xA8

VERSIONS = {"v1": 0, "v2c": 1, "v3": 3}


class BERError(ValueError):
    """Malformed encoding/decoding."""


class SNMPParseError(BERError):
    pass


# ---------------------------------------------------------------------------
# encoders
# ---------------------------------------------------------------------------


def encode_length(length: int) -> bytes:
    if length < 0:
        raise BERError("length must be >= 0")
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8 or 1, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def encode_int(value: int) -> bytes:
    """Signed two's-complement INTEGER, minimally encoded."""
    if value == 0:
        return tlv(INTEGER, b"\x00")
    length = (value.bit_length() + 8) // 8
    raw = int(value).to_bytes(max(1, length), "big", signed=True)
    while len(raw) > 1 and raw[0] in (0x00, 0xFF) and ((raw[0] ^ raw[1]) & 0x80) == 0:
        raw = raw[1:]
    return tlv(INTEGER, raw)


def encode_uint(value: int, tag: int = INTEGER) -> bytes:
    if value < 0:
        raise BERError(f"{tag:#x} must be non-negative")
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return tlv(tag, raw)


def encode_bytes(value: bytes, tag: int = OCTET_STRING) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8", "surrogateescape")
    return tlv(tag, value)


def encode_str(value: str, tag: int = OCTET_STRING) -> bytes:
    return encode_bytes((value or "").encode("utf-8", "surrogateescape"), tag)


def encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in str(oid).lstrip(".").split(".") if p != ""]
    if len(parts) < 2:
        raise BERError(f"OID needs at least 2 arcs: {oid!r}")
    if parts[0] > 2 or (parts[0] == 2 and parts[1] > 39):
        raise BERError(f"OID first arcs out of range: {oid!r}")
    out = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        if arc < 0:
            raise BERError("negative OID arc")
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append((arc & 0x7F) | 0x80)
            arc >>= 7
        out.extend(reversed(chunk))
    return tlv(OID, bytes(out))


def decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    arcs = [first // 40, first % 40]
    if first >= 0x80:  # single-byte encodings above 0x78 are invalid but seen in the wild
        arcs = [0, first]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if value:
        raise SNMPParseError("truncated base-128 OID arc")
    return ".".join(str(a) for a in arcs)


def encode_null() -> bytes:
    return tlv(NULL, b"")


def encode_sequence(*elements: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(elements))


def encode_varbind(name: str, value: bytes) -> bytes:
    return encode_sequence(encode_oid(name), value)


def encode_varbinds(pairs: list[tuple[str, bytes]]) -> bytes:
    return encode_sequence(*[encode_varbind(n, v) for n, v in pairs])


# ---------------------------------------------------------------------------
# decoder
# ---------------------------------------------------------------------------


class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_tlv(self) -> tuple[int, bytes, int]:
        """Return (tag, value, header_len). Raises on truncation."""
        if self.remaining < 2:
            raise SNMPParseError("truncated BER header")
        tag = self.data[self.pos]
        first = self.data[self.pos + 1]
        self.pos += 2
        if first < 0x80:
            length = first
        elif first == 0x80:
            # indefinite length: scan for EOC (rare in SNMP)
            end = self.data.find(b"\x00\x00", self.pos)
            if end < 0:
                raise SNMPParseError("indefinite length without EOC")
            length = end - self.pos
        else:
            count = first & 0x7F
            if count > 8 or self.remaining < count:
                raise SNMPParseError(f"bogus length field ({count} bytes)")
            length = int.from_bytes(self.data[self.pos : self.pos + count], "big")
            self.pos += count
        if length < 0 or self.remaining < length:
            raise SNMPParseError(f"truncated BER value (need {length}, have {self.remaining})")
        value = self.data[self.pos : self.pos + length]
        self.pos += length
        return tag, value, length

    def at_end(self) -> bool:
        return self.remaining <= 0


def decode_int(raw: bytes) -> int:
    if not raw:
        return 0
    return int.from_bytes(raw, "big", signed=True)


def decode_length(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=False) if raw else 0


def decode_value(tag: int, raw: bytes) -> Any:
    """Map a value TLV onto a Python object."""
    if tag == INTEGER:
        return decode_int(raw)
    if tag in (COUNTER32, GAUGE32, TIME_TICKS, COUNTER64, U64):
        return decode_length(raw)
    if tag == IP_ADDRESS:
        if len(raw) == 4:
            return ".".join(str(b) for b in raw)
        return raw.hex()
    if tag == OCTET_STRING:
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw
        # Binary payloads (e.g. PhysAddress) arrive as octet strings too.
        if any(ord(c) < 32 and c not in "\t\r\n" for c in txt):
            return raw
        return txt
    if tag == OID:
        return decode_oid(raw)
    if tag == NULL:
        return None
    if tag in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return None
    if tag == OPAQUE:
        return raw
    return raw


def iter_sequence(raw: bytes) -> Iterator[tuple[int, bytes]]:
    sub = Reader(raw)
    while not sub.at_end():
        tag, value, _ = sub.read_tlv()
        yield tag, value


def parse_varbind_list(data: bytes) -> list[tuple[str, Any]]:
    """`data` is the full varbindList TLV (SEQUENCE OF Varbind)."""
    reader = Reader(data)
    seq_tag, seq_body, _ = reader.read_tlv()
    if seq_tag != SEQUENCE:
        raise SNMPParseError(f"expected varbindList SEQUENCE, got {seq_tag:#x}")
    out: list[tuple[str, Any]] = []
    inner = Reader(seq_body)
    while not inner.at_end():
        vb_tag, vb_body, _ = inner.read_tlv()
        if vb_tag != SEQUENCE:
            raise SNMPParseError("varbind is not a SEQUENCE")
        sub = Reader(vb_body)
        name_tag, name_raw, _ = sub.read_tlv()
        if name_tag != OID:
            raise SNMPParseError("varbind name is not an OID")
        oid = decode_oid(name_raw)
        if sub.at_end():
            out.append((oid, None))
            continue
        val_tag, val_raw, _ = sub.read_tlv()
        out.append((oid, decode_value(val_tag, val_raw)))
    return out


def tag_name(tag: int) -> str:
    return {
        GET_REQUEST: "get-request",
        GET_NEXT_REQUEST: "get-next",
        GET_RESPONSE: "response",
        SET_REQUEST: "set-request",
        GET_BULK: "get-bulk",
        INFORM: "inform",
        SNMPV2_TRAP: "v2-trap",
        REPORT: "report",
    }.get(tag, f"{tag:#02x}")

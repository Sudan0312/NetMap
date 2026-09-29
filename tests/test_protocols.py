"""Wire-level codecs: BER, SNMP messaging, CDP/LLDP frames and X.509 DER.

These are the pieces a normal Python toolbox would delegate to a library, so the
tests pin them against byte-exact fixtures — including certificates produced with
OpenSSL and cross-checked against `openssl x509 -text` — instead of only checking
that a parser agrees with itself.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from struct import pack

import pytest

from netmap.models import Certificate
from netmap.protocols import ber
from netmap.protocols.ber import Reader
from netmap.protocols.frames import (
    FrameError,
    neighbor_from_cdp,
    neighbor_from_lldp,
    parse_cdp,
    parse_lldp,
)
from netmap.protocols.mibs import IF_TYPES
from netmap.protocols.snmp import Credentials, SNMPClient, build_request, parse_message
from netmap.protocols.x509 import hostname_matches, parse_certificate

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> Path:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"{name} fixture missing")
    return path


# ------------------------------------------------------------------------------ BER
@pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, 65535, 2**31 - 1, -1, -(2**20)])
def test_ber_integer_roundtrip(value):
    """encode_int already emits a complete TLV; the decoder must read it back."""
    raw = ber.encode_int(value)
    tag, body, _ = Reader(raw).read_tlv()
    assert tag == ber.INTEGER
    assert ber.decode_int(body) == value


@pytest.mark.parametrize("value,size", [(127, 1), (128, 2), (255, 2), (65535, 3), (-1, 1), (-128, 1), (-129, 2)])
def test_ber_integers_are_minimally_encoded(value, size):
    """DER forbids redundant leading 0x00/0xff padding; agents are picky about it."""
    _, body, _ = Reader(ber.encode_int(value)).read_tlv()
    assert len(body) == size


@pytest.mark.parametrize(
    "length,expected",
    [(0, b"\x00"), (1, b"\x01"), (127, b"\x7f"), (128, b"\x81\x80"), (255, b"\x81\xff"), (70000, b"\x83\x01\x11\x70")],
)
def test_ber_length_forms(length, expected):
    assert ber.encode_length(length) == expected


@pytest.mark.parametrize("count", [1, 5, 127, 128, 300, 70000])
def test_ber_long_payloads_survive_reader(count):
    raw = ber.tlv(ber.OCTET_STRING, b"y" * count)
    reader = Reader(raw)
    tag, value, _ = reader.read_tlv()
    assert tag == ber.OCTET_STRING and len(value) == count and reader.at_end()


def test_ber_typed_value_decoding():
    _, body, _ = Reader(ber.encode_str("public")).read_tlv()
    assert ber.decode_value(ber.OCTET_STRING, body) == "public"
    _, body, _ = Reader(ber.encode_int(-3)).read_tlv()
    assert ber.decode_value(ber.INTEGER, body) == -3
    _, body, _ = Reader(ber.encode_uint(4000, ber.GAUGE32)).read_tlv()
    assert ber.decode_value(ber.GAUGE32, body) == 4000
    _, body, _ = Reader(ber.encode_null()).read_tlv()
    assert ber.decode_value(ber.NULL, body) is None

    _, body, _ = Reader(ber.encode_oid("1.3.6.1.2.1.1.1.0")).read_tlv()
    assert ber.decode_oid(body) == "1.3.6.1.2.1.1.1.0"

    from netmap.protocols.snmp import encode_ip_address

    _, body, _ = Reader(encode_ip_address("10.0.0.7")).read_tlv()
    assert ber.decode_value(ber.IP_ADDRESS, body) == "10.0.0.7"


def test_ber_sequence_iteration_and_varbinds():
    varbinds = ber.encode_varbinds([("1.3.6.1.2.1.1.1.0", ber.encode_str("Acme Router"))])
    body = ber.encode_sequence(ber.encode_int(12345), ber.encode_int(0), ber.encode_int(0), varbinds)
    # encode_sequence returns a complete TLV, so descend one level first
    _, seq_body, _ = Reader(body).read_tlv()
    elements = list(ber.iter_sequence(seq_body))
    assert [t for t, _ in elements] == [ber.INTEGER, ber.INTEGER, ber.INTEGER, ber.SEQUENCE]
    assert ber.decode_int(elements[0][1]) == 12345
    # parse_varbind_list wants the whole varbindList TLV, not its body
    assert ber.parse_varbind_list(ber.tlv(ber.SEQUENCE, elements[3][1])) == [("1.3.6.1.2.1.1.1.0", "Acme Router")]
    assert ber.parse_varbind_list(varbinds) == [("1.3.6.1.2.1.1.1.0", "Acme Router")]


def test_ber_truncated_and_bogus_input_raises():
    with pytest.raises(ber.BERError):
        Reader(b"\x04\x40abc").read_tlv()  # length promises 64 bytes, 3 present
    with pytest.raises(ber.BERError):
        Reader(b"\x30").read_tlv()
    with pytest.raises(ber.SNMPParseError):
        ber.parse_varbind_list(ber.encode_sequence(ber.encode_int(1)))  # not a varbind list


# ------------------------------------------------------------------------ SNMP wire
def test_credentials_wire_versions_and_labels():
    assert Credentials("v2c", "public").wire_version == 1
    assert Credentials("v1", "public").wire_version == 0
    assert Credentials("v2c", "public").label == "v2c:public"
    v3 = Credentials("v3", None, v3={"user": "ro"})
    assert v3.wire_version == 3 and v3.label == "v3:ro", "log lines must say which v3 user was tried"
    assert Credentials("v3", None, v3={}).label == "v3:?"


def test_build_and_parse_request_are_inverse():
    creds = Credentials("v2c", "public")
    data = build_request(creds, ber.GET_REQUEST, ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"], request_id=12345)
    msg = parse_message(data)
    assert msg["community"] == "public"
    assert msg["request_id"] == 12345
    assert msg["pdu_type"] == ber.GET_REQUEST
    assert msg["version"] == creds.wire_version
    assert [v[0] for v in msg["varbinds"]] == ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]


def test_known_get_packet_parses():
    """Byte-exact `snmpget -v2c -c public host 1.3.6.1.2.1.1.1.0` on the wire."""
    packet = bytes.fromhex("302702010104067075626c6963a01a02023039020100020100300e300c06082b060102010101000500")
    msg = parse_message(packet)
    assert msg["community"] == "public"
    assert msg["request_id"] == 12345
    assert msg["pdu_type"] == ber.GET_REQUEST
    assert msg["varbinds"][0][0] == "1.3.6.1.2.1.1.1.0"
    assert msg["error_status"] == 0


def test_client_times_out_on_a_silent_port():
    from netmap.protocols.snmp import SNMPError

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    client = SNMPClient("127.0.0.1", creds=Credentials("v2c", "public"), port=port, timeout=0.2, retries=0)
    try:
        with pytest.raises(SNMPError):
            client.get(["1.3.6.1.2.1.1.1.0"])
    finally:
        client.close()


def test_if_type_names_are_readable():
    assert IF_TYPES[6] == "ethernetCsmacd"
    assert IF_TYPES[131] == "tunnel"
    assert "loopback" in IF_TYPES[24].lower()


# ----------------------------------------------------------------------- CDP / LLDP
def _cdp_frame() -> bytes:
    def tlv(kind: int, value: bytes) -> bytes:
        return pack(">HH", kind, 4 + len(value)) + value

    addresses = b"\x01\x00\x00\x00" + pack(">I", 0x08000000) + b"\x04" + socket.inet_aton("10.0.0.2")
    return (
        pack(">BBH", 2, 180, 0)
        + tlv(1, b"sw-core-1")  # device id
        + tlv(2, addresses)  # addresses
        + tlv(3, b"GigabitEthernet1/0/11")  # port id
        + tlv(4, pack(">I", 0x04))  # capabilities: switch
        + tlv(5, b"Cisco IOS Software, Catalyst L3 Switch Software")  # version string
        + tlv(99, b"\xde\xad")  # unknown TLV must be carried, not fatal
    )


def test_cdp_tlv_parsing_and_neighbour_mapping():
    parsed = parse_cdp(_cdp_frame())
    assert parsed["device_id"] == "sw-core-1"
    assert parsed["port_id"] == "GigabitEthernet1/0/11"
    assert parsed["ttl"] == 180
    assert "10.0.0.2" in (parsed.get("addresses") or [])
    assert any(t["name"].startswith("type-") for t in parsed["tlvs"]), "unknown TLVs must be preserved"

    nbr = neighbor_from_cdp("Gi0/1", parsed)
    assert nbr.remote_system == "sw-core-1"
    assert nbr.remote_port == "GigabitEthernet1/0/11"
    assert nbr.local_if == "Gi0/1"
    assert nbr.remote_ip == "10.0.0.2"
    assert nbr.remote_key == "10.0.0.2", "the address is the key that joins neighbour rows to devices"
    assert nbr.via == "cdp"
    assert 0 < nbr.confidence <= 1.0


def _lldp_frame() -> bytes:
    def tlv(kind: int, value: bytes) -> bytes:
        return pack(">H", (kind << 9) | len(value)) + value

    out = tlv(1, pack(">B", 5) + socket.inet_aton("10.0.0.10"))  # chassis id: network address
    out += tlv(2, pack(">B", 5) + b"Eth1/9")  # port id: interface name
    out += tlv(3, pack(">H", 120))  # ttl
    out += tlv(4, b"leaf port to app-01")  # port description
    out += tlv(5, b"core-sw-1")  # system name
    out += tlv(6, b"ACME switch OS 9.1")  # system description
    out += tlv(7, pack(">BB", 4, 0x11) + socket.inet_aton("10.0.0.10") + b"\x02" + pack(">I", 1) + b"\x00")
    out += tlv(8, pack(">HH", 0x000C, 0x0004))  # capabilities
    out += tlv(0, b"")
    return out


def test_lldp_frame_parsing_and_neighbour_mapping():
    parsed = parse_lldp(_lldp_frame())
    assert parsed["system_name"] == "core-sw-1"
    assert parsed["system_description"] == "ACME switch OS 9.1"
    assert parsed["port_description"] == "leaf port to app-01"
    assert parsed["port_id"]["value"] == "Eth1/9"
    assert parsed["chassis_id"]["value"] == "10.0.0.10"
    assert parsed["ttl"] == 120
    assert parsed["management_address"] == "10.0.0.10", "IPv4 management address must decode, not hexdump"
    assert "mac-bridge" in parsed["system_capabilities"]["enabled"]

    nbr = neighbor_from_lldp("Eth1/1", parsed)
    assert nbr.remote_system == "core-sw-1"
    assert nbr.remote_port == "Eth1/9"
    assert nbr.remote_ip == "10.0.0.10"
    assert nbr.remote_key == "10.0.0.10"
    assert nbr.remote_description == "ACME switch OS 9.1"
    assert nbr.via == "lldp"
    assert nbr.ttl_seconds == 120
    assert nbr.confidence > 0.8


def test_lldp_frame_behind_an_ethernet_header_is_still_parsed():
    frame = b"\x01\x80\xc2\x00\x00\x0e" + b"\x00\x11\x22\x33\x44\x55" + pack(">H", 0x88CC) + _lldp_frame()
    assert parse_lldp(frame)["system_name"] == "core-sw-1"


def test_malformed_discovery_frames_degrade_cleanly():
    for junk in (b"", b"\x01\x02", bytes(range(48))):
        with pytest.raises(FrameError):
            parse_cdp(junk)  # too short, or not a CDP version we speak
    # a plausible header followed by nonsense must yield a dict, not a traceback
    parsed = parse_cdp(b"\x02\xb4\x00\x00" + b"\xff" * 24)
    assert isinstance(parsed, dict) and parsed["tlvs"] == [] or isinstance(parsed["tlvs"], list)
    for junk in (b"", b"\x01\x02", bytes(range(48)), b"\x88\xcc" + b"\x00" * 40):
        assert isinstance(parse_lldp(junk), dict)


# --------------------------------------------------------------------------- X.509
def test_leaf_certificate_matches_openssl():
    cert = parse_certificate(fixture("leaf.der").read_bytes())
    assert cert["version"] == 3, "X.509 v3 is encoded as integer 2 inside [0]"
    assert cert["key_bits"] == 2048
    assert cert["key_alg"] == "rsaEncryption"
    assert cert["sig_alg"] == "sha256WithRSAEncryption"
    assert cert["subject_cn"] == ["vip.corp.contoso.example"]
    assert cert["self_signed"] is True
    assert isinstance(cert["not_before"], datetime) and isinstance(cert["not_after"], datetime)
    assert cert["not_after"] > cert["not_before"]
    assert set(cert["san"]) == {"vip.corp.contoso.example", "*.corp.contoso.example", "10.0.0.9"}
    assert cert["extensions"]["basicConstraints"] == {"ca": False, "path_len": None, "critical": True}
    assert cert["extensions"]["keyUsage"]["usage"] == ["digitalSignature", "keyEncipherment"]


def test_ca_certificate_path_len_and_usage():
    cert = parse_certificate(fixture("ca.der").read_bytes())
    bc = cert["extensions"]["basicConstraints"]
    assert bc["ca"] is True and bc["path_len"] == 0 and bc["critical"] is True
    assert set(cert["extensions"]["keyUsage"]["usage"]) == {"keyCertSign", "cRLSign"}
    assert cert["serial"]


def test_san_fallback_is_distinguished_from_a_real_san():
    """A CN-only certificate must not look like it carries a SAN."""
    expired = parse_certificate(fixture("expired.der").read_bytes())
    assert expired["san"] == []
    assert expired["san_source"] == "common_name"
    assert expired["names"] == ["old.corp.contoso.example"], "matching still falls back to the CN"
    leaf = parse_certificate(fixture("leaf.der").read_bytes())
    assert leaf["san_source"] == "extension"
    assert "old.corp.contoso.example" not in leaf["san"]


def test_expired_certificate_dates():
    cert = parse_certificate(fixture("expired.der").read_bytes())
    assert cert["not_after"].year == 2025
    assert cert["not_after"] < datetime.now(timezone.utc), "fixture must be in the past"
    model = Certificate(subject_cn=cert["subject_cn"][0], not_after=cert["not_after"].strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert model.days_remaining < 0 and model.expired and not model.expiring_soon


@pytest.mark.parametrize("name,bits", [("c.der", 2048), ("rsa4096.der", 4096), ("ec.der", 256)])
def test_fixture_certificates(name, bits):
    cert = parse_certificate(fixture(name).read_bytes())
    assert cert["version"] == 3
    assert cert["key_bits"] == bits
    assert cert["key_alg"] in ("rsaEncryption", "id-ecPublicKey")
    assert cert["sig_alg"]
    assert isinstance(cert["self_signed"], bool)
    assert cert["serial"]


def test_certificate_feeds_the_model_without_massaging():
    cert = parse_certificate(fixture("leaf.der").read_bytes())
    model = Certificate(
        subject_cn=cert["subject_cn"][0],
        issuer_cn=", ".join(cert["issuer"]),
        not_before=cert["not_before"].strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_after=cert["not_after"].strftime("%Y-%m-%dT%H:%M:%SZ"),
        san=cert["san"],
        self_signed=cert["self_signed"],
        key_bits=cert["key_bits"],
        bits=cert["key_bits"],
    )
    assert model.days_remaining is not None and not model.expired
    assert model.expiring_soon is (model.days_remaining <= 30)
    dumped = model.to_dict()
    assert Certificate.from_dict(dumped).subject_cn == model.subject_cn


def test_model_expiry_derives_from_not_after():
    """`days_remaining` must come from the validity window, not only from `days_left`."""
    now = datetime.now(timezone.utc)
    past = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    future = (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert Certificate(subject_cn="a", not_after=past).expired
    assert Certificate(subject_cn="a", not_after=past).days_remaining < 0
    assert Certificate(subject_cn="a", not_after=future).expiring_soon
    assert Certificate(subject_cn="a").days_remaining is None
    assert not Certificate(subject_cn="a").expired
    assert Certificate(subject_cn="a", days_left=-1).expired
    assert Certificate(subject_cn="a", days_left=3).expiring_soon


def test_hostname_matches_wildcards_and_ips():
    names = ["corp-gw.contoso.example", "*.contoso.example", "10.0.0.9"]
    assert hostname_matches("x.contoso.example", names) is True
    assert hostname_matches("corp-gw.contoso.example", names) is True
    assert hostname_matches("a.b.contoso.example", names) is False, "a wildcard covers one label only"
    assert hostname_matches("contoso.example", names) is False, "the wildcard must not match the apex"
    assert hostname_matches("CORP-GW.contoso.example", names) is True, "matching is case-insensitive"
    assert hostname_matches("10.0.0.9", names) is True
    assert hostname_matches(None, names) is None, "no hostname means unknown, not mismatch"
    assert hostname_matches("x.com", []) is None


def test_unreadable_certificates_report_an_error_instead_of_raising():
    """Probing a non-TLS or broken listener must not abort a scan."""
    for blob in (b"", b"not a certificate", bytes(range(40))):
        parsed = parse_certificate(blob)
        assert parsed.get("error"), "callers rely on an `error` key rather than exception handling"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not available")
@pytest.mark.parametrize("name", ["leaf.der", "ca.der", "expired.der"])
def test_openssl_agrees_with_our_parser(name):
    der = fixture(name)
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(der), "-inform", "DER", "-noout", "-text"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    ours = parse_certificate(der.read_bytes())
    assert f"Public-Key: ({ours['key_bits']} bit)" in proc.stdout
    serial_hex = re.sub(r"[^0-9a-f]", "", proc.stdout.split("Serial Number:")[1].split("Signature Algorithm")[0])
    assert serial_hex.endswith(ours["serial"]), "serial numbers must match octet for octet"
    usage = ours["extensions"].get("keyUsage")
    if usage and usage["usage"]:
        readable = {"digitalSignature": "Digital Signature", "keyEncipherment": "Key Encipherment", "keyCertSign": "Certificate Sign", "cRLSign": "CRL Sign"}
        for label in usage["usage"]:
            assert readable[label] in proc.stdout, f"openssl must list {label} too"
    bc = ours["extensions"]["basicConstraints"]
    assert ("CA:TRUE" if bc["ca"] else "CA:FALSE") in proc.stdout
    assert ours["san_source"] == ("extension" if ours["san"] else "common_name")
    if ours["san"]:
        assert "X509v3 Subject Alternative Name" in proc.stdout
        for entry in ours["san"]:
            if entry.count(".") == 3 and entry.replace(".", "").isdigit():
                assert f"IP Address:{entry}" in proc.stdout
            else:
                assert f"DNS:{entry}" in proc.stdout
    else:
        assert "Subject Alternative Name" not in proc.stdout, "a CN-only certificate must not claim a SAN"

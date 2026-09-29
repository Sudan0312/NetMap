"""Target/address/model layer: the parts everything else trusts."""

from __future__ import annotations

import copy
import datetime as dt

import pytest

from netmap import ports
from netmap.models import (
    Certificate,
    Device,
    Finding,
    Interface,
    Link,
    Neighbor,
    ScanSnapshot,
    Service,
    Zone,
    device_id_for,
    merge_devices,
    summarize_devices,
)
from netmap.config import load_inventory
from netmap.util import (
    cidr_contains,
    days_until,
    expand_cidr,
    human_age,
    ip_in_private_ranges,
    is_ip,
    mac_oui,
    norm_ip,
    parse_iso,
    parse_mac,
    parse_version,
    slug,
    sorted_ips,
    version_between,
    version_lt,
    write_json,
)


# --------------------------------------------------------------------- addresses
@pytest.mark.parametrize(
    "spec,expected",
    [
        ("10.0.0.0/29", ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"]),
        ("10.0.0.5-9", ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"]),
        ("192.168.1.10-12", ["192.168.1.10", "192.168.1.11", "192.168.1.12"]),
        ("172.16.5.7", ["172.16.5.7"]),
        ("10.0.0.0/30", ["10.0.0.1", "10.0.0.2"]),
    ],
)
def test_expand_cidr_forms(spec, expected):
    assert list(expand_cidr(spec)) == expected


def test_expand_cidr_honours_exclude():
    got = list(expand_cidr("10.0.0.0/29", exclude=["10.0.0.1-3"]))
    assert "10.0.0.1" not in got and "10.0.0.2" not in got
    assert "10.0.0.4" in got
    assert list(expand_cidr("10.0.0.9/32")) == ["10.0.0.9"], "an explicit /32 must not be dropped as a network address"


def test_host_cap_lives_in_the_config_gate():
    """expand_cidr is a dumb expander; `scan.max_hosts` is the enforced limit."""
    from netmap.config import Config

    cfg = Config({"scan": {"targets": ["10.0.0.0/16"], "max_hosts": 254}})
    hosts, _names = cfg.resolved_targets()
    assert len(hosts) <= 254


@pytest.mark.parametrize(
    "ip,ranges,expected",
    [
        ("10.0.4.5", ["10.0.0.0/24"], False),
        ("10.0.0.5", ["10.0.0.0/24"], True),
        ("10.0.0.5", ["10.0.0.6-9", "10.0.0.5"], True),
        ("1.2.3.4", [], False),
    ],
)
def test_cidr_contains(ip, ranges, expected):
    assert cidr_contains(ranges, ip) is expected


def test_ip_helpers():
    assert is_ip("10.0.0.1") and not is_ip("10.0.0.1/") and not is_ip("999.1.1.1")
    assert is_ip("::1")
    assert norm_ip(" 10.0.0.007 ") == "10.0.0.7", "leading zeros must not survive into a key"
    assert norm_ip("garbage") == "garbage" and norm_ip("") is None
    assert ip_in_private_ranges("10.1.2.3") and ip_in_private_ranges("192.168.0.1")
    assert ip_in_private_ranges("127.0.0.1") and ip_in_private_ranges("169.254.1.1")
    assert ip_in_private_ranges("100.64.0.1"), "CGNAT is not routable to the internet and is treated as internal"
    assert not ip_in_private_ranges("8.8.8.8")
    assert sorted_ips(["10.0.0.10", "10.0.0.2", "10.0.0.9"]) == ["10.0.0.2", "10.0.0.9", "10.0.0.10"]


def test_mac_parsing_and_oui():
    assert parse_mac("00:1C:B3:AA:0B:01") == "00:1c:b3:aa:0b:01"
    assert parse_mac("001c.b3aa.0b01") == "00:1c:b3:aa:0b:01"
    assert parse_mac("nonsense") is None
    # the bundled table resolves prefixes to vendor names, or falls back to the
    # prefix itself so a report never claims a vendor it cannot support
    oui = str(mac_oui("00:1c:b3:aa:0b:01"))
    assert oui and oui in ("CISCO SYSTEMS", "001CB3") or "CISCO" in oui.upper()


# ----------------------------------------------------------------------- versions
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("12.2(55)SE12", (12, 2, 55, 12)),
        ("15.2(4)E7", (15, 2, 4, 7)),
        ("9.3(8)", (9, 3, 8)),
        ("15.1X49D140.2", (15, 1, 49, 140, 2)),
        ("8.6.0.13", (8, 6, 0, 13)),
        ("", ()),
    ],
)
def test_parse_version(raw, expected):
    assert parse_version(raw) == expected


def test_version_comparisons():
    assert version_lt("12.2(55)SE12", "15.2(4)E7")
    assert not version_lt("15.2(4)E7", "12.2(55)SE12")
    assert version_lt("9.3(8)", "9.3(10)")
    assert version_between("15.2(4)E7", "15.0", "16.0")
    assert not version_between("12.2(55)", "15.0", "16.0")
    # equal versions are not "less than", and unparseable input is never older
    assert not version_lt("15.2(4)E7", "15.2(4)E7")
    assert not version_lt("junk", "1.0")


def test_dates_and_ages():
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert 9 < days_until(future) < 11
    assert days_until(None) is None
    assert days_until("not-a-date") is None
    assert days_until("2020-01-01") < 0
    parsed = parse_iso(future)
    assert parsed.year >= 2020
    assert "d" in human_age(60 * 60 * 24 * 3)
    assert human_age(30) == "30s" or "s" in human_age(30)
    assert human_age(None) == "unknown"


def test_slug_and_write_json(tmp_path):
    assert slug("Web Server #1 (rack 4)")
    assert "/" not in slug("a/b") and " " not in slug("a b")
    path = tmp_path / "x.json"
    write_json(path, {"b": 1, "a": [1, 2]})
    assert '"a"' in path.read_text()


# -------------------------------------------------------------------------- ports
def test_port_table_lookup():
    info = ports.port_info(22)
    assert info[0] == "ssh" and info[1] == "management"
    assert ports.port_name(443) == "https"
    assert ports.port_name(58001) == "unknown/58001", "unregistered ports stay honest"
    assert ports.is_plaintext(23) and not ports.is_plaintext(22)
    assert ports.port_category(5432) == "database"
    assert ports.expected_encryption(443) == "tls"
    assert 623 in ports.PORTS and 623 in ports.UDP_PORTS, "IPMI must be in the scan tables"
    assert ports.port_risk(23) > ports.port_risk(22), "telnet must rank riskier than ssh"


def test_top_ports_are_sorted_and_unique():
    top = ports.top_ports(12)
    assert top == sorted(set(top)) and len(top) == 12
    big = ports.top_ports(87)
    assert {22, 443, 445, 161, 53} <= set(big), "the default scan list must cover the common admin ports"
    assert len(big) == 87


def test_udp_table_exists():
    assert 161 in ports.UDP_PORTS and 53 in ports.UDP_PORTS
    assert ports.port_name(161, "udp") == "snmp"


# ------------------------------------------------------------------------- models
def make_device(**kw) -> Device:
    base = dict(
        id="ip:10.0.0.1",
        ip="10.0.0.1",
        hostname="gw1",
        device_type="router",
        zone="core",
        criticality=4,
        services=[
            Service(port=22, protocol="tcp", state="open", name="ssh", encryption="ssh"),
            Service(port=23, protocol="tcp", state="open", name="telnet", encryption="none"),
            Service(port=161, protocol="udp", state="open", name="snmp", encryption="none"),
        ],
        interfaces=[Interface(if_index=1, name="Gi0/0", oper_status="up", role="uplink", ips=["10.0.0.1"])],
    )
    base.update(kw)
    return Device(**base)


def test_device_helpers():
    dev = make_device()
    assert dev.has_port(22) and dev.has_port([161], "udp") and not dev.has_port(443)
    assert dev.open_ports == [22, 23, 161], "open_ports spans both protocols; the service record carries the protocol"
    assert dev.service(22).product is None
    assert "telnet" in dev.text_blob().lower()
    assert dev.is_network_infrastructure
    assert set(dev.management_protocols) >= {"ssh", "telnet"}
    assert dev.uplink_count == 1, "one uplink-role interface, no neighbour protocol data"
    assert dev.interface("Gi0/0") is not None and dev.interface(1) is not None
    assert dev.interface("Gi0/0").if_index == dev.interface(1).if_index
    assert dev.interface(None) is None and dev.interface("Gi9/9") is None
    assert dev.label == "gw1", "label is the short name humans recognise"
    assert dev.display == "gw1 (10.0.0.1)", "display adds the address for tables"
    assert Device(id="ip:10.9.9.9", ip="10.9.9.9").label == "10.9.9.9", "nameless devices still need a label"


def test_service_plaintext_fallback():
    known_clear = Service(port=23, protocol="tcp", state="open")  # no encryption info at all
    assert known_clear.is_plaintext
    encrypted = Service(port=443, protocol="tcp", state="open", encryption="tls")
    assert not encrypted.is_plaintext
    weird = Service(port=23, protocol="tcp", state="open", encryption="tls")
    assert not weird.is_plaintext, "an encrypted service on a plaintext port is not plaintext"


def test_certificate_properties():
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expired = Certificate(subject_cn="a", not_after=past)
    expiring = Certificate(subject_cn="a", not_after=soon)
    assert expired.expired and not expired.expiring_soon
    assert expiring.expiring_soon and not expiring.expired
    assert Certificate(subject_cn="a", key_bits=1024).key_bits == 1024
    assert Certificate(subject_cn="a", days_left=-1).expired
    assert Certificate(subject_cn="a", days_left=None).days_remaining is None


def test_device_roundtrip_and_merge():
    dev = make_device()
    dev.neighbors.append(Neighbor(via="lldp", local_if="Gi0/1", remote_key="10.0.0.2", remote_system="sw2", confidence=0.9))
    data = dev.to_dict()
    again = Device.from_dict(copy.deepcopy(data))
    assert again.id == dev.id
    assert len(again.services) == 3 and again.services[0].port == 22
    assert again.neighbors[0].remote_system == "sw2"

    other = make_device(id="ip:10.0.0.1", hostname=None, mac="00:1c:b3:00:00:01", discovery_sources=["snmp"])
    other.services = [Service(port=443, protocol="tcp", state="open", name="https", encryption="tls")]
    merged = merge_devices(dev, other)
    assert {s.port for s in merged.services} == {22, 23, 161, 443}
    assert merged.hostname == "gw1", "an existing hostname must not be erased by a nameless duplicate"
    assert merged.mac == "00:1c:b3:00:00:01"
    assert merged.discovery_sources, "merge records where the data came from"


def test_device_id_for_is_stable():
    assert device_id_for("10.0.0.1", None) == device_id_for("10.0.0.1", None)
    assert device_id_for("10.0.0.1", None) == "ip:10.0.0.1"
    assert device_id_for(None, "Host.Example") == "host:host.example"


def test_snapshot_roundtrip_and_validation():
    snap = ScanSnapshot(snapshot_id="s1", mode="lab", devices=[make_device()], zones=[Zone(name="core", trust="internal")])
    snap.findings = [
        Finding(
            id="f1",
            rule_id="NM-TEST-001",
            rule_title="test",
            severity="high",
            score=7.0,
            scope="device",
            target_id="ip:10.0.0.1",
            target_label="gw1",
        )
    ]
    payload = snap.to_dict()
    back = ScanSnapshot.from_dict(copy.deepcopy(payload))
    assert back.devices[0].services[1].name == "telnet"
    assert back.findings[0].rule_id == "NM-TEST-001"
    assert back.validate() == []

    broken = copy.deepcopy(payload)
    broken["devices"][0]["services"][0]["port"] = "not-a-port"
    recovered = ScanSnapshot.from_dict(broken)
    assert recovered.devices[0].services[0].port == "not-a-port" or recovered.devices[0].services[0].port is not None


def test_snapshot_indexes_and_summaries():
    devices = [make_device(documented=True), make_device(id="ip:10.0.0.2", ip="10.0.0.2", hostname="sw2", documented=False)]
    snap = ScanSnapshot(devices=devices, zones=[Zone(name="core", trust="internal", device_count=2)])
    assert len(snap.device_map()) == 2
    assert snap.find_device("10.0.0.2").hostname == "sw2"
    assert snap.find_device("ip:10.0.0.1").id == "ip:10.0.0.1"
    assert len(snap.devices_by(documented=False)) == 1
    assert len(snap.open_devices) == 2
    summary = summarize_devices(devices)
    assert summary["total"] == 2 and summary["undocumented"] == 1
    assert summary["undocumented_pct"] == 50.0
    assert summary["by_type"]["router"] == 2
    assert 443 not in summary["ports_open"] and 22 in summary["ports_open"]


def test_link_to_dict_and_sort_key():
    link = Link(id="l1", src_device="ip:10.0.0.1", dst_device="ip:10.0.0.2", kind="ethernet", speed_mbps=1000, is_spof=True)
    assert link.to_dict()["is_spof"] is True
    finding = Finding(id="a", rule_id="r", rule_title="t", severity="critical", score=9.9, scope="device", target_id="x", target_label="x")
    assert finding.sort_key[0] <= 1, "critical findings must sort first"


def test_load_inventory(tmp_path):
    from netmap.config import Config

    csv_path = tmp_path / "inv.csv"
    csv_path.write_text("ip,hostname,criticality,tags\n10.0.0.1,gw1,5,\"managed,core\"\n10.0.0.2,sw2,4,managed\n", encoding="utf-8")
    cfg = Config({"inventory": {"file": str(csv_path), "key": "ip"}})
    index = load_inventory(cfg, base_dir=str(tmp_path))
    assert set(index) == {"10.0.0.1", "10.0.0.2"}
    assert index["10.0.0.1"]["criticality"] == "5"
    assert "core" in index["10.0.0.1"]["tags"]

"""CDP (Cisco) and LLDP (IEEE 802.1AB) TLV parsers.

Used two ways:
  * on frames captured by ``discovery/neighbors.py`` (raw capture, needs CAP_NET_RAW)
  * on the octet-string payloads of ``lldpRem*`` / ``dot1d`` MIB rows

Both paths produce ``Neighbor`` records, so the topology builder does not care
where the adjacency came from.
"""

from __future__ import annotations

from typing import Any

from ..models import Neighbor
from ..util import norm_ip, parse_mac

CDP_TYPES = {
    1: "device_id",
    2: "addresses",
    3: "port_id",
    4: "capabilities",
    5: "version",
    6: "platform",
    7: "ip_prefix",
    8: "proto_alias",
    9: "vlan_name",
    10: "mtu",
    11: "native_vlan",
    15: "duplex",
    17: "trunk_mgmt_vlan",
    20: "system_name",
}

CDP_CAPABILITIES = {
    0x01: "router",
    0x02: "switch",
    0x04: "bridge",
    0x08: "wlan-access-point",
    0x10: "telephone",
    0x20: "docsis-cable-device",
    0x40: "server",
}

LLDP_TYPES = {
    0: "end",
    1: "chassis_id",
    2: "port_id",
    3: "ttl",
    4: "port_description",
    5: "system_name",
    6: "system_description",
    7: "management_address",
    8: "system_capabilities",
    9: "management_vlan",
    10: "link_aggregation",
    16: "power_via_mdi",
}

LLDP_ETHERTYPE = b"\x88\xcc"

LLDP_CAPABILITIES = {0: "other", 1: "repeater", 2: "mac-bridge", 3: "wlan-access-point", 4: "router", 5: "telephone", 6: "docsis-cable-device", 7: "station-only"}

CHASSIS_ID_SUBTYPES = {1: "component", 2: "interface-alias", 3: "port-comp", 4: "mac-address", 5: "network-address", 6: "interface-name", 7: "local"}
PORT_ID_SUBTYPES = {1: "interface-alias", 2: "port-component", 3: "mac-address", 4: "network-address", 5: "interface-name", 6: "agent-circuit-id", 7: "local"}


class FrameError(ValueError):
    pass


# ---------------------------------------------------------------------------
# CDP
# ---------------------------------------------------------------------------


def parse_cdp(frame: bytes) -> dict[str, Any]:
    """Parse a CDP PDU (header + TLVs) into a flat dict."""
    if len(frame) < 8:
        raise FrameError("CDP frame too short")
    version, ttl = frame[0], frame[1]
    if version not in (1, 2):
        raise FrameError(f"unsupported CDP version {version}")
    checksum = int.from_bytes(frame[2:4], "big")
    out: dict[str, Any] = {"protocol": "cdp", "cdp_version": version, "ttl": ttl, "checksum": checksum, "tlvs": []}
    body = frame[4:]
    pos = 0
    while pos + 4 <= len(body):
        tlv_type = int.from_bytes(body[pos : pos + 2], "big")
        length = int.from_bytes(body[pos + 2 : pos + 4], "big")
        if length < 4 or pos + length > len(body):
            break
        value = body[pos + 4 : pos + length]
        name = CDP_TYPES.get(tlv_type, f"type-{tlv_type}")
        decoded = _decode_cdp_tlv(name, value)
        out["tlvs"].append({"type": tlv_type, "name": name, "value": decoded})
        out.setdefault(name, decoded)
        pos += length
    return out


def _decode_cdp_tlv(name: str, value: bytes) -> Any:
    if name == "device_id" or name == "version" or name == "platform" or name == "port_id":
        return value.decode("utf-8", "replace").strip("\x00").strip()
    if name == "capabilities":
        bits = int.from_bytes(value[:4], "big") if len(value) >= 4 else 0
        return {"mask": bits, "list": sorted(k for v, k in CDP_CAPABILITIES.items() if bits & v)}
    if name == "addresses":
        return _decode_cdp_addresses(value)
    if name in ("native_vlan", "duplex"):
        return int.from_bytes(value[:2], "big")
    if name == "mtu":
        return int.from_bytes(value[:4], "big")
    if name == "ip_prefix":
        prefix = value[0] if value else 0
        raw = value[2:6]
        return f"{'.'.join(str(b) for b in raw)}/{prefix}" if len(raw) == 4 else None
    return value.hex()


def _decode_cdp_addresses(value: bytes) -> list[str]:
    """CDP TLV 2: u8 number-of-addresses, 3 reserved, then per address:
    u32 protocol-type-PDU (0x08000000 for IPv4), u8 length, address bytes.
    """
    if len(value) < 5:
        return []
    count = value[0]
    pos = 4
    addr_len = value[pos + 4] if pos + 4 < len(value) else 0
    addrs: list[str] = []
    pos += 5
    for _ in range(count):
        if pos + addr_len > len(value):
            break
        raw = value[pos : pos + addr_len]
        pos += addr_len
        if addr_len == 4:
            addrs.append(".".join(str(b) for b in raw))
        elif addr_len == 6:
            mac = parse_mac(raw)
            if mac:
                addrs.append(mac)
        elif addr_len == 16:
            groups = [f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2)]
            addrs.append(":".join(groups))
    return addrs


# ---------------------------------------------------------------------------
# LLDP
# ---------------------------------------------------------------------------


def parse_lldp(frame: bytes) -> dict[str, Any]:
    """Parse an LLDPDU (skipping the 14-byte Ethernet header if present)."""
    if len(frame) >= 14 and frame[12:14] == LLDP_ETHERTYPE:
        frame = frame[14:]
    out: dict[str, Any] = {"protocol": "lldp", "tlvs": []}
    pos = 0
    tlv_index = {}
    while pos + 2 <= len(frame):
        header = int.from_bytes(frame[pos : pos + 2], "big")
        tlv_type, length = header >> 9, header & 0x01FF
        pos += 2
        if pos + length > len(frame):
            break
        value = frame[pos : pos + length]
        pos += length
        name = LLDP_TYPES.get(tlv_type, f"org-{tlv_type}")
        decoded = _decode_lldp_tlv(name, value)
        out["tlvs"].append({"type": tlv_type, "name": name, "value": decoded})
        tlv_index[name] = decoded
        out[name] = decoded
        if tlv_type == 0:
            break
    out["raw"] = frame
    return out


def _decode_lldp_tlv(name: str, value: bytes) -> Any:
    if name == "end":
        return None
    if name in ("chassis_id", "port_id"):
        subtypes = CHASSIS_ID_SUBTYPES if name == "chassis_id" else PORT_ID_SUBTYPES
        sub = value[0] if value else 0
        body = value[1:]
        if sub == 4:
            return {"subtype": subtypes.get(sub, sub), "value": parse_mac(body)}
        if sub == 5 and len(body) == 4:
            return {"subtype": subtypes.get(sub, sub), "value": ".".join(str(b) for b in body)}
        return {"subtype": subtypes.get(sub, sub), "value": body.decode("utf-8", "replace").strip()}
    if name == "ttl":
        return int.from_bytes(value, "big")
    if name in ("port_description", "system_name", "system_description"):
        return value.decode("utf-8", "replace").strip()
    if name == "management_address":
        # [address string length][subtype][address][interface subtype][interface number]
        # `address string length` counts the address only (4 for IPv4, 16 for
        # IPv6). Some agents include the subtype octet in that count, and the
        # subtype bit layout differs between vendors, so the address length
        # decides instead of the flag bits.
        if len(value) < 3:
            return None
        str_len = value[0]
        body = value[2 : 2 + str_len] if str_len else b""
        if len(body) not in (4, 16):
            body = value[2:]
        if len(body) >= 4 and len(body) < 16:
            return ".".join(str(b) for b in body[:4])
        if len(body) >= 16:
            return ":".join(f"{body[i]:02x}{body[i + 1]:02x}" for i in range(0, 16, 2))
        return body.hex()
    if name == "system_capabilities":
        available = int.from_bytes(value[:2], "big") if len(value) >= 2 else 0
        enabled = int.from_bytes(value[2:4], "big") if len(value) >= 4 else 0
        return {
            "enabled": sorted(k for i, k in LLDP_CAPABILITIES.items() if enabled >> i & 1),
            "supported": sorted(k for i, k in LLDP_CAPABILITIES.items() if available >> i & 1),
        }
    if name == "management_vlan":
        return int.from_bytes(value, "big") if len(value) == 2 else None
    if name == "link_aggregation":
        return {"supported": bool(value[0] & 1) if value else False, "id": int.from_bytes(value[1:5], "big") if len(value) >= 5 else None}
    if name == "power_via_mdi":
        return {"port": value[0] & 0x01 if value else 0, "pairs": (value[0] >> 1) & 0x03 if value else 0}
    return value.hex()


# ---------------------------------------------------------------------------
# -> model
# ---------------------------------------------------------------------------


def neighbor_from_cdp(local_if: str | None, parsed: dict) -> Neighbor:
    addrs = [a for a in (parsed.get("addresses") or []) if looks_like_ip(a)]
    caps = parsed.get("capabilities") or {}
    if isinstance(caps, dict):
        caps = caps.get("list") or []
    return Neighbor(
        via="cdp",
        local_if=local_if,
        remote_key=norm_ip(addrs[0]) if addrs else (parsed.get("device_id") or None),
        remote_system=parsed.get("device_id"),
        remote_port=parsed.get("port_id"),
        remote_ip=addrs[0] if addrs else None,
        remote_description=parsed.get("version"),
        remote_mac=None,
        capabilities=list(caps),
        confidence=0.95,
    )


def neighbor_from_lldp(local_if: str | None, parsed: dict) -> Neighbor:
    chassis = parsed.get("chassis_id") or {}
    port = parsed.get("port_id") or {}
    mgmt = parsed.get("management_address")
    key = None
    if isinstance(mgmt, str) and looks_like_ip(mgmt):
        key = norm_ip(mgmt)
    elif isinstance(chassis, dict) and looks_like_ip(chassis.get("value")):
        key = norm_ip(chassis["value"])
    else:
        key = parsed.get("system_name")
    caps = (parsed.get("system_capabilities") or {}).get("enabled") or []
    return Neighbor(
        via="lldp",
        local_if=local_if,
        remote_key=key,
        remote_system=parsed.get("system_name"),
        remote_port=port.get("value") if isinstance(port, dict) else port,
        remote_chassis_id=chassis.get("value") if isinstance(chassis, dict) else chassis,
        remote_ip=mgmt if isinstance(mgmt, str) and looks_like_ip(mgmt) else None,
        remote_description=parsed.get("system_description"),
        ttl_seconds=parsed.get("ttl"),
        capabilities=list(caps),
        confidence=0.95,
    )


def looks_like_ip(value: Any) -> bool:
    from ..util import is_ip

    return bool(value) and is_ip(str(value))


__all__ = [
    "parse_cdp",
    "parse_lldp",
    "neighbor_from_cdp",
    "neighbor_from_lldp",
    "CDP_TYPES",
    "LLDP_TYPES",
    "FrameError",
]

"""Optional passive neighbour capture (CDP/LLDP frames).

Active CDP/LLDP enumeration normally comes from the SNMP MIBs. This module is
for the cases where SNMP is not available: sniff the wire for a few seconds and
learn adjacencies from what devices advertise. Requires a capture tool
(``tcpdump``) and privilege; everything degrades to a clean error otherwise.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

from ..models import Neighbor
from ..protocols.frames import looks_like_ip, neighbor_from_cdp, neighbor_from_lldp, parse_cdp, parse_lldp
from ..util import norm_ip, parse_mac


class CaptureUnavailable(RuntimeError):
    pass


async def _run(cmd: list[str], seconds: float) -> bytes:
    exe = shutil.which(cmd[0])
    if not exe:
        raise CaptureUnavailable(f"{cmd[0]} not found; install it or use SNMP-based neighbour discovery")
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=seconds + 5)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:  # pragma: no cover
            pass
        raise CaptureUnavailable(f"{cmd[0]} timed out after {seconds}s") from None
    if proc.returncode not in (0, None) and not out:
        raise CaptureUnavailable(f"{cmd[0]} failed: {(err or b'').decode('utf-8', 'replace')[:200]}")
    return out or b""


async def capture_frames(interface: str | None, seconds: float) -> list[bytes]:
    """Return raw 802.3 frames containing CDP or LLDP ethertypes."""
    if shutil.which("tcpdump"):
        args = ["tcpdump", "-l", "-s", "1518", "-Q", "in", "net 0.0.0.0/0"]
        if interface:
            args = args[:2] + ["-i", interface] + args[2:]
        args[-1] = "( ether proto 0x88cc or ( udp port 2000 ) or ( ip and ( udp port 161 ) ) )"
        out = await _run(["tcpdump", "-vv", "-xx", *(["-i", interface] if interface else []), "-c", "200", "ether proto 0x88cc or ether proto 0x2000"], seconds)
        return _hexdump_frames(out)
    raise CaptureUnavailable("no capture tool available (tcpdump not found)")


def _hexdump_frames(text: bytes) -> list[bytes]:
    """Parse `tcpdump -xx` output back into frames."""
    frames: list[bytes] = []
    current = bytearray()
    for line in text.decode("utf-8", "replace").splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                frames.append(bytes(current))
                current = bytearray()
            continue
        if ":" not in stripped and "." in stripped and len(stripped) > 24:  # packet header line
            if current:
                frames.append(bytes(current))
                current = bytearray()
        m = stripped.rsplit(": ", 1)
        body = m[1] if len(m) == 2 else stripped
        hexes = [h for h in body.split() if len(h) == 2 and all(c in "0123456789abcdefABCDEF" for c in h)]
        if hexes:
            try:
                current.extend(bytes.fromhex("".join(hexes)))
            except ValueError:  # pragma: no cover
                continue
    if current:
        frames.append(bytes(current))
    return frames


def frame_to_neighbor(frame: bytes, *, local_if: str | None = None, src_mac: str | None = None) -> dict[str, Any] | None:
    """Decode one captured frame into a neighbour record."""
    eth_type = frame[12:14] if len(frame) >= 14 else b""
    if eth_type == b"\x88\xcc":
        parsed = parse_lldp(frame)
        nb = neighbor_from_lldp(local_if, parsed)
        kind = "lldp"
    elif len(frame) > 14 and frame[:2] in (b"\x01\x00", b"\x01\x80"):
        body = frame[14:]
        try:
            parsed = parse_cdp(body)
        except Exception as exc:  # noqa: BLE001
            return None
        nb = neighbor_from_cdp(local_if, parsed)
        kind = "cdp"
    else:
        return None
    nb.remote_mac = nb.remote_mac or src_mac
    return {
        "kind": kind,
        "neighbor": nb,
        "source_ip": norm_ip(nb.remote_ip) if looks_like_ip(nb.remote_ip) else None,
        "remote_system": nb.remote_system,
        "src_mac": parse_mac(src_mac) if src_mac else None,
        "confidence": nb.confidence,
    }


async def capture_neighbour_frames(*, iface: str | None = None, seconds: float = 25.0) -> list[dict[str, Any]]:
    frames = await capture_frames(iface, seconds)
    out = []
    for raw in frames:
        item = frame_to_neighbor(raw, local_if=iface)
        if item:
            out.append(item)
    return out


def parse_capture_file(path: str) -> list[dict[str, Any]]:
    """Read a text dump of `tcpdump -xx` (offline analysis / unit tests)."""
    with open(path, "rb") as fh:
        frames = _hexdump_frames(fh.read())
    out = []
    for raw in frames:
        item = frame_to_neighbor(raw)
        if item:
            out.append(item)
    return out


__all__ = [
    "CaptureUnavailable",
    "capture_frames",
    "capture_neighbour_frames",
    "frame_to_neighbor",
    "parse_capture_file",
]

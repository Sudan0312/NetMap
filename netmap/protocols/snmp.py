"""SNMPv1/v2c client built on the in-tree BER codec.

Zero dependencies: a UDP socket, ~150 lines of message framing, and a
GET/GETNEXT/GETBULK walk loop. This is read-only by design -- there is no
SET path anywhere in NetMap, so a scan cannot change a device.
"""

from __future__ import annotations

import logging
import random
import socket
import time
from typing import Any, Iterable

from . import ber
from .mibs import SNMP_ERROR_TEXT, SYS_DESCR

log = logging.getLogger("netmap.snmp")

GET = ber.GET_REQUEST
GETNEXT = ber.GET_NEXT_REQUEST
GETBULK = ber.GET_BULK
RESPONSE = ber.GET_RESPONSE

SUPPORTED_VERSIONS = ("v1", "v2c")


class SNMPError(RuntimeError):
    pass


class SNMPTimeout(SNMPError):
    pass


class SNMPAuthError(SNMPError):
    """Wrong community / unsupported PDU: the target answered, but refused."""


class Credentials:
    def __init__(self, version: str = "v2c", community: str = "public", *, v3: dict | None = None):
        if version not in SUPPORTED_VERSIONS and version != "v3":
            raise SNMPError(f"unsupported SNMP version {version!r}")
        self.version = version
        self.community = community
        self.v3 = v3 or {}

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Credentials {self.version} community={self.community!r}>"

    @property
    def label(self) -> str:
        return f"{self.version}:{self.community}" if self.version != "v3" else f"v3:{self.v3.get('user', '?')}"

    @property
    def wire_version(self) -> int:
        return ber.VERSIONS[self.version]


# ---------------------------------------------------------------------------
# message framing
# ---------------------------------------------------------------------------


def build_request(
    creds: Credentials,
    pdu_type: int,
    oids: list[str],
    *,
    request_id: int | None = None,
    non_repeaters: int = 0,
    max_repetitions: int = 0,
) -> bytes:
    """Encode a GET / GETNEXT / GETBULK request."""
    rid = request_id if request_id is not None else random.randint(1, 0x7FFFFFFE)
    varbinds = ber.encode_varbinds([(oid, ber.encode_null()) for oid in oids])
    if pdu_type == GETBULK:
        pdu_body = (
            ber.encode_int(rid)
            + ber.encode_int(non_repeaters)
            + ber.encode_int(max_repetitions)
            + varbinds
        )
    else:
        pdu_body = ber.encode_int(rid) + ber.encode_int(0) + ber.encode_int(0) + varbinds
    pdu = bytes([pdu_type]) + ber.encode_length(len(pdu_body)) + pdu_body
    message = ber.encode_sequence(ber.encode_int(creds.wire_version), ber.encode_str(creds.community), pdu)
    return message


def parse_message(data: bytes) -> dict:
    """Decode an SNMP message into a plain dict of its top-level fields."""
    reader = ber.Reader(data)
    msg_tag, msg_body, _ = reader.read_tlv()
    if msg_tag != ber.SEQUENCE:
        raise ber.SNMPParseError(f"not an SNMP message ({data[:1].hex()})")
    inner = ber.Reader(msg_body)
    version = ber.decode_int(inner.read_tlv()[1])
    community = inner.read_tlv()[1].decode("latin-1")
    if inner.at_end():
        raise ber.SNMPParseError("message has no PDU")
    pdu_tag, pdu_body, _ = inner.read_tlv()
    pdu = ber.Reader(pdu_body)
    request_id = ber.decode_int(pdu.read_tlv()[1])
    if pdu_tag == GETBULK:
        non_repeaters = ber.decode_int(pdu.read_tlv()[1])
        max_repetitions = ber.decode_int(pdu.read_tlv()[1])
        error_status = error_index = 0
    else:
        error_status = ber.decode_int(pdu.read_tlv()[1])
        error_index = ber.decode_int(pdu.read_tlv()[1])
        non_repeaters = max_repetitions = 0
    varbinds = ber.parse_varbind_list(pdu.data[pdu.pos :]) if not pdu.at_end() else []
    return {
        "version": version,
        "community": community,
        "pdu_type": pdu_tag,
        "request_id": request_id,
        "error_status": error_status,
        "error_index": error_index,
        "non_repeaters": non_repeaters,
        "max_repetitions": max_repetitions,
        "varbinds": varbinds,
    }


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------


class SNMPClient:
    """Synchronous, single-socket client. One instance per target host."""

    def __init__(
        self,
        host: str,
        *,
        creds: Credentials | None = None,
        port: int = 161,
        timeout: float = 1.2,
        retries: int = 1,
        source_ip: str | None = None,
        local_port: int | None = None,
    ):
        self.host = host
        self.port = int(port)
        self.creds = creds or Credentials()
        self.timeout = float(timeout)
        self.retries = int(retries)
        self.source_ip = source_ip
        self.local_port = local_port
        self._sock: socket.socket | None = None
        self._rid = random.randint(1, 0x7FFFFFF0)
        self.requests = 0
        self.timeouts = 0
        self.last_rtt_ms: float | None = None

    # -- plumbing -----------------------------------------------------------
    def _socket(self) -> socket.socket:
        if self._sock is None:
            family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            if self.source_ip:
                try:
                    sock.bind((self.source_ip, self.local_port or 0))
                except OSError as exc:  # pragma: no cover
                    log.debug("cannot bind source %s: %s", self.source_ip, exc)
            self._sock = sock
        return self._sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "SNMPClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- requests ----------------------------------------------------------
    def _next_rid(self) -> int:
        self._rid = self._rid % 0x7FFFFFFE + 1
        return self._rid

    def _exchange(self, message: bytes, expect_id: int) -> dict:
        sock = self._socket()
        for attempt in range(self.retries + 1):
            self.requests += 1
            stamp = time.monotonic()
            try:
                sock.sendto(message, (self.host, self.port))
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                self.timeouts += 1
                if attempt >= self.retries:
                    raise SNMPTimeout(f"{self.host}:{self.port} no reply after {self.timeout}s") from None
                continue
            except OSError as exc:
                if exc.errno in (101, 113) and attempt < self.retries:
                    continue
                raise SNMPError(f"{self.host}:{self.port} socket error: {exc}") from exc
            if addr[0] != self.host:
                # unsolicited/spoofed reply: ignore and retry inside the deadline
                continue
            self.last_rtt_ms = round((time.monotonic() - stamp) * 1000, 2)
            parsed = parse_message(data)
            if parsed["request_id"] != expect_id:
                log.debug("request-id mismatch (%s != %s), ignoring", parsed["request_id"], expect_id)
                if attempt < self.retries:
                    continue
                raise SNMPError("response request-id did not match request")
            return parsed
        raise SNMPTimeout(f"{self.host}:{self.port} timed out")

    def _check(self, parsed: dict, oids: list[str]) -> dict[str, Any]:
        status = parsed["error_status"]
        if status:
            text = SNMP_ERROR_TEXT.get(status, "unknown error")
            if status == 2:  # noSuchName: object simply is not supported here
                log.debug("SNMP %s: %s -> treating as unsupported", self.host, text)
                return {oid: None for oid in oids}
            if status in (1, 6):  # tooBig/noAccess: retrying is pointless
                raise SNMPError(f"SNMP error {status} ({text})")
            idx = int(parsed["error_index"] or 0)
            target = oids[idx - 1] if 0 < idx <= len(oids) else (oids[0] if oids else "?")
            raise SNMPError(f"SNMP error {status} ({text}) at {target}")
        return {oid: value for oid, value in parsed["varbinds"]}

    def get(self, oids: Iterable[str] | str) -> dict[str, Any]:
        if isinstance(oids, str):
            oids = [oids]
        oid_list = [str(o) for o in oids]
        rid = self._next_rid()
        parsed = self._exchange(build_request(self.creds, GET, oid_list, request_id=rid), rid)
        return self._check(parsed, oid_list)

    def get_one(self, oid: str) -> Any:
        return self.get([oid]).get(oid)

    def get_next(self, oids: Iterable[str]) -> dict[str, Any]:
        oid_list = [str(o) for o in oids]
        rid = self._next_rid()
        parsed = self._exchange(build_request(self.creds, GETNEXT, oid_list, request_id=rid), rid)
        return self._check(parsed, oid_list)

    def walk(self, base: str, *, max_rows: int = 600, max_depth: int | None = None) -> list[tuple[str, Any]]:
        """GETNEXT walk below `base`."""
        rows: list[tuple[str, Any]] = []
        current = base
        prefix = base.rstrip(".")
        while len(rows) < max_rows:
            got = self.get_next([current])
            oid, value = next(iter(got.items()))
            if not oid.startswith(prefix + ".") and oid != prefix:
                break
            if value is None:  # endOfMibView / noSuchInstance
                break
            if max_depth is not None and len(oid.split(".")) > len(prefix.split(".")) + max_depth:
                break
            rows.append((oid, value))
            current = oid
        return rows

    def bulk_walk(self, base: str, *, max_rows: int = 600, repetitions: int = 40) -> list[tuple[str, Any]]:
        """GETBULK walk (v2c only); falls back to GETNEXT for v1 or on error."""
        if self.creds.version == "v1":
            return self.walk(base, max_rows=max_rows)
        rows: list[tuple[str, Any]] = []
        prefix = base.rstrip(".")
        current = [base]
        while len(rows) < max_rows and current:
            rid = self._next_rid()
            try:
                parsed = self._exchange(
                    build_request(self.creds, GETBULK, current, request_id=rid, non_repeaters=0, max_repetitions=repetitions),
                    rid,
                )
                pairs = parsed["varbinds"]
            except (SNMPError, ber.BERError) as exc:
                log.debug("GETBULK failed on %s (%s); using GETNEXT walk", base, exc)
                return self.walk(base, max_rows=max_rows)
            nxt = []
            for oid, value in pairs:
                if not oid.startswith(prefix + ".") or value is None:
                    continue
                rows.append((oid, value))
                if len(rows) >= max_rows:
                    break
                nxt = [oid]  # resume from the highest OID seen
            if not nxt or nxt == current:
                break
            current = nxt
        return rows[:max_rows]

    def walk_smart(self, base: str, **kw) -> list[tuple[str, Any]]:
        try:
            return self.bulk_walk(base, **kw)
        except (SNMPTimeout, SNMPError) as exc:
            if isinstance(exc, SNMPTimeout):
                raise
            log.debug("bulk walk %s failed: %s", base, exc)
            return []


# ---------------------------------------------------------------------------
# credential discovery
# ---------------------------------------------------------------------------


def try_credentials(
    host: str,
    *,
    port: int = 161,
    versions: Iterable[str] = ("v2c", "v1"),
    communities: Iterable[str] = ("public",),
    v3: dict | None = None,
    timeout: float = 1.0,
    retries: int = 0,
) -> tuple[Credentials, dict[str, Any]] | tuple[None, None]:
    """Return the first credential set that answers, plus its sysDescr facts.

    Trying the well-known default communities is intentional: whether a device
    still answers 'public' *is* the finding (RISK-SNMP-DEFAULT).
    """
    combos: list[Credentials] = []
    for version in versions:
        for community in communities:
            combos.append(Credentials(version, community))
    if (v3 or {}).get("enabled"):
        combos.append(Credentials("v3", "", v3=v3))
    for creds in combos:
        client = SNMPClient(host, creds=creds, port=port, timeout=timeout, retries=retries)
        try:
            values = client.get([SYS_DESCR, "1.3.6.1.2.1.1.5.0"])
            facts = {"sys_descr": values.get(SYS_DESCR), "sys_name": values.get("1.3.6.1.2.1.1.5.0")}
            return creds, facts
        except (SNMPTimeout, SNMPError, ber.BERError, OSError) as exc:
            log.debug("snmp %s %s failed on %s: %s", creds.version, creds.community, host, exc)
            continue
        finally:
            client.close()
    return None, None


def encode_ip_address(ip: str) -> bytes:
    """Helper for tests/sim: build an IpAddress value TLV."""
    parts = [int(p) for p in ip.split(".")]
    return ber.tlv(ber.IP_ADDRESS, bytes(parts))


def __getattr__(name: str):  # pragma: no cover - small deprecation shim
    raise AttributeError(name)

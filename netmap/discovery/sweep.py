"""Async host sweep and TCP/UDP port scan.

Strategies, in the order they are attempted for `auto`:
  1. ICMP echo via the system ``ping`` binary (no raw sockets needed, so it
     works unprivileged; RTT is parsed from the summary line)
  2. TCP connect to a few common ports -- a *refused* reply still proves the
     host is up, which is what makes this work when ICMP is filtered
  3. ARP / neighbour-table evidence supplied by the engine (a host with a live
     ARP entry is up regardless of what ping says)

Port scanning uses ``loop.create_connection`` and keeps the socket open for the
banner read, so an open port costs one round trip, not two.
"""

from __future__ import annotations

import asyncio
import errno
import re
import shutil
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from ..ports import port_category, port_name


class RateLimiter:
    """Token bucket shared by all workers, so `rate_pps` actually holds."""

    def __init__(self, rate_pps: float, burst: int | None = None):
        self.rate = max(1.0, float(rate_pps))
        self.capacity = float(burst or max(4, int(self.rate // 4) or 4))
        self.tokens = self.capacity
        self._stamp = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, cost: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self._stamp) * self.rate)
                self._stamp = now
                if self.tokens >= cost:
                    self.tokens -= cost
                    return
                await asyncio.sleep((cost - self.tokens) / self.rate)

    async def __aenter__(self):  # pragma: no cover - symmetry helper
        await self.acquire()
        return self

    async def __aexit__(self, *exc):  # pragma: no cover
        return False


@dataclass
class HostResult:
    ip: str
    alive: bool = False
    method: str = "none"  # icmp | tcp-refused | tcp-open | arp | none
    rtt_ms: float | None = None
    evidence: list[str] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "alive": self.alive,
            "method": self.method,
            "rtt_ms": self.rtt_ms,
            "evidence": self.evidence,
            "closed_ports": self.closed_ports,
        }


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"  # open | closed | filtered | open|filtered | unreachable
    rtt_ms: float | None = None
    banner: bytes | None = None
    error: str | None = None
    writer: Any = None
    reader: Any = None

    @property
    def name(self) -> str:
        return port_name(self.port, self.protocol)

    @property
    def category(self) -> str:
        return port_category(self.port, self.protocol)


PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


def ping_available() -> str | None:
    return shutil.which("ping")


async def icmp_ping(host: str, *, timeout: float = 1.0, count: int = 1, binary: str | None = None) -> HostResult:
    """One ICMP echo round, via the system ping binary."""
    binary = binary or ping_available()
    if not binary:
        return HostResult(ip=host, evidence=["ping binary not found"])
    family_flag: list[str] = []
    args = [binary, "-n", "-c", str(int(count)), *family_flag]
    # -W is seconds on Linux/BSD, ms on Windows-ish builds; -t is Windows TTL
    if _is_linux():
        args += ["-W", str(max(1, int(round(timeout))))]
    elif _is_mac():
        args += ["-t", str(max(1, int(round(timeout))))]
    args.append(host)
    started = time.monotonic()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout + count + 2.0)
    except asyncio.TimeoutError:
        if proc is not None:
            await _kill(proc)
        return HostResult(ip=host, evidence=["ping timed out"])
    except (OSError, ValueError) as exc:
        return HostResult(ip=host, evidence=[f"ping error: {exc}"])
    elapsed = round((time.monotonic() - started) * 1000, 1)
    text = out.decode("utf-8", "replace") if out else ""
    err_text = (err or b"").decode("utf-8", "replace") if "err" in dir() else ""
    alive = proc.returncode == 0
    m = PING_TIME_RE.search(text)
    rtt = float(m.group(1)) if m else (elapsed if alive else None)
    if alive and "100% packet loss" in text:
        alive = False
    evidence: list[str] = []
    if not alive:
        if "Operation not permitted" in err_text or "cap_net_raw" in err_text:
            evidence.append("icmp unavailable: no CAP_NET_RAW / setuid ping; set scan.ping.strategy=tcp")
        elif "Destination Host Unreachable" in text:
            evidence.append("icmp host unreachable")
        else:
            evidence.append(f"ping rc={proc.returncode}")
    return HostResult(ip=host, alive=alive, method="icmp" if alive else "none", rtt_ms=rtt, evidence=evidence)


def _is_linux() -> bool:
    import sys

    return sys.platform.startswith("linux")


def _is_mac() -> bool:
    import sys

    return sys.platform == "darwin"


async def _kill(proc) -> None:  # pragma: no cover
    try:
        proc.kill()
        await proc.wait()
    except Exception:
        pass


async def tcp_ping(
    host: str,
    ports: Sequence[int] = (22, 80, 443, 445, 3389),
    *,
    timeout: float = 0.6,
) -> HostResult:
    """Alive if any TCP port answers -- including with a RST (refused)."""
    if not ports:
        return HostResult(ip=host)
    results = await asyncio.gather(
        *[probe_tcp(host, int(p), timeout=timeout, read=False) for p in ports], return_exceptions=True
    )
    res = HostResult(ip=host)
    for item in results:
        if isinstance(item, BaseException):
            continue
        if item.state == "open":
            res.alive, res.method, res.rtt_ms = True, "tcp-open", item.rtt_ms
            res.evidence.append(f"port {item.port}/tcp open")
            break
        if item.state == "closed":
            res.closed_ports.append(item.port)
            if not res.alive:
                res.alive, res.method, res.rtt_ms = True, "tcp-refused", item.rtt_ms
                res.evidence.append(f"port {item.port}/tcp refused (host responded)")
    return res


async def probe_tcp(
    host: str,
    port: int,
    *,
    timeout: float = 0.75,
    read: bool = True,
    payload: bytes | None = None,
    banner_bytes: int = 1024,
    keep: bool = False,
) -> PortResult:
    """Connect, optionally send a probe, optionally read once."""
    started = time.monotonic()
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=timeout)
    except asyncio.TimeoutError:
        return PortResult(port=port, state="filtered", error="connect timeout")
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed", rtt_ms=_ms(started))
    except OSError as exc:
        state = "unreachable" if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENOENT) else "filtered"
        return PortResult(port=port, state=state, error=str(exc.strerror or exc))
    rtt = _ms(started)
    banner = None
    try:
        if payload is not None:
            writer.write(payload)
            await writer.drain()
        if read:
            banner = await asyncio.wait_for(reader.read(banner_bytes), timeout=min(2.5, timeout * 2))
    except asyncio.TimeoutError:
        banner = banner or b""
    except (OSError, asyncio.IncompleteReadError):
        pass
    if not keep:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return PortResult(port=port, state="open", rtt_ms=rtt, banner=banner or b"", reader=reader if keep else None, writer=writer if keep else None)


def _ms(started: float) -> float:
    return round((time.monotonic() - started) * 1000, 2)


async def probe_udp(
    host: str,
    port: int,
    *,
    payload: bytes,
    timeout: float = 0.5,
) -> PortResult:
    """Single-datagram UDP probe. No reply => open|filtered (ICMP errors are
    invisible without raw sockets); a reply => open."""
    loop = asyncio.get_running_loop()
    try:
        sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        return PortResult(port=port, protocol="udp", state="unreachable", error=str(exc))
    sock.setblocking(False)
    started = time.monotonic()
    fut: asyncio.Future = loop.create_future()

    def _readable():
        try:
            data = sock.recv(2048)
            if not fut.done():
                fut.set_result(data)
        except OSError as exc:
            if not fut.done():
                fut.set_exception(exc)
        finally:
            loop.remove_reader(sock.fileno())

    try:
        loop.add_reader(sock.fileno(), _readable)
        sock.sendto(payload, (host, int(port)))
        data = await asyncio.wait_for(fut, timeout=timeout)
        state = "open" if data else "open|filtered"
        return PortResult(port=port, protocol="udp", state=state, banner=data or None, rtt_ms=_ms(started))
    except asyncio.TimeoutError:
        return PortResult(port=port, protocol="udp", state="open|filtered", rtt_ms=_ms(started))
    except OSError as exc:
        state = "closed" if exc.errno == errno.ECONNREFUSED else "unreachable"
        return PortResult(port=port, protocol="udp", state=state, error=str(exc.strerror or exc))
    finally:
        try:
            sock.close()
        except OSError:
            pass


UDP_PROBES: dict[int, bytes] = {
    53: bytes.fromhex("abcd010000010000000000000776657273696f6e0462696e640000100003"),  # CH TXT version.bind
    123: b"\x1b" + b"\x00" * 47,  # NTP v3 mode 3 client
    161: b"",  # replaced by the SNMP client; placeholder so the port is touched
    137: bytes.fromhex("82a60100000100000000000020434b414141414141414141414141414141414141414141414141414141410000210001"),
    518: b"\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00",
    111: bytes.fromhex("00000028" + "5c000000" + "00000002" + "000186a0" + "00000004" + "00000004" + "00000000" + "00000000" + "00000001"),
}


async def scan_host(
    host: str,
    *,
    tcp_ports: Sequence[int] = (),
    udp_ports: Sequence[int] = (),
    concurrency: int = 64,
    connect_timeout: float = 0.75,
    read_timeout: float = 1.25,
    banner_grab: bool = True,
    banner_bytes: int = 1024,
    limiter: RateLimiter | None = None,
    on_port: Callable[[PortResult], None] | None = None,
) -> list[PortResult]:
    """Port scan a single host; returns results for every probed port."""
    sem = asyncio.Semaphore(max(1, concurrency))
    tasks: list[asyncio.Task] = []

    async def _tcp(port: int) -> PortResult:
        async with sem:
            if limiter:
                await limiter.acquire()
            res = await probe_tcp(
                host,
                port,
                timeout=connect_timeout,
                read=banner_grab,
                banner_bytes=banner_bytes,
            )
            if on_port:
                on_port(res)
            return res

    async def _udp(port: int) -> PortResult:
        async with sem:
            if limiter:
                await limiter.acquire()
            payload = UDP_PROBES.get(port)
            if not payload:
                return PortResult(port=port, protocol="udp", state="filtered", error="no probe payload")
            res = await probe_udp(host, port, payload=payload, timeout=read_timeout)
            if on_port:
                on_port(res)
            return res

    loop = asyncio.get_event_loop()
    tasks = [loop.create_task(_tcp(int(p))) for p in tcp_ports]
    tasks += [loop.create_task(_udp(int(p))) for p in udp_ports]
    if not tasks:
        return []
    done = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[PortResult] = []
    for item in done:
        if isinstance(item, BaseException):
            out.append(PortResult(port=-1, state="error", error=f"{type(item).__name__}: {item}"))
        else:
            out.append(item)
    return out


async def discover(
    hosts: Sequence[str],
    *,
    strategy: str = "auto",
    icmp_timeout: float = 1.0,
    icmp_count: int = 1,
    concurrency: int = 100,
    tcp_ping_ports: Sequence[int] = (22, 80, 443, 445, 3389),
    rate_pps: float = 350,
    known_alive: Iterable[str] = (),
    on_host: Callable[[HostResult], None] | None = None,
) -> dict[str, HostResult]:
    """Host discovery across a (possibly large) list."""
    hosts = list(dict.fromkeys(hosts))
    known = {str(h) for h in known_alive}
    limiter = RateLimiter(rate_pps)
    sem = asyncio.Semaphore(max(1, concurrency))
    results: dict[str, HostResult] = {}
    ping_bin = ping_available()
    do_icmp = strategy in ("auto", "icmp") and ping_bin
    do_tcp = strategy in ("auto", "tcp", "none")

    async def _one(host: str) -> tuple[str, HostResult]:
        async with sem:
            if host in known:
                return host, HostResult(ip=host, alive=True, method="arp", evidence=["neighbour table"])
            result = HostResult(ip=host)
            if do_icmp:
                await limiter.acquire()
                result = await icmp_ping(host, timeout=icmp_timeout, count=icmp_count, binary=ping_bin)
            if not result.alive and do_tcp:
                await limiter.acquire()
                fallback = await tcp_ping(host, tcp_ping_ports, timeout=min(0.6, icmp_timeout))
                if fallback.alive:
                    fallback.evidence = (result.evidence or []) + fallback.evidence
                    if result.rtt_ms:
                        fallback.rtt_ms = fallback.rtt_ms or result.rtt_ms
                    result = fallback
                elif result.method == "none":
                    result.evidence = (result.evidence or []) + ["no answer to icmp or tcp ping"]
            if on_host:
                on_host(result)
            return host, result

    pairs = await asyncio.gather(*[_one(h) for h in hosts], return_exceptions=True)
    for item in pairs:
        if isinstance(item, BaseException):
            continue
        ip, res = item
        results[ip] = res
    return results


def partition_alive(results: dict[str, HostResult]) -> tuple[list[str], list[str]]:
    alive = [ip for ip, r in results.items() if r.alive]
    dead = [ip for ip, r in results.items() if not r.alive]
    return sorted(alive), sorted(dead)


__all__ = [
    "RateLimiter",
    "HostResult",
    "PortResult",
    "probe_tcp",
    "probe_udp",
    "scan_host",
    "discover",
    "icmp_ping",
    "tcp_ping",
    "partition_alive",
    "UDP_PROBES",
    "ping_available",
]

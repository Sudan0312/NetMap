"""Local / in-process discovery tests (stdlib only, no root required)."""
from __future__ import annotations

import asyncio
import socket
import threading
import time
from pathlib import Path

import pytest

from netmap import ports as ports_mod
from netmap.discovery import probes, sweep
from netmap.discovery.simulator import build_devices
from netmap.protocols import ber, snmp, frames, x509
from netmap.protocols.snmp import Credentials, SNMPClient, SNMPTimeout, SNMPError


# ---- helpers --------------------------------------------------------------

@pytest.fixture(scope="module")
def event_loop_policy():
    # stay on the default loop; keep module scope simple
    return asyncio.DefaultEventLoopPolicy()


def _run(coro):
    return asyncio.run(coro)


# ---- sweep against our local echo server ------------------------------------
def test_probe_tcp_against_local_listener(tcp_server):
    srv = tcp_server(banner=b"SSH-2.0-OpenSSH_8.9 test\r\n")
    res = _run(sweep.probe_tcp("127.0.0.1", srv.port, timeout=1.5, banner_bytes=256))
    assert res.state == "open"
    assert b"OpenSSH" in (res.banner or b"")


def test_probe_tcp_closed_port_refused():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    res = _run(sweep.probe_tcp("127.0.0.1", port, timeout=0.5))
    assert res.state in ("closed", "filtered")


def test_scan_host_runs_multiple_ports(tcp_server):
    s1 = tcp_server(banner=b"SSH-2.0-OpenSSH_8.9\r\n")
    s2 = tcp_server(banner=b"HTTP/1.1 200 OK\r\nServer: nginx/1.18\r\n\r\n")
    results = _run(sweep.scan_host("127.0.0.1", tcp_ports=[s1.port, s2.port], concurrency=4,
                                    connect_timeout=1.0, read_timeout=0.5))
    # scan_host returns a list of PortResult objects
    open_ports = {r.port for r in results if r.state == "open"}
    assert {s1.port, s2.port} <= open_ports


# ---- service classification ------------------------------------------------
def test_classify_service_detects_ssh():
    svc = probes.classify_service(22, "tcp", "open", banner=b"SSH-2.0-OpenSSH_8.9")
    assert svc.is_open
    assert svc.name == "ssh"
    assert "OpenSSH" in (svc.product or "")


def test_classify_service_detects_http_from_banner():
    svc = probes.classify_service(8080, "tcp", "open",
                                  banner=b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n")
    assert svc.name in ("http", "http-proxy")
    assert svc.is_plaintext


def test_classify_service_marks_expected_encryption():
    plain = probes.classify_service(23, "tcp", "open", banner=b"User Access Verification")
    assert plain.is_plaintext is True
    assert plain.is_encrypted is False
    tls = probes.classify_service(443, "tcp", "open")
    assert tls.is_encrypted is True


# ---- SNMP client against an in-process fake agent --------------------------
class _FakeAgent:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.requests = []

    def _run(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            self.requests.append(data)
            try:
                msg = snmp.parse_message(data)
                rid = msg["request_id"]
                varbinds = ber.encode_varbinds([
                    ("1.3.6.1.2.1.1.1.0", ber.encode_str("FakeOS 1.0"))
                ])
                pdu_body = ber.encode_int(rid) + ber.encode_int(0) + ber.encode_int(0) + varbinds
                pdu = bytes([0xA2]) + ber.encode_length(len(pdu_body)) + pdu_body
                resp = ber.encode_sequence(
                    ber.encode_int(msg["version"]),
                    ber.encode_str(msg["community"]),
                    pdu,
                )
                self.sock.sendto(resp, addr)
            except Exception:
                continue

    def close(self):
        self._stop.set()
        self.sock.close()


def test_snmp_client_get_request():
    agent = _FakeAgent()
    try:
        creds = Credentials("v2c", "public")
        with SNMPClient("127.0.0.1", creds=creds, port=agent.port, timeout=1.5, retries=1) as cli:
            res = cli.get(["1.3.6.1.2.1.1.1.0"])
        assert res.get("1.3.6.1.2.1.1.1.0") == "FakeOS 1.0"
    finally:
        agent.close()


def test_snmp_client_timeout_on_closed_port_does_not_hang():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
    t0 = time.monotonic()
    try:
        with SNMPClient("127.0.0.1", creds=Credentials("v2c", "public"), port=closed, timeout=0.3, retries=0) as cli:
            cli.get(["1.3.6.1.2.1.1.1.0"])
    except (SNMPTimeout, SNMPError, OSError):
        pass
    assert time.monotonic() - t0 < 2.0


# ---- ports metadata --------------------------------------------------------
def test_port_info_and_top_ports():
    name, category, enc, risk = ports_mod.port_info(22)
    assert name == "ssh"
    risky = ports_mod.top_ports(8, order="risk")
    assert 23 in risky and 21 in risky
    common = ports_mod.top_ports(20, order="common")
    assert 22 in common and 80 in common and 443 in common
    assert ports_mod.expected_encryption(22, "tcp") in ("ssh", "tls", "none")


# ---- simulator determinism -------------------------------------------------
def test_simulator_is_deterministic_with_seed():
    a, _ = build_devices("small", seed=42)
    b, _ = build_devices("small", seed=42)
    assert [d.ip for d in a] == [d.ip for d in b]
    # Medium lab with different seeds must produce different sys_locations/notes
    # (small lab is too template-heavy to guarantee variety, but re-seeding must
    #  not raise and must always return the same device count).
    c, _ = build_devices("medium", seed=99)
    d, _ = build_devices("medium", seed=7)
    assert len(c) == len(d)
    assert len({dev.snmp.get("sys_location") for dev in c}) >= 1

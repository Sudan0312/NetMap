"""Shared fixtures.

The lab generator is the spine of the suite: it gives every test a realistic,
deterministic network without touching a socket.
"""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from netmap.config import Config, load
from netmap.discovery.simulator import build_devices
from netmap.models import ScanSnapshot
from netmap.pipeline import analyze


@pytest.fixture(scope="session")
def lab_devices():
    devices, zones = build_devices("medium", seed=7)
    return devices, zones


@pytest.fixture(scope="session")
def lab_snapshot(lab_devices) -> ScanSnapshot:
    devices, zones = lab_devices
    from netmap.discovery.engine import classify_devices, snapshot_from_devices

    classify_devices(devices)
    cfg = load(None)
    cfg.set("scan.mode", "lab")
    snap = snapshot_from_devices(devices, cfg, mode="lab", zones=zones)
    analyze(cfg, snap)
    return snap


@pytest.fixture()
def fresh_snapshot() -> ScanSnapshot:
    """An unanalysed snapshot for tests that need to run topology/risk themselves."""
    from netmap.discovery.engine import classify_devices, snapshot_from_devices

    devices, zones = build_devices("small", seed=11)
    classify_devices(devices)
    cfg = load(None)
    cfg.set("scan.mode", "lab")
    return snapshot_from_devices(devices, cfg, mode="lab", zones=zones)


@pytest.fixture()
def cfg() -> Config:
    out = load(None)
    out.set("scan.mode", "lab")
    return out


@pytest.fixture()
def tmp_out(tmp_path: Path) -> Path:
    path = tmp_path / "out"
    path.mkdir()
    return path


class EchoServer:
    """Tiny one-shot TCP listener that answers with a fixed banner."""

    def __init__(self, banner: bytes = b"", response_delay: float = 0.0):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.banner = banner
        self.delay = response_delay
        self.received: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self.sock.settimeout(0.25)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.settimeout(1.5)
                if self.delay:
                    threading.Event().wait(self.delay)
                if self.banner:
                    conn.sendall(self.banner)
                try:
                    data = conn.recv(4096)
                    self.received.append(data)
                except OSError:
                    pass
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture()
def tcp_server():
    servers: list[EchoServer] = []

    def _make(banner: bytes = b"", port_hint: int = 0) -> EchoServer:
        srv = EchoServer(banner)
        servers.append(srv)
        return srv

    yield _make
    for srv in servers:
        srv.close()


@pytest.fixture()
def write_json(tmp_path: Path):
    def _write(name: str, payload: dict) -> Path:
        path = tmp_path / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    return _write


FIXTURES = Path(__file__).parent / "fixtures"

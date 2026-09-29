"""Backend API tests for the NetMap FastAPI service (real pipeline, no mocks)."""
import json
import os
import time
import urllib.error
import urllib.request

BASE = os.environ.get("NETMAP_TEST_BASE", "http://127.0.0.1:8000")


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=15) as r:
        return json.loads(r.read().decode())


def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()
        raise AssertionError(f"HTTP {e.code}: {detail}") from None


def wait_job(jid, timeout=60):
    for _ in range(timeout):
        time.sleep(1)
        j = get(f"/api/scan/{jid}")
        if j["status"] in ("completed", "failed"):
            return j
    raise AssertionError(f"job {jid} did not finish")


def test_health():
    h = get("/api/health")
    assert h["ok"] is True
    print("health OK", h)


def test_invalid_target_rejected():
    try:
        post("/api/scan", {"environment": "live", "target": "not-an-ip", "confirmAuthorized": True})
    except AssertionError as e:
        assert "Invalid target" in str(e), str(e)
        print("invalid target rejected OK")
        return
    raise AssertionError("invalid target was not rejected")


def test_live_requires_confirmation():
    try:
        post("/api/scan", {"environment": "live", "target": "192.168.1.0/24"})
    except AssertionError as e:
        assert "confirmAuthorized" in str(e), str(e)
        print("live gate OK")
        return
    raise AssertionError("live gate missing")


def test_demo_scan_e2e():
    j = post("/api/scan", {"environment": "demo", "size": "small", "seed": 7})
    jid = j["job_id"]
    assert j["stages"] and len(j["stages"]) == 8
    j = wait_job(jid)
    assert j["status"] == "completed", j
    assert j["counts"]["devices"] > 20, j["counts"]
    s = get("/api/summary")
    assert s["devices"] == j["counts"]["devices"], (s, j)
    devs = get("/api/devices")
    assert len(devs) == s["devices"]
    g = get("/api/graph")
    assert len(g["nodes"]) == s["devices"] and len(g["edges"]) == s["links"]
    assert all({"role", "status", "exposed"} <= set(n.keys()) for n in g["nodes"]), "graph nodes must carry role/status/exposed"
    assert any(n.get("role") == "core" for n in g["nodes"]), "core roles must be present for hierarchy"
    f = get("/api/findings")
    assert len(f) == s["findings"] and all(x["title"] and x["severity"] for x in f)
    d1 = get(f"/api/devices/{devs[0]['id']}")
    assert d1["ip"] and "services" in d1 and "findings" in d1
    z = get("/api/zones")
    assert len(z) >= 5
    # watch room: the completed job must carry its narrative + live artefacts
    assert len(j.get("events", [])) >= 6, j.get("events")
    assert len(j.get("live_devices", [])) == s["devices"], len(j.get("live_devices", []))
    assert len(j.get("live_links", [])) == s["links"]
    assert len(j.get("live_findings", [])) > 0
    print(f"demo E2E OK: {s['devices']} devices, {s['links']} links, {s['findings']} findings, {len(j['events'])} narrative events")


def test_changes_and_reports():
    j = post("/api/scan", {"environment": "demo", "size": "small", "seed": 8})
    wait_job(j["job_id"])
    h = get("/api/history")
    assert len(h) >= 2, h
    c = get("/api/changes")
    assert c["available"] is True and "summary" in c
    r = get("/api/reports")
    assert any(x["format"] == "json" for x in r)
    print("history/changes/reports OK", c["summary"])


def test_demo_options_drift():
    a = post("/api/scan", {"environment": "demo", "size": "small", "seed": 7, "include_risks": True})
    wait_job(a["job_id"])
    b = post("/api/scan", {"environment": "demo", "size": "small", "seed": 7, "include_risks": False})
    wait_job(b["job_id"])
    c = get("/api/changes")
    assert c["available"] is True
    s = c["summary"]
    assert (s["devices_removed"] + s["findings_resolved"]) > 0, s
    print("demo drift via include_risks OK", s)


def test_sse_stream():
    import socket
    j = post("/api/scan", {"environment": "demo", "size": "small", "seed": 21})
    jid = j["job_id"]
    req = urllib.request.Request(f"{BASE}/api/scan/{jid}/events", headers={"Accept": "text/event-stream"})
    seen_status = set()
    with urllib.request.urlopen(req, timeout=60) as r:
        assert "text/event-stream" in r.headers.get("Content-Type", ""), r.headers
        buf = b""
        while True:
            chunk = r.read(1024)
            if not chunk:
                break
            buf += chunk
            while b"\n\n" in buf:
                frame, buf = buf.split(b"\n\n", 1)
                for line in frame.decode().splitlines():
                    if line.startswith("data: "):
                        payload = json.loads(line[6:])
                        if payload.get("status"):
                            seen_status.add(payload["status"])
                if "completed" in seen_status or "failed" in seen_status:
                    break
            if "completed" in seen_status or "failed" in seen_status:
                break
    assert "completed" in seen_status, seen_status
    print("SSE stream OK, states seen:", sorted(seen_status))


def test_live_loopback_scan():
    # Genuine live pipeline against this machine's loopback (private/loopback ranges are allowed).
    j = post("/api/scan", {"environment": "live", "target": "127.0.0.1/32", "mode": "fast", "confirmAuthorized": True, "snmp_community": "public"})
    assert "public" not in json.dumps(j), "SNMP secret must never be echoed in the job response"
    j = wait_job(j["job_id"], timeout=150)
    assert j["status"] == "completed", j
    assert j["environment"] == "live", j
    assert j["counts"]["devices"] >= 1, j["counts"]
    devs = get("/api/devices")
    ips = [d["ip"] for d in devs]
    assert "127.0.0.1" in ips, ips
    s = get("/api/summary")
    assert s["mode"] == "live", s
    assert len(j.get("events", [])) >= 3, j.get("events")
    assert any(d["ip"] == "127.0.0.1" for d in j.get("live_devices", [])), j.get("live_devices")
    print(f"LIVE LOOPBACK OK: {s['devices']} device(s), {s['services']} services, {s['findings']} findings; capture={j.get('capture_status')}")


def test_snmp_session_store():
    import urllib.request as _u

    def raw(method, path, body=None):
        r = _u.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None,
                       headers={"Content-Type": "application/json"}, method=method)
        try:
            return 200, _u.urlopen(r, timeout=15).read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    _, _ = raw("DELETE", "/api/settings/snmp")
    code, b = raw("GET", "/api/settings/snmp")
    assert code == 200 and json.loads(b)["configured"] is False, b
    code, b = raw("POST", "/api/settings/snmp", {"community": "s3cr3t-lab"})
    assert code == 200 and json.loads(b)["configured"] is True, b
    assert "s3cr3t-lab" not in b
    for p in ("/api/settings/snmp", "/api/capabilities", "/api/health", "/api/jobs"):
        _, body = raw("GET", p)
        assert "s3cr3t-lab" not in body, f"secret leaked via {p}"
    code, b = raw("GET", "/api/settings/snmp")
    assert json.loads(b)["configured"] is True and "s3cr3t-lab" not in b, b
    _, _ = raw("DELETE", "/api/settings/snmp")
    _, b = raw("GET", "/api/settings/snmp")
    assert json.loads(b)["configured"] is False, b
    print("SNMP session store OK (set/use/clear, secret never echoed)")


def test_gateway_star_links():
    # Deterministic (no network): two reachable hosts on one /24 with zero
    # LLDP/SNMP/MAC evidence. The labelled gateway-star inference must link
    # the member to the discovered .1 gateway serving HTTPS — and must NOT
    # invent a gateway when .1 serves nothing.
    import sys as _sys
    _sys.path.insert(0, ".")
    from netmap.models import Device, ScanSnapshot, Service
    from netmap.topology.builder import build_topology

    def snap_with(gw_services):
        gw = Device(id="ip:192.168.1.1", ip="192.168.1.1", reachable=True,
                    services=list(gw_services))
        member = Device(id="ip:192.168.1.12", ip="192.168.1.12", reachable=True,
                        services=[Service(port=445, protocol="tcp", state="open", name="smb")])
        return ScanSnapshot(snapshot_id="t", mode="live", devices=[gw, member])

    on = lambda k, d=None: True if k == "topology.treat_same_subnet_as_adjacency" else (d if "min_conf" not in k else 0.4)
    s = snap_with([Service(port=443, protocol="tcp", state="open", name="https")])
    build_topology(s, cfg_get=on)
    gw_links = [ln for ln in s.links if ln.derived_from == "same-subnet"]
    assert len(gw_links) == 1, [(ln.src_device, ln.dst_device, ln.derived_from) for ln in s.links]
    assert gw_links[0].confidence <= 0.4, gw_links[0].confidence
    assert {gw_links[0].src_device, gw_links[0].dst_device} == {"ip:192.168.1.1", "ip:192.168.1.12"}

    # Guard: .1 with no open services is not treated as a gateway — no links.
    s2 = snap_with([])
    build_topology(s2, cfg_get=on)
    assert [ln for ln in s2.links if ln.derived_from == "same-subnet"] == [], s2.links

    # Live wiring: a real live scan runs the builder with the flag enabled
    # without errors (single gateway host alone yields no invented links).
    j = post("/api/scan", {"environment": "live", "targets": ["192.168.1.1"],
                            "mode": "fast", "confirmAuthorized": True})
    j = wait_job(j["job_id"], timeout=150)
    assert j["status"] == "completed", j
    assert j["counts"]["devices"] >= 1, j["counts"]
    print(f"GATEWAY-STAR OK: inference links member to serving .1 gateway, "
          f"invents nothing without services; live wiring completed {j['counts']}")


if __name__ == "__main__":
    test_health()
    test_invalid_target_rejected()
    test_live_requires_confirmation()
    test_demo_scan_e2e()
    test_changes_and_reports()
    test_demo_options_drift()
    test_sse_stream()
    test_live_loopback_scan()
    test_snmp_session_store()
    test_gateway_star_links()
    print("ALL BACKEND API TESTS PASSED")

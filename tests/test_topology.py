"""Topology / layout integration tests."""
from __future__ import annotations

from netmap.config import load
from netmap.discovery.engine import classify_devices, snapshot_from_devices
from netmap.discovery.simulator import build_devices
from netmap.pipeline import analyze
from netmap.topology import builder, layout


def _snap(size="small", seed=11):
    devices, zones = build_devices(size, seed=seed)
    classify_devices(devices)
    cfg = load(None); cfg.set("scan.mode", "lab")
    snap = snapshot_from_devices(devices, cfg, mode="lab", zones=zones)
    analyze(cfg, snap)
    return snap


def test_topology_produces_a_connected_graph_in_lab():
    snap = _snap("small")
    assert len(snap.devices) >= 8
    assert len(snap.links) >= 5
    ids = {d.id for d in snap.devices}
    for l in snap.links:
        assert l.src_device in ids and l.dst_device in ids
    b = builder.TopologyBuilder(snap)
    b.from_neighbours(); b.from_mac_tables(); b.from_routing()
    g = b.graph()
    assert g.components()


def test_bridges_and_spofs_are_marked(lab_snapshot):
    snap = lab_snapshot
    metrics = snap.config["topology_metrics"]
    for key in ("nodes", "edges", "bridges", "articulation_points", "components", "link_coverage_pct"):
        assert key in metrics, f"missing metric {key}"
    assert metrics["edges"] == len(snap.links)
    assert metrics["nodes"] == len(snap.devices)
    spof_links = [l for l in snap.links if l.is_spof]
    assert len(spof_links) >= 1
    cov = metrics.get("link_coverage_pct")
    assert 0 <= cov <= 100


def test_layout_assigns_every_reachable_node_a_position():
    snap = _snap("small")
    laid = layout.layout(snap, width=900)
    positions = laid["nodes"]
    reachable_ids = {d.id for d in snap.devices if d.reachable}
    assert set(positions.keys()) == reachable_ids
    for p in positions.values():
        assert 0 <= p["x"] <= 900 and p["y"] >= 0
    assert "bounds" in laid
    edges = layout.edges_with_layout(snap, positions)
    assert len(edges) >= 1
    for e in edges:
        assert "path" in e and "src" in e and "dst" in e


def test_cluster_summary_counts_by_zone(lab_snapshot):
    summary = layout.cluster_summary(lab_snapshot.devices, lab_snapshot.zones)
    assert summary
    total = sum(z["devices"] for z in summary)
    assert total == len(lab_snapshot.devices)
    zones_in_snap = {d.zone for d in lab_snapshot.devices}
    assert zones_in_snap <= {z["zone"] for z in summary}


def test_graph_degree_reflects_links(lab_snapshot):
    b = builder.TopologyBuilder(lab_snapshot)
    g = b.graph()
    # degree must equal the number of incident links for every node
    for dev in lab_snapshot.devices:
        assert g.degree(dev.id) == sum(
            1 for l in lab_snapshot.links if dev.id in (l.src_device, l.dst_device)
        )

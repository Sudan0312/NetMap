# Architecture

NetMap is a seven-stage pipeline with a clear division between **discovery**,
**topology**, **risk** and **reporting**.

```
 ┌─sweep──┐ ┌─fingerprint─┐ ┌─tls/cert─┐ ┌─snmp_enum─┐ ┌─capture──┐
 │  ICMP  │ │   banners    │ │  X.509   │ │ sys/if/arp│ │ CDP/LLDP │
 │ TCP-80 │ │  apply refs  │ │  SNI/hst │ │ fdb/route │ │  frames  │
 └───┬────┘ └──────┬───────┘ └────┬─────┘ └────┬──────┘ └────┬─────┘
     └─────────────┴───────┬──────┴────────────┴─────────────┘
                           ▼
                     classify_devices
                           ▼
              build_topology (Tarjan bridges + APs)
                           ▼
                risk.engine.RiskEngine.analyze
                           ▼
          score_devices → score_network → summarize
                           ▼
                   writer.write_report  (+ serve)
```

## Facts namespace

The expression engine evaluates rules against a facts dict.

- `device.*` — full device record plus derived fields: `open_ports`,
  `management_protocols`, `uplink_count`, `isolated`, `is_articulation_point`,
  `certificate_summary`, `tls_summary`, `os_eol`, `zone`, `trust`,
  `criticality`, `reachable`, `documented`, `banner_summary`, `http_paths`.
- `service.*` — inside `foreach: {over: device.services, where: …}`, the
  service being examined (port/name/product/version/certificate/config/…).
- `link.*` — scope:link rules; `src_device`, `dst_device`, `kind`, `speed_mbps`,
  `is_spof`, `protected`, `confidence`, `carries`, `risk_score`, `zone_a`,
  `zone_b`, `trust_distance`.
- `network.*` — `devices`, `links`, `bridges`, `isolated_nodes`,
  `link_coverage_pct`, `components`, `severity_counts`, `mode`.
- `scan.*` — resolved scan config and thresholds.

## Scoring

Device risk: `10 * (1 − Π (1 − w_i/10))` with criticality/exposure biasing,
capped at 10.

Network risk:

```
0.55*weighted_device_risk
+ 0.25*worst_device_risk
+ 0.20*exposure_index
+ 0.25*architecture_index
+ 0.45*structural_penalty
+ 1.2*coverage_penalty
```

Bands:

| Score from | Band     |
|-----------:|----------|
|        9.0 | Critical |
|        7.0 | High     |
|        4.5 | Moderate |
|        2.0 | Low      |
|        0.0 | Minimal  |

The structural penalty saturates at 2.5 from bridges and 1.5 from isolated
nodes to avoid runaway scores on topologies that are genuinely sparse.

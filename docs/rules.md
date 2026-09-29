# Risk Rule Authoring

Every rule is a dict under the top-level `rules:` list in a YAML file:

```yaml
rules:
  - id: MY-RULE-001           # unique id (letters, digits, dash, underscore)
    title: Short human title
    version: "1"              # bump when changing semantics; participates in fingerprint
    family: exposure          # architecture|asset|coverage|crypto|exposure|hardening|
                              # lifecycle|segmentation|threat|general
    severity: high            # info|low|medium|high|critical
    impact: 8                 # 0..10
    likelihood: 5             # 0..10
    scope: device             # device | link | network
    applies_to:               # optional pre-filter (avoids wasteful evaluation)
      device_type: [router, firewall, switch]
      trust: [dmz, internal]
    when: {port_open: 23}     # expression; fires when truthy
    unless: {path: device.documented}  # optional suppression predicate
    foreach:                  # optional service/link iteration
      over: device.services
      where: {"==": [{"path": "service.name"}, "telnet"]}
    escalate:                 # optional conditional severity upgrades
      - when: {">=": [{"path": "device.criticality"}, 5]}
        severity: critical
        impact: 9
        likelihood: 7
    evidence:
      - "Telnet open on {device.hostname}:{service.port}"
    description: One paragraph for the report.
    remediation: One paragraph telling the engineer what to do.
    refs:
      cwe: CWE-319
      nist: SC-8
      cis: "3.3"
      mitre: T1040
```

## Expression operators

Logic: `and or not nand if true false`
Comparison: `== != > >= < <=`
Sets/strings: `in not_in any_in contains regex lower join coalesce`
Aggregates: `count sum max_of path literal`
Domain helpers: `any_service all_services match_services service_matching port_open
open_port_list tls_of eol_state days_until version_lt has_tag zone_trust
reachable_from max_trust_distance neighbour_missing process_absent http_state
service_config banner_regex now_iso`

No `eval`, no function calls; operators can only reference facts paths through
`resolve_path`. Unknown operators are caught at validate time, not at run time.

## Running extra catalogues

```bash
netmap lab --rules examples/custom_rules.yaml
netmap analyze --from out/snap.json --rules site-a.yaml site-b.yaml
netmap rules validate --files examples/custom_rules.yaml
```

Later files override earlier ones with the same `id`.

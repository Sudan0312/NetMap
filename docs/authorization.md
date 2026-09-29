# Authorization & Rate-Limiting

NetMap treats live scanning as a sensitive operation. The guardrails run
_before_ any packet is sent and cannot be overridden silently.

## Default scope

Out of the box, `netmap discover` will refuse to scan unless **every** target
resolves to an address in:

- `127.0.0.0/8` (loopback),
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC1918),
- `169.254.0.0/16` (link-local),
- `100.64.0.0/10` (CGNAT / shared address space),
- `::1`, `fe80::/10`, `fc00::/7` (IPv6 loopback/ULA/link-local).

Public-routable addresses, multicast, and unspecified addresses are denied
unless `scan.allow_external: true` is set **and** `--confirm-authorized` is
passed on the CLI.

## The authorization gate

Every live scan requires `--confirm-authorized`. You can record who approved
the scan with `--statement`; the statement is stored verbatim in the snapshot:

```bash
netmap discover 10.0.0.0/24 \
    --confirm-authorized \
    --statement "Approved by J. Doe, NETOPS-2042, 2026-09-23 02:00-04:00Z"
```

Without `--confirm-authorized`, the CLI exits with code `3` after printing
which targets were rejected and why.

## Rate-limit & deny-list

- Default rate is `350` probes/sec (`scan.rate_pps`). The limiter is a token
  bucket applied uniformly across TCP, UDP and SNMP.
- `scan.exclude` is a repeatable list of CIDRs/IPs/hosts that are always
  skipped (good for embedded controllers, out-of-band management, printers).
- `scan.max_hosts` caps the number of live hosts per run as an additional
  guard against runaway CIDRs.
- `authorization.scope` in the config can pin runs to an explicit CIDR list
  and `authorization.signed_by` records the sign-off chain for audits.

## Exit codes

| Code | Meaning                                                   |
|-----:|-----------------------------------------------------------|
|    0 | Success, all thresholds passed                            |
|    1 | Threshold breached (`ci`, `compare --fail-on`, `--fail-on`) |
|    2 | Usage / config error                                      |
|    3 | Authorization refused                                     |

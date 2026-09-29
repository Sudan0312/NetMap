# FAQ

**Do I need to install anything else?**
No. NetMap's core is stdlib-only. PyYAML and scapy are optional extras (see
README). JSON twins in `netmap/refs/*.json` are committed to the repo so even
without PyYAML every catalogue still loads.

**Why does `netmap discover` say "authorization refused"?**
Because you didn't pass `--confirm-authorized`. See docs/authorization.md.
If your targets are also outside RFC1918, additionally set `scan.allow_external: true`.

**How do I add our internal rules?**
Create a YAML file (copy `examples/custom_rules.yaml`), validate with
`netmap rules validate --files yours.yaml`, then run with
`--rules yours.yaml`. Rules are additive; same-id rules in later files override
earlier ones.

**Why does the lab network find "critical" issues?**
It's supposed to. The generator deliberately plants realistic misconfigurations
so that reports and severity bands exercise every code path. Use `--no-risks`
to generate a boring clean network, or a fresh seed to reshuffle.

**Can I import an existing nmap/nessus/... scan?**
`netmap discover --import-file` accepts NetMap snapshots (write a small adapter
if you want to feed another scanner; the `models.ScanSnapshot` dataclasses are
stable). Nmap XML import is planned.

**The HTML dashboard shows no external fonts — that's by design?**
Yes. The report renders fully offline and inside sandboxed iframe previews
(e.g. Arena workspaces), so everything is inlined: CSS, SVG, and JS.

**Why does the X.509 parser list CNs under `names` even when a certificate has
no SAN?**
Because legacy network gear ships CN-only certs and clients still fall back to
CN matching in practice. `Certificate.san` is *only* the real SAN extension;
`Certificate.san_source` is `extension | common_name | none`; hostname
matching uses `names` so it behaves the way operators expect.

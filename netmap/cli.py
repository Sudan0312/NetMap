"""Command line interface: `python -m netmap ...` / `netmap ...`.

Subcommands mirror the pipeline stages so a scan can be re-analysed without
re-touching the network: `lab`/`discover` produce a snapshot, `analyze` re-runs
topology + risk on one, `report` re-renders, `compare`/`ci` gate a change.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config, load as load_config
from .config import validate as validate_config
from .report.writer import FORMATS as REPORT_FORMATS
from .util import SEVERITY_ORDER, color, sev
from .pipeline import analyze, compare_snapshots, discover, load_snapshot, run as pipeline_run, save_snapshot

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USAGE = 2
EXIT_AUTH = 3


def _cfg(args: argparse.Namespace) -> Config:
    cfg = load_config(getattr(args, "config", None))
    for item in getattr(args, "set", []) or []:
        if "=" not in item:
            raise SystemExit(f"--set expects key=value, got {item!r}")
        key, _, value = item.partition("=")
        try:
            parsed: Any = json.loads(value)
        except json.JSONDecodeError:
            parsed = value
        cfg.set(key.strip(), parsed)
    return cfg


def _progress(args: argparse.Namespace):
    """Stage callback: `progress(stage, fraction, message)`.

    Tolerates being called with a dict of stage counters or a bare message so
    third-party callers cannot break a scan with a signature mismatch.
    """
    quiet = getattr(args, "quiet", False)

    def cb(stage, frac=None, msg="") -> None:
        if isinstance(frac, dict):
            bits = ", ".join(f"{k}={v}" for k, v in frac.items() if not isinstance(v, (list, dict)))
            msg, frac = (msg or bits), 0.0
        elif isinstance(frac, str):
            msg, frac = frac, 0.0
        if quiet:
            return
        pct = f"{int(float(frac or 0) * 100):>3}% " if isinstance(frac, (int, float)) else ""
        sys.stderr.write(f"  {pct}[{stage}] {msg}\n")
        sys.stderr.flush()

    return cb


def _print_summary(snap: Any, *, top: int = 10) -> None:
    risk = snap.risk or {}
    counts = {sev: sum(1 for f in snap.findings if f.severity == sev and f.status == "open") for sev in SEVERITY_ORDER}
    print()
    print(f"{color.bold('NetMap')} {snap.mode} scan {snap.snapshot_id}  finished {snap.finished}")
    print(
        f"  devices {len(snap.devices)}   links {len(snap.links)}   findings {len(snap.findings)}   "
        f"errors {len(snap.errors)}   duration {snap.duration_seconds}s"
    )
    sev_line = "  ".join(f"{sev(_s)} {counts[_s]}" for _s in ("critical", "high", "medium", "low", "info") if counts[_s])
    print(f"  severity: {sev_line or 'nothing open'}")
    score = float(risk.get("score") or 0)
    band = str(risk.get("band") or "unknown")
    band_sev = {"minimal": "info", "low": "low", "moderate": "medium", "high": "high", "critical": "critical"}.get(band.lower(), "medium")
    print(f"  risk score {sev(band_sev)} {score}/10 -> {band}")
    metrics = (snap.config or {}).get("topology_metrics") or {}
    if metrics:
        print(
            f"  topology: {metrics.get('components', '?')} segment(s), {metrics.get('bridges', 0)} SPOF link(s), "
            f"{metrics.get('articulation_points', 0)} device(s) whose loss isolates others, "
            f"{metrics.get('isolated_nodes', 0)} node(s) with no adjacency, link coverage {metrics.get('link_coverage_pct')}%"
        )
    open_f = sorted([f for f in snap.findings if f.status == "open"], key=lambda f: f.sort_key)
    if open_f:
        print(f"\n{color.bold('Top findings')}")
        for f in open_f[:top]:
            print(f"  {sev(f.severity):>24}  {f.rule_id:<12} {f.target_label[:32]:<32} {f.rule_title}")
    fam = (risk.get("families") or {})
    if fam:
        print(f"\n{color.bold('Risk by rule family')}")
        for name, meta in list(fam.items())[:8]:
            print(f"  {name:<8} {meta.get('count'):>4} findings   weight {meta.get('score'):>7}   worst {meta.get('worst')}")


def _write_outputs(snap: Any, args: argparse.Namespace, cfg: Config) -> dict[str, Path]:
    out_dir = Path(str(getattr(args, "out", None) or cfg.get("report.output_dir") or "out"))
    formats = [f.strip() for f in str(getattr(args, "formats", None) or ",".join(cfg.get("report.formats") or ["json", "md"])).split(",") if f.strip()]
    bad = [f for f in formats if f not in REPORT_FORMATS]
    if bad:
        raise SystemExit(f"unknown report format(s) {bad}; choose from {', '.join(REPORT_FORMATS)}")
    from .report.writer import write_report

    rules = None
    try:
        from .risk.engine import RiskEngine

        rules = RiskEngine().rules
    except Exception:  # noqa: BLE001 - reports do not need the catalogue objects
        rules = None
    written = write_report(
        snap,
        out_dir,
        formats=formats,
        title=cfg.get("report.title"),
        redact=bool(cfg.get("report.redact", True)),
        rules=rules,
    )
    if written:
        print(f"\n{color.bold('Wrote')} " + ", ".join(f"{fmt} -> {path}" for fmt, path in sorted(written.items())))
    return written


def _threshold_breach(snap: Any, fail_on: str | None, max_critical: int | None) -> tuple[bool, str]:
    open_f = [f for f in snap.findings if f.status == "open"]
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    if fail_on and fail_on.lower() != "never":
        want = order.get(fail_on.lower(), 4)
        hits = [f for f in open_f if order.get(f.severity, 9) <= want]
        if hits:
            return True, f"{len(hits)} finding(s) at or above {fail_on}"
    if max_critical is not None:
        crit = [f for f in open_f if f.severity == "critical"]
        if len(crit) > max_critical:
            return True, f"{len(crit)} critical findings (budget {max_critical})"
    return False, "within thresholds"


# ---------------------------------------------------------------------- commands
def cmd_init(args: argparse.Namespace) -> int:
    from .config import dump_default

    path = Path(args.out)
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_USAGE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_default(), encoding="utf-8")
    print(f"wrote default configuration to {path}")
    print("next: edit targets/authorization, then run  netmap discover -c", path, "10.0.0.0/24")
    return EXIT_OK


def cmd_lab(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    cfg.set("scan.mode", "lab")
    cfg.set("lab.size", args.size)
    cfg.set("lab.seed", args.seed)
    cfg.set("lab.include_risks", not args.no_risks)
    if args.formats:
        cfg.set("report.formats", [f.strip() for f in args.formats.split(",") if f.strip()])
    if args.snapshot_out:
        cfg.set("report.snapshot_out", args.snapshot_out)
    result = pipeline_run(cfg, rules=args.rules, progress=_progress(args))
    snap = result.snapshot
    _print_summary(snap, top=args.top)
    out_dir = Path(args.out or cfg.get("report.output_dir") or "out")
    out_dir.mkdir(parents=True, exist_ok=True)
    snap_path = Path(args.snapshot_out) if args.snapshot_out else out_dir / "lab-snapshot.json"
    save_snapshot(snap, snap_path)
    print(f"snapshot -> {snap_path}")
    _write_outputs(snap, argparse.Namespace(out=args.out, formats=args.formats, quiet=True), cfg)
    if args.compare_with:
        base = load_snapshot(Path(args.compare_with))
        drift = compare_snapshots(base, snap)
        print(json.dumps(drift, indent=2, default=str)[:4000])
    breach, why = _threshold_breach(snap, args.fail_on, args.max_critical)
    if breach:
        print(f"\n{color.red('threshold breached')}: {why}", file=sys.stderr)
        return EXIT_THRESHOLD
    return EXIT_OK


def cmd_discover(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    if args.targets:
        cfg.set("scan.targets", list(dict.fromkeys(list(cfg.get("scan.targets") or []) + args.targets)))
    if args.exclude:
        cfg.set("scan.exclude", list(cfg.get("scan.exclude") or []) + list(args.exclude))
    if args.ports:
        cfg.set("scan.tcp_ports", args.ports)
    if args.udp_ports:
        cfg.set("scan.udp_ports", args.udp_ports)
    if args.no_snmp:
        cfg.set("scan.snmp.enabled", False)
    if args.no_tls:
        cfg.set("scan.tls_probe", False)
    if args.rate:
        cfg.set("scan.rate_pps", args.rate)
    if args.max_hosts:
        cfg.set("scan.max_hosts", args.max_hosts)
    if args.mode:
        cfg.set("scan.mode", args.mode)
    if args.import_file:
        cfg.set("scan.mode", "import")
        cfg.set("scan.import_path", args.import_file)
    if args.confirm_authorized:
        cfg.set("authorization.confirmed", True)
        cfg.set("authorization.signed_by", cfg.get("authorization.signed_by") or cfg.get("operator") or "cli operator")
        cfg.set("authorization.statement", args.statement or "confirmed on the command line with --confirm-authorized")
        # Recording the requested targets as the authorised scope keeps the
        # audit trail honest instead of leaving the field empty.
        if not (cfg.get("authorization.scope") or []) and args.targets:
            cfg.set("authorization.scope", list(dict.fromkeys(str(t) for t in args.targets)))
    if args.formats:
        cfg.set("report.formats", [f.strip() for f in args.formats.split(",") if f.strip()])

    # An unauthorised live scan is refused before any config nitpicking: the
    # operator needs the reason, not a generic validation dump.
    mode = str(cfg.get("scan.mode") or "live").lower()
    auth_problems = cfg.authorization_problems() if mode == "live" else []
    if auth_problems and not args.dry_run:
        print(f"{color.red('refusing to scan')} - authorization is not complete:", file=sys.stderr)
        for item in auth_problems:
            print(f"  - {item}", file=sys.stderr)
        print("\nRecord written permission in the config (authorization.confirmed / scope / signed_by), "
              "or pass --confirm-authorized when you hold it.", file=sys.stderr)
        print("To exercise the whole pipeline against synthetic data instead: netmap lab", file=sys.stderr)
        return EXIT_AUTH

    errors, warnings = validate_config(cfg)
    for warn in warnings:
        print(f"{color.yellow('warn')} {warn}", file=sys.stderr)
    # authorization gaps are already explained above; a dry run never sends traffic
    fatal = [e for e in errors if not (args.dry_run or "authorization" in e or "confirmed" in e)]
    if fatal:
        for err in fatal:
            print(f"{color.red('config')} {err}", file=sys.stderr)
        return EXIT_USAGE
    if args.dry_run and errors:
        print(f"{color.yellow('dry run')} ignoring {len(errors)} authorization/config complaint(s): " + "; ".join(errors[:3]) + "\n", file=sys.stderr)

    if args.dry_run:
        hosts, names = cfg.resolved_targets()
        print(f"targets: {len(hosts)} host(s) to probe" + (f", {len(names)} name(s) to resolve" if names else ""))
        for host in hosts[:40]:
            print("  ", host)
        if len(hosts) > 40:
            print(f"   ... {len(hosts) - 40} more")
        print("tcp ports:", len(cfg.tcp_port_list()), "udp ports:", len(cfg.udp_port_list()))
        print("would run:", ", ".join(["sweep", "reverse-dns", "arp"] + (["snmp"] if cfg.get("scan.snmp.enabled") else []) + (["tls"] if cfg.get("scan.tls_probe") else [])))
        return EXIT_OK

    result = pipeline_run(cfg, rules=args.rules, progress=_progress(args))
    snap = result.snapshot
    _print_summary(snap, top=args.top)
    out_dir = Path(args.out or cfg.get("report.output_dir") or "out")
    out_dir.mkdir(parents=True, exist_ok=True)
    snap_path = Path(args.snapshot_out) if args.snapshot_out else out_dir / f"{snap.snapshot_id}.json"
    save_snapshot(snap, snap_path)
    print(f"snapshot -> {snap_path}")
    if result.problems:
        print(f"{color.yellow('stage problems')} ({len(result.problems)}):")
        for line in result.problems[:10]:
            print("  ", line)
    _write_outputs(snap, args, cfg)
    if args.baseline:
        base = load_snapshot(Path(args.baseline))
        drift = compare_snapshots(base, snap)
        snap.drift = drift
        path = out_dir / "drift.json"
        path.write_text(json.dumps(drift, indent=2, default=str) + "\n", encoding="utf-8")
        print(
            f"drift vs baseline: +{len(drift['devices_added'])} devices, -{len(drift['devices_removed'])}, "
            f"{len(drift['findings_appeared'])} findings appeared, {len(drift['findings_resolved'])} resolved "
            f"(risk {drift['risk_score']['was']} -> {drift['risk_score']['now']}); detail in {path}"
        )
    breach, why = _threshold_breach(snap, args.fail_on, args.max_critical)
    if breach:
        print(f"\n{color.red('threshold breached')}: {why}", file=sys.stderr)
        return EXIT_THRESHOLD
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    snap = load_snapshot(Path(args.from_snapshot))
    if args.rules:
        cfg.set("risk.rules_files", list(args.rules))
    if args.disable:
        cfg.set("risk.disabled", list(cfg.get("risk.disabled") or []) + list(args.disable))
    if args.only:
        cfg.set("risk.only", list(args.only))
    if args.min_severity:
        cfg.set("risk.min_severity", args.min_severity)
    if args.exception:
        cfg.set("risk.exceptions", list(cfg.get("risk.exceptions") or []) + [json.loads(x) for x in args.exception])
    analyze(cfg, snap)
    _print_summary(snap, top=args.top)
    if args.save:
        save_snapshot(snap, Path(args.save))
        print(f"snapshot -> {args.save}")
    _write_outputs(snap, args, cfg)
    breach, why = _threshold_breach(snap, args.fail_on, args.max_critical)
    if breach:
        print(f"\n{color.red('threshold breached')}: {why}", file=sys.stderr)
        return EXIT_THRESHOLD
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    snap = load_snapshot(Path(args.from_snapshot)) if args.from_snapshot else None
    if snap is None:
        print("--from SNAPSHOT.json is required (or use `netmap lab --formats ...`)", file=sys.stderr)
        return EXIT_USAGE
    if args.reanalyze:
        analyze(cfg, snap)
    if args.compare_with:
        snap.drift = compare_snapshots(load_snapshot(Path(args.compare_with)), snap)
    _write_outputs(snap, argparse.Namespace(out=args.out, formats=args.formats, quiet=True), cfg)
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    old = load_snapshot(Path(args.old))
    new = load_snapshot(Path(args.new))
    drift = compare_snapshots(old, new)
    if args.format == "json":
        print(json.dumps(drift, indent=2, default=str))
    else:
        from .report.writer import _drift_markdown

        print(f"baseline {drift['old_snapshot']} ({drift['old_finished']}) -> {drift['new_snapshot']} ({drift['new_finished']})")
        print(_drift_markdown(drift))
    if args.fail_on and args.fail_on.lower() != "never":
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        want = order.get(args.fail_on.lower(), 4)
        bad = [f for f in drift["findings_appeared"] if order.get(f["severity"], 9) <= want]
        if bad:
            print(f"\n{len(bad)} new finding(s) at or above {args.fail_on}", file=sys.stderr)
            for f in bad[:15]:
                print(f"  {f['severity']:>8} {f['rule_id']:<12} {f['target']} {f['title']}", file=sys.stderr)
            return EXIT_THRESHOLD
        print(f"\nno new findings at or above {args.fail_on}")
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    if args.port:
        cfg.set("web.port", args.port)
    if args.host:
        cfg.set("web.host", args.host)
    if args.snapshot:
        cfg.set("web.snapshot", args.snapshot)
    if args.lab and not args.snapshot:
        print("no snapshot given: running a lab scan to serve", file=sys.stderr)
        result = pipeline_run(_with_lab(cfg), progress=_progress(args))
        path = Path(cfg.get("report.output_dir") or "out") / "served-lab.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        save_snapshot(result.snapshot, path)
        cfg.set("web.snapshot", str(path))
    from .web.server import serve_forever

    serve_forever(
        cfg,
        snapshot_path=cfg.get("web.snapshot"),
        host=args.host,
        port=args.port,
        allow_scan=not args.no_scan,
        verbose=args.verbose,
    )
    return EXIT_OK


def _with_lab(cfg: Config) -> Config:
    out = cfg.copy()
    out.set("scan.mode", "lab")
    return out


def cmd_rules(args: argparse.Namespace) -> int:
    from .risk.engine import DEFAULT_RULES, RiskEngine

    paths = [str(p) for p in (args.files or [])] or [DEFAULT_RULES]
    engine = RiskEngine(rules_files=paths)
    if args.action == "validate":
        problems = list(engine.audit.get("errors") or [])
        catalogue = RiskEngine(rules_files=paths)
        for rule in catalogue.rules:
            problems.extend(f"{rule.id}: {p}" for p in rule.validate())
        if problems:
            print(f"{len(problems)} problem(s) in {len(catalogue.rules)} rules:", file=sys.stderr)
            for p in problems:
                print("  ", p, file=sys.stderr)
            return EXIT_USAGE
        print(f"{len(catalogue.rules)} rules validated, no problems")
        return EXIT_OK
    if args.action == "show":
        for rule in engine.rules:
            if rule.id == args.show or rule.raw.get("title", "").lower().startswith(str(args.show).lower()):
                print(json.dumps(rule.raw, indent=2, default=str))
                return EXIT_OK
        print(f"no rule {args.show}", file=sys.stderr)
        return EXIT_USAGE
    rows = [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "family": r.family,
            "scope": r.scope,
            "version": r.raw.get("version", "1"),
            "active": "yes" if r.active else "no",
            "tags": " ".join(r.raw.get("tags") or []),
        }
        for r in engine.rules
    ]
    if args.format == "json":
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    if args.format == "csv":
        import csv as _csv

        writer = _csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        return EXIT_OK
    width = max(len(r["id"]) for r in rows)
    for row in rows:
        flag = "" if row["active"] else "  (inactive)"
        print(f"  {row['id']:<{width}}  {sev(row['severity']):<26} {row['scope']:<8} {row['title']}{flag}")
    print(f"\n{len(rows)} rules from {', '.join(paths)}")
    return EXIT_OK


def cmd_ci(args: argparse.Namespace) -> int:
    """Gate a change: analyse, emit machine-readable output, exit non-zero on regressions."""
    if not getattr(args, "formats", None):
        args.formats = "sarif,txt"
    if not getattr(args, "fail_on", None):
        args.fail_on = "critical"
    cfg = _cfg(args)
    if args.lab:
        cfg.set("scan.mode", "lab")
    if args.from_snapshot:
        snap = load_snapshot(Path(args.from_snapshot))
        analyze(cfg, snap)
    else:
        snap = pipeline_run(cfg, progress=_progress(args)).snapshot
    out_dir = Path(args.out or cfg.get("report.output_dir") or "out")
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.save:
        save_snapshot(snap, out_dir / "ci-snapshot.json")
    from .report.writer import write_report

    formats = [f.strip() for f in (args.formats or "sarif,txt").split(",") if f.strip()]
    write_report(snap, out_dir, formats=formats, title=cfg.get("report.title"), redact=bool(cfg.get("report.redact", True)))
    if args.baseline:
        drift = compare_snapshots(load_snapshot(Path(args.baseline)), snap)
        (out_dir / "ci-drift.json").write_text(json.dumps(drift, indent=2, default=str) + "\n", encoding="utf-8")
        if args.no_new_findings and drift["findings_appeared"]:
            print(f"{len(drift['findings_appeared'])} new finding(s) versus baseline", file=sys.stderr)
            for f in drift["findings_appeared"][:10]:
                print(f"  {f['severity']:>8} {f['rule_id']} {f['target']} {f['title']}", file=sys.stderr)
            return EXIT_THRESHOLD
    from .report.writer import to_txt

    print(to_txt(snap))
    breach, why = _threshold_breach(snap, args.fail_on, args.max_critical)
    print(f"threshold check ({args.fail_on}, max_critical={args.max_critical}): {why}")
    if breach:
        return EXIT_THRESHOLD
    return EXIT_OK


def cmd_scan_report_preview(args: argparse.Namespace) -> int:  # pragma: no cover - convenience
    return cmd_report(args)


# ---------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netmap",
        description="Auto-discovery, topology mapping and risk analysis for enterprise networks.",
        epilog="start here:  netmap lab   (no network required)   then   netmap serve --lab",
    )
    parser.add_argument("--version", action="version", version=f"netmap {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="noisy stage logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    parser.add_argument("--top", type=int, default=10, help="findings to list in the console summary")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", help="YAML/JSON config file")
    common.add_argument("--set", action="append", metavar="KEY=VALUE", help="override a config key (repeatable)")
    common.add_argument("-o", "--out", help="output directory (default: report.output_dir)")
    common.add_argument("--formats", help="comma list of " + ",".join(REPORT_FORMATS))
    common.add_argument("--rules", action="append", help="extra/override rule catalogue file (repeatable)")
    common.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["never"], help="exit 1 when a finding is at or above this severity")
    common.add_argument("--max-critical", type=int, help="exit 1 when more than N critical findings are open")
    common.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    common.add_argument("-v", "--verbose", action="store_true", help="noisy stage logging")
    common.add_argument("--top", type=int, default=10, help="findings to list in the console summary")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("init", help="write a documented starter config")
    p.add_argument("-o", "--out", default="configs/netmap.yaml", help="path for the new config file")
    p.add_argument("--force", action="store_true", help="overwrite an existing file")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("lab", parents=[common], help="run the whole pipeline on a synthetic network")
    p.add_argument("--size", choices=["small", "medium", "large"], default="medium")
    p.add_argument("--seed", type=int, default=7, help="deterministic generator seed")
    p.add_argument("--no-risks", action="store_true", help="generate a boring, clean network instead")
    p.add_argument("--snapshot-out", help="where to save the JSON snapshot")
    p.add_argument("--compare-with", help="diff the result against a baseline snapshot file")
    p.set_defaults(func=cmd_lab)

    p = sub.add_parser("discover", parents=[common], help="scan live networks (authorization required)")
    p.add_argument("targets", nargs="*", help="CIDRs, ranges (10.0.0.1-20), hostnames or IPs")
    p.add_argument("--mode", choices=["live", "lab", "import"], help="override scan.mode")
    p.add_argument("--import-file", help="snapshot JSON to analyse instead of scanning")
    p.add_argument("--ports", help='TCP ports: "top", "1-1024", "22,80,443"')
    p.add_argument("--udp-ports", help="UDP ports (same syntax)")
    p.add_argument("--exclude", action="append", help="addresses to skip (repeatable)")
    p.add_argument("--max-hosts", type=int, help="hard cap on hosts per run")
    p.add_argument("--rate", type=float, help="packets/second limiter")
    p.add_argument("--no-snmp", action="store_true", help="skip SNMP enumeration")
    p.add_argument("--no-tls", action="store_true", help="skip TLS handshakes / certificate inspection")
    p.add_argument("--snapshot-out", help="explicit snapshot filename")
    p.add_argument("--baseline", help="previous snapshot to diff against")
    p.add_argument("--dry-run", action="store_true", help="show what would be scanned, then exit")
    p.add_argument("--confirm-authorized", action="store_true", help="assert you hold written permission to scan the targets")
    p.add_argument("--statement", help="authorization text to record in the snapshot (who/what/when)")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("analyze", parents=[common], help="re-run topology + risk on a saved snapshot")
    p.add_argument("--from", dest="from_snapshot", required=True, metavar="SNAP.json")
    p.add_argument("--save", help="write the analysed snapshot back out")
    p.add_argument("--disable", action="append", help="rule id to skip (repeatable)")
    p.add_argument("--only", action="append", help="run only these rule ids/families (repeatable)")
    p.add_argument("--min-severity", choices=SEVERITY_ORDER, help="ignore findings below this severity")
    p.add_argument(
        "--exception",
        action="append",
        metavar="JSON",
        help='accept/suppress a finding, e.g. \'{"rule":"NM-PLN-001","target":"10.0.2.1","status":"accepted","reason":"legacy gear"}\'',
    )
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("report", parents=[common], help="render report formats from a snapshot")
    p.add_argument("--from", dest="from_snapshot", required=True, metavar="SNAP.json")
    p.add_argument("--reanalyze", action="store_true", help="re-run risk before rendering")
    p.add_argument("--compare-with", help="include a drift section against a baseline snapshot")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("compare", parents=[common], help="diff two snapshots (change review)")
    p.add_argument("old", help="baseline snapshot")
    p.add_argument("new", help="current snapshot")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("serve", parents=[common], help="dashboard + JSON API on http.server")
    p.add_argument("--host", help="bind address (default 0.0.0.0)")
    p.add_argument("--port", type=int, help="bind port (default 8080)")
    p.add_argument("--snapshot", help="existing snapshot JSON to serve")
    p.add_argument("--lab", action="store_true", help="generate a lab snapshot first")
    p.add_argument("--no-scan", action="store_true", help="disable the in-UI scan trigger (read-only)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("rules", parents=[common], help="list, show or validate the risk catalogue")
    p.add_argument("action", nargs="?", choices=["list", "show", "validate"], default="list")
    p.add_argument("show", nargs="?", help="rule id or title prefix for `show`")
    p.add_argument("--files", action="append", help="catalogue file(s) to load instead of the built-in one")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("ci", parents=[common], help="fail a pipeline on new/at-risk findings")
    p.add_argument("--from", dest="from_snapshot", metavar="SNAP.json", help="analyse a saved snapshot instead of scanning")
    p.add_argument("--lab", action="store_true", help="use the synthetic network (no scanning)")
    p.add_argument("--baseline", help="previous snapshot; combined with --no-new-findings")
    p.add_argument("--no-new-findings", action="store_true", help="fail when any finding appeared versus the baseline")
    p.add_argument("--save", action="store_true", help="persist the analysed snapshot as out/ci-snapshot.json")
    p.set_defaults(func=cmd_ci)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130
    except FileNotFoundError as exc:
        print(f"file not found: {exc.filename or exc}", file=sys.stderr)
        return EXIT_USAGE
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level: show the reason, keep the trace for -v
        if getattr(args, "verbose", False):
            raise
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_USAGE


__all__ = ["build_parser", "main"]

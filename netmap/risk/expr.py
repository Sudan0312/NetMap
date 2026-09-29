"""Safe predicate language for risk rules.

Rules are data (YAML/JSON), never code. This evaluator understands a
JSON-Logic-shaped tree with a handful of network-specific operators. There is
no ``eval``/``exec`` anywhere: a malformed rule is a validation error, not an
arbitrary-code risk, which is what lets operators edit rules in production.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from ..util import days_until, is_ip, parse_version, version_lt


class RuleError(ValueError):
    """A rule could not be compiled or evaluated."""


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in ("", "false", "no", "0", "none", "null")
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def _num(value: Any, default: float = 0.0) -> float:
    try:
        if isinstance(value, bool):
            return float(value)
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"-?\d+", text):
            return int(text)
        if re.fullmatch(r"-?\d*\.\d+", text):
            return float(text)
    return value


def resolve_path(facts: dict, path: str) -> Any:
    """Dotted lookup through dicts/objects; ``None`` when any hop is missing."""
    if not path:
        return None
    cur: Any = facts
    for part in str(path).split("."):
        if part == "":
            continue
        if isinstance(cur, dict):
            if part in cur:
                cur = cur[part]
                continue
            cur = None
            continue
        if isinstance(cur, (list, tuple)):
            if part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
                continue
            # "services.port" over a list -> projected list
            cur = [getattr(x, part, None) if not isinstance(x, dict) else x.get(part) for x in cur]
            continue
        cur = getattr(cur, part, None)
    return cur


# ---------------------------------------------------------------------------
# operator implementations
# ---------------------------------------------------------------------------

Ops = dict[str, Callable[[Any, dict], Any]]
ops: Ops = {}


def op(name: str, *, variadic: bool = False, arity: int | None = None):
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        fn.variadic = variadic  # type: ignore[attr-defined]
        fn.arity = arity  # type: ignore[attr-defined]
        ops[name] = fn
        return fn

    return deco


def _args(raw: Any, facts: dict) -> list:
    """Operator arguments: a YAML list is a list of arguments, anything else is
    a single argument. Lists that are *values* (e.g. the haystack of `in`) must
    be written as ``{literal: [...]}`` so they are not mistaken for arguments."""
    if isinstance(raw, list):
        return [evaluate(item, facts) for item in raw]
    return [evaluate(raw, facts)]


@op("and", variadic=True)
def _and(args: list, facts: dict):
    for item in args:
        value = evaluate(item, facts)
        if not _truthy(value):
            return False
    return True


@op("or", variadic=True)
def _or(args: list, facts: dict):
    for item in args:
        if _truthy(evaluate(item, facts)):
            return True
    return False


@op("not", arity=1)
def _not(args: list, facts: dict):
    return not _truthy(args[0])


@op("nand", variadic=True)
def _nand(args: list, facts: dict):
    return not _truthy(_and(args, facts))


@op("if")
def _if(args: list, facts: dict):
    for cond, then in zip(args[0::2], args[1::2]):
        if _truthy(evaluate(cond, facts) if not isinstance(cond, dict) else evaluate(cond, facts)):
            return evaluate(then, facts)
    rest = args[len(args) - (1 if len(args) % 2 else 0) :]
    return evaluate(rest[0], facts) if rest else False


@op("==", arity=2)
def _eq(args: list, facts: dict):
    a, b = _coerce(args[0]), _coerce(args[1])
    if isinstance(a, (int, float)) and isinstance(b, str):
        b = _coerce(b)
    if isinstance(b, (int, float)) and isinstance(a, str):
        a = _coerce(a)
    if isinstance(a, str) and isinstance(b, str):
        return a.strip().lower() == b.strip().lower()
    return a == b


@op("!=", arity=2)
def _ne(args: list, facts: dict):
    return not _eq(args, facts)


def _cmp(args: list, fn) -> bool:
    a, b = _coerce(args[0]), _coerce(args[1])
    if isinstance(a, str) or isinstance(b, str):
        na, nb = _coerce(a), _coerce(b)
        if isinstance(na, (int, float)) and isinstance(nb, (int, float)):
            a, b = na, nb
        else:
            return bool(fn(str(a), str(b)))
    try:
        return bool(fn(a, b))
    except TypeError:
        return False


@op(">", arity=2)
def _gt(args, facts):
    return _cmp(args, lambda a, b: a > b)


@op(">=", arity=2)
def _gte(args, facts):
    return _cmp(args, lambda a, b: a >= b)


@op("<", arity=2)
def _lt(args, facts):
    return _cmp(args, lambda a, b: a < b)


@op("<=", arity=2)
def _lte(args, facts):
    return _cmp(args, lambda a, b: a <= b)


@op("in", arity=2)
def _in(args, facts):
    needle = _coerce(args[0])
    haystack = args[1] or []
    if isinstance(haystack, str):
        return str(needle).lower() in haystack.lower()
    try:
        return any(_eq([needle, item], facts) for item in haystack)
    except TypeError:
        return False


@op("not_in", arity=2)
def _not_in(args, facts):
    return not _in(args, facts)


@op("any_in", arity=2)
def _any_in(args, facts):
    """True when any element of the first list appears in the second."""
    left = args[0] or []
    right = args[1] or []
    if isinstance(left, str):
        left = [left]
    if isinstance(right, str):
        right = [right]
    left_norm = {str(x).strip().lower() for x in left}
    right_norm = {str(x).strip().lower() for x in right}
    return bool(left_norm & right_norm)


@op("contains", arity=2)
def _contains(args, facts):
    haystack, needle = args[0], args[1]
    if haystack is None:
        return False
    if isinstance(haystack, (list, tuple, set)):
        return any(_eq([needle, item], facts) for item in haystack)
    if isinstance(haystack, dict):
        return _coerce(needle) in [_coerce(k) for k in haystack] or str(needle) in haystack
    return str(needle).lower() in str(haystack).lower()


@op("regex", arity=2)
def _regex(args, facts):
    text, pattern = args[0], args[1]
    if text is None or not pattern:
        return False
    if isinstance(text, (list, tuple)):
        text = " ".join(str(t) for t in text)
    flags = re.I if len(args) > 2 and args[2] else re.I
    return bool(re.search(str(pattern), str(text), flags))


@op("count")
def _count(args, facts):
    value = args[0]
    if value is None:
        return 0
    if isinstance(value, (list, tuple, set, dict, str)):
        return len(value)
    return 1 if _truthy(value) else 0


@op("sum")
def _sum(args, facts):
    value = args[0] or []
    if isinstance(value, dict):
        value = list(value.values())
    try:
        return round(sum(_num(x) for x in value), 4)
    except TypeError:
        return 0


@op("max_of")
def _max_of(args, facts):
    value = args[0] or []
    nums = [_num(x) for x in value if x is not None]
    return max(nums) if nums else 0


@op("path", arity=1)
def _path(args, facts):
    return resolve_path(facts, args[0] if isinstance(args, list) else args)


@op("literal")
def _literal(args, facts):
    return args[0] if isinstance(args, list) else args


@op("lower")
def _lower(args, facts):
    return str(args[0] or "").lower()


@op("join")
def _join(args, facts):
    sep = str(args[1]) if len(args) > 1 else ", "
    value = args[0] or []
    if isinstance(value, (list, tuple, set)):
        return sep.join(str(v) for v in value)
    return str(value)


@op("coalesce")
def _coalesce(args, facts):
    for item in args:
        if item not in (None, "", [], {}):
            return item
    return None


@op("true")
def _true(args, facts):
    return True


@op("false")
def _false(args, facts):
    return False


# -- network-domain operators ------------------------------------------------


def _services(facts: dict) -> list[dict]:
    return list((facts.get("device") or {}).get("services") or [])


def _open_services(facts: dict) -> list[dict]:
    return [s for s in _services(facts) if str(s.get("state", "")).startswith("open")]


@op("port_open")
def _port_open(args, facts):
    want = args[0]
    ports = {int(p) for p in (want if isinstance(want, (list, tuple)) else [want])}
    proto = args[1] if len(args) > 1 else None
    for svc in _open_services(facts):
        if _num(svc.get("port")) in ports and (proto is None or svc.get("protocol") == proto):
            return True
    return False


@op("service_matching")
def _service_matching(args, facts):
    """{service_matching: [{path: "service.name"}, "telnet"]} -> matching services.

    The path may be written relative to the service (``name``) or qualified
    (``service.name``); both resolve against the service record.
    """
    spec = args[0] if isinstance(args[0], dict) else {}
    needle = _coerce(args[1]) if len(args) > 1 else None
    out = []
    for svc in _open_services(facts):
        field = str(spec.get("path", "name")).split("service.")[-1]
        value = resolve_path(svc, field)
        if value is None:
            continue
        if needle is None:
            out.append(svc)
        elif isinstance(needle, (list, tuple)):
            if any(str(value).lower() == str(n).lower() for n in needle):
                out.append(svc)
        elif str(value).lower() == str(needle).lower():
            out.append(svc)
    return out


@op("open_port_list")
def _open_port_list(args, facts):
    proto = args[0] if args else None
    return sorted({int(_num(s.get("port"))) for s in _open_services(facts) if proto is None or s.get("protocol") == proto})


@op("tls_of")
def _tls_of(args, facts):
    """Best TLS state for the device: {version, cipher, cert_days_left, ...}."""
    want_port = _coerce(args[0]) if args else None
    best = None
    for svc in _open_services(facts):
        cfg = svc.get("config") or {}
        cert = svc.get("certificate") or {}
        if not cfg and not cert:
            continue
        if want_port is not None and _num(svc.get("port")) != _num(want_port):
            continue
        item = {
            "port": svc.get("port"),
            "protocol": cfg.get("tls_version") or cert.get("protocol"),
            "cipher": cfg.get("tls_cipher"),
            "verified": cfg.get("tls_verified", False),
            "self_signed": bool(cfg.get("self_signed") or cert.get("self_signed")),
            "not_after": cert.get("not_after") or cfg.get("not_after"),
            "hostname_match": cert.get("hostname_match"),
            "key_bits": cfg.get("key_bits") or cert.get("key_bits"),
            "weak_protocol": bool(cfg.get("weak_protocol")),
            "weak_cipher": bool(cfg.get("weak_cipher")),
            "fingerprint": cfg.get("certificate_fingerprint_sha256"),
        }
        if best is None or str(item.get("protocol") or "") < str(best.get("protocol") or ""):
            best = item
    if not best:
        return {}
    left = days_until(best.get("not_after"))
    best["days_left"] = None if left is None else round(left, 1)
    return best


@op("eol_state")
def _eol_state(args, facts):
    dev = facts.get("device") or {}
    eol = dev.get("os_eol")
    if not eol:
        return {"known": False, "eol": None, "days": None}
    days = days_until(eol)
    return {"known": True, "eol": eol, "days": None if days is None else round(days, 1), "basis": dev.get("os_eol_basis")}


@op("days_until")
def _days_until(args, facts):
    value = args[0]
    days = days_until(value if isinstance(value, str) else None)
    return None if days is None else round(days, 1)


@op("version_lt")
def _version_lt_op(args, facts):
    return version_lt(args[0], args[1])


@op("has_tag")
def _has_tag(args, facts):
    dev = facts.get("device") or {}
    tags = {str(t).lower() for t in (dev.get("tags") or [])}
    needle = args[0]
    needles = {str(t).lower() for t in (needle if isinstance(needle, (list, tuple)) else [needle])}
    return bool(tags & needles)


@op("zone_trust")
def _zone_trust(args, facts):
    want = args[0] if args else None
    trust = (facts.get("zone") or {}).get("trust")
    if want is None:
        return trust
    return trust == want


@op("reachable_from")
def _reachable_from(args, facts):
    """Did the graph walk find a path from a zone with this trust into the device?"""
    want_trust = args[0] if args else "untrusted"
    blocked_by = set(args[1]) if len(args) > 1 and isinstance(args[1], (list, tuple)) else {"firewall", "proxy", "ips_ids"}
    hops = facts.get("reachability") or {}
    value = hops.get(want_trust)
    if isinstance(value, dict):
        return bool(value.get("reachable")) and not value.get("filtered", False)
    return _truthy(value)


@op("max_trust_distance")
def _max_trust_distance(args, facts):
    return _num((facts.get("device") or {}).get("max_trust_distance"))


@op("neighbour_missing")
def _neighbour_missing(args, facts):
    dev = facts.get("device") or {}
    missing = dev.get("dangling_neighbors") or []
    return bool(missing)


@op("process_absent")
def _process_absent(args, facts):
    dev = facts.get("device") or {}
    procs = [str(p).lower() for p in ((dev.get("config") or {}).get("running_processes") or [])]
    if not procs:
        return None  # unknown: rule must guard with `!= null`
    want = [str(w).lower() for w in (args[0] if isinstance(args[0], (list, tuple)) else [args[0]])]
    return not any(any(w in p for p in procs) for w in want)


@op("http_state")
def _http_state(args, facts):
    key = args[0] if args else "paths"
    dev = facts.get("device") or {}
    for svc in _open_services(facts):
        http = svc.get("http") or {}
        if not http:
            continue
        value = http.get(key)
        if value not in (None, {}, [], False):
            return value
    return None


@op("service_config")
def _service_config(args, facts):
    path = args[0]
    want_port = _coerce(args[1]) if len(args) > 1 else None
    for svc in _open_services(facts):
        if want_port is not None and _num(svc.get("port")) != want_port:
            continue
        value = resolve_path({"config": svc.get("config") or {}}, f"config.{path}")
        if value is not None:
            return value
    return None


@op("banner_regex")
def _banner_regex(args, facts):
    pattern = str(args[0])
    for svc in _services(facts):
        blob = " ".join(str(svc.get(k) or "") for k in ("banner", "product", "version", "extrainfo"))
        if re.search(pattern, blob, re.I | re.S):
            return {"port": svc.get("port"), "text": blob.strip()[:300]}
    return None


@op("any_service")
def _any_service(args, facts):
    """{any_service: <predicate>} - evaluate predicate with `service` bound."""
    pred = args[0]
    for svc in _open_services(facts):
        local = dict(facts)
        local["service"] = svc
        if _truthy(evaluate(pred, local)):
            return True
    return False


@op("all_services")
def _all_services(args, facts):
    pred = args[0]
    services = _open_services(facts)
    if not services:
        return False
    for svc in services:
        local = dict(facts)
        local["service"] = svc
        if not _truthy(evaluate(pred, local)):
            return False
    return True


@op("match_services")
def _match_services(args, facts):
    """Return the list of open services satisfying a predicate (for evidence)."""
    pred = args[0]
    hits = []
    for svc in _open_services(facts):
        local = dict(facts)
        local["service"] = svc
        if _truthy(evaluate(pred, local)):
            hits.append(svc)
    return hits


@op("now_iso")
def _now_iso(args, facts):
    from ..util import iso, now_utc

    return iso(now_utc())


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def evaluate(node: Any, facts: dict) -> Any:
    """Evaluate a rule node against a facts namespace."""
    if isinstance(node, dict):
        keys = list(node)
        # Handle the {path: ...}, {literal: ...} and {var: ...} sugar first so
        # they don't get routed through the generic op dispatch (which wraps
        # their value in _args and can mis-handle a list literal).
        if len(keys) == 1 and keys[0] in ("path", "var"):
            return resolve_path(facts, node[keys[0]])
        if len(keys) == 1 and keys[0] == "literal":
            return node["literal"]
        if len(keys) == 1 and keys[0] in ops:
            name = keys[0]
            return _apply(name, node[name], facts)
        if "op" in node:  # explicit form: {op: port_open, args: [23]}
            name = str(node["op"])
            if name not in ops:
                raise RuleError(f"unknown operator {name!r}")
            return _apply(name, node.get("args"), facts)
        return {k: evaluate(v, facts) for k, v in node.items()}
    if isinstance(node, list):
        return [evaluate(item, facts) for item in node]
    if isinstance(node, str) and node[:2] in ("$.",) :
        return resolve_path(facts, node[2:])
    return node


def _apply(name: str, raw: Any, facts: dict) -> Any:
    fn = ops[name]
    try:
        return fn(_args(raw, facts), facts)
    except RuleError:
        raise
    except (TypeError, KeyError, IndexError, ValueError, re.error) as exc:
        raise RuleError(f"operator {name!r} with {raw!r}: {exc}") from exc


def validate(node: Any, *, _path: str = "rule") -> list[str]:
    """Static check: every operator name must exist, arity must be sane."""
    problems: list[str] = []
    if isinstance(node, dict):
        keys = list(node)
        if len(keys) == 1 and keys[0] in ops:
            value = node[keys[0]]
            arity = getattr(ops[keys[0]], "arity", None)
            if arity is not None:
                count = len(value) if isinstance(value, list) else 1
                if count != arity:
                    problems.append(f"{_path}: operator {keys[0]} expects {arity} argument(s), got {count}")
            problems.extend(validate(value, _path=f"{_path}.{keys[0]}"))
        elif len(keys) == 1 and keys[0] == "path":
            if not isinstance(node["path"], str):
                problems.append(f"{_path}: path must be a string")
        else:
            for key, value in node.items():
                if key in ("evidence", "description", "remediation", "refs", "title"):
                    continue
                problems.extend(validate(value, _path=f"{_path}.{key}"))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            problems.extend(validate(item, _path=f"{_path}[{i}]"))
    return problems


def compile_rule(predicate: Any) -> Callable[[dict], Any]:
    """Bind a predicate for repeated evaluation."""

    def _run(facts: dict) -> Any:
        return evaluate(predicate, facts)

    _run.__doc__ = f"compiled predicate: {str(predicate)[:200]}"
    return _run


__all__ = ["evaluate", "validate", "compile_rule", "resolve_path", "ops", "RuleError"]

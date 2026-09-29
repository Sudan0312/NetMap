"""Small shared helpers: version parsing, CIDR math, time, files, terminal.

Everything here is stdlib-only so the core package has no hard dependencies.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Iterable

# --------------------------------------------------------------------------
# time
# --------------------------------------------------------------------------


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: float | datetime | None) -> str | None:
    """Render an epoch/aware-datetime as ISO-8601 UTC with second precision."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        ts = datetime.fromtimestamp(ts, tz=timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    txt = value.strip()
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def days_until(value: str | datetime | None, *, at: datetime | None = None) -> float | None:
    """Positive = still in the future, negative = already passed."""
    dt = value if isinstance(value, datetime) else parse_iso(value) if isinstance(value, str) else None
    if dt is None:
        return None
    ref = at or now_utc()
    return (dt - ref).total_seconds() / 86400.0


def human_age(seconds: float | None) -> str:
    """`41d 3h` style duration, used for uptime and freshness display."""
    if seconds is None:
        return "unknown"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    parts = []
    for size, label in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds >= size:
            parts.append(f"{seconds // size}{label}")
            seconds %= size
    return " ".join(parts) or "0m"


# --------------------------------------------------------------------------
# network primitives
# --------------------------------------------------------------------------


def is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def norm_ip(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    # `10.0.0.007` is common CLI/spreadsheet noise that ipaddress refuses to
    # parse (leading zeros are ambiguous). Normalise it instead of passing the
    # ambiguous text on as a key.
    if value.count(".") == 3:
        parts = value.split(".")
        if all(p.isdigit() and int(p) <= 255 for p in parts):
            return ".".join(str(int(p)) for p in parts)
    return value or None


def _range_bounds(text: str) -> tuple[int, int] | None:
    """Numeric bounds for `10.0.0.5-9` / `10.0.0.5-10.0.0.9`, else None."""
    if "-" not in text or "/" in text:
        return None
    lo_s, hi_s = (p.strip() for p in text.split("-", 1))
    if re.fullmatch(r"\d+", hi_s):  # short high octet: 10.0.0.5-9
        if "." not in lo_s:
            return None
        hi_s = f"{lo_s.rsplit('.', 1)[0]}.{hi_s}"
    try:
        lo, hi = int(ipaddress.ip_address(lo_s)), int(ipaddress.ip_address(hi_s))
    except ValueError:
        return None
    return (lo, hi) if lo <= hi else (hi, lo)


def cidr_contains(cidrs: Iterable[str], ip: str) -> bool:
    """True when `ip` falls in any entry of `cidrs`.

    Accepts CIDRs, single addresses and the same `a.b.c.d-e` / `a.b.c.5-9`
    ranges that target parsing accepts, so an exclusion written as a range
    behaves like the target it was copied from instead of silently doing
    nothing.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for raw in cidrs or []:
        raw = str(raw).strip()
        if not raw:
            continue
        bounds = _range_bounds(raw)
        if bounds is not None:
            if addr.version == 4 and bounds[0] <= int(addr) <= bounds[1]:
                return True
            continue
        try:
            net = ipaddress.ip_network(raw if "/" in raw else f"{raw}/32", strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def ip_in_private_ranges(ip: str) -> bool:
    """RFC1918 + CGNAT + link-local. Used as a hard safety rail for live scans."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr in ipaddress.ip_network("100.64.0.0/10")
    )


def expand_cidr(cidr: str, *, exclude: Iterable[str] = ()) -> list[str]:
    """Host addresses for a CIDR/network range, skipping network/broadcast (v4)."""
    text = cidr.strip()
    out: list[str] = []
    if "-" in text and "/" not in text:
        bounds = _range_bounds(text)
        if bounds is None:
            return []
        lo, hi = bounds
        for n in range(lo, min(hi, lo + MAX_HOSTS) + 1):
            out.append(str(ipaddress.ip_address(n)))
    else:
        try:
            net = ipaddress.ip_network(text if "/" in text else f"{text}/32", strict=False)
        except ValueError:
            return []
        if net.version == 4 and net.prefixlen < 31:
            hosts = list(net.hosts())[: MAX_HOSTS + 1]
        else:
            hosts = list(net)[: MAX_HOSTS + 1]
        out = [str(h) for h in hosts]
    return [ip for ip in out if not cidr_contains(exclude, ip)]


def network_of(ip: str, prefix: int = 24) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.version == 6:
        return f"{addr.exploded.split(':')[0]}::/{max(prefix, 48)}"
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(net)


def sorted_ips(ips: Iterable[str]) -> list[str]:
    items = [i for i in ips if i]

    def key(ip: str):
        try:
            return (0, int(ipaddress.ip_address(ip)))
        except ValueError:
            return (1, ip)

    return sorted(items, key=key)


def parse_mac(raw: Any) -> str | None:
    """Normalise MAC from bytes, 'aa:bb:..', 'AABB.ccdd.eeff' (Cisco) or 'aabbccddeeff'."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return ":".join(f"{b:02x}" for b in bytes(raw)) or None
    txt = re.sub(r"[^0-9a-fA-F]", "", str(raw))
    if len(txt) != 12:
        return None
    low = txt.lower()
    return ":".join(low[i : i + 2] for i in range(0, 12, 2))


def mac_oui(mac: str | None) -> str | None:
    if not mac:
        return None
    return mac.upper().replace(":", "").replace("-", "").replace(".", "")[:6] or None


# --------------------------------------------------------------------------
# versions
# --------------------------------------------------------------------------

_VER_SPLIT = re.compile(r"[^\d.]+|\.", flags=re.S)


def parse_version(text: Any) -> tuple[int, ...]:
    """Best-effort numeric version tuple.

    Handles ``12.2(55)SE12``, ``6.0.9.102``, ``15.1X49-D140.2`` and bare ints.
    Trailing alphabetic suffixes are dropped; only the leading numeric
    components matter for range comparisons.
    """
    if text is None:
        return ()
    if isinstance(text, (int, float)):
        text = str(text)
    cleaned = re.sub(r"\((\d+)\)", r".\1", str(text))
    cleaned = re.sub(r"[vV]", " ", cleaned)
    nums = re.findall(r"\d+", cleaned)
    return tuple(int(n) for n in nums[:5])


def version_lt(a: Any, b: Any) -> bool:
    va, vb = parse_version(a), parse_version(b)
    if not va or not vb:
        return False
    size = max(len(va), len(vb))
    va += (0,) * (size - len(va))
    vb += (0,) * (size - len(vb))
    return va < vb


def version_le(a: Any, b: Any) -> bool:
    va, vb = parse_version(a), parse_version(b)
    if not va or not vb:
        return False
    return version_lt(a, b) or va == vb


def version_ge(a: Any, b: Any) -> bool:
    return not version_lt(a, b)


def version_between(version: Any, lo: Any | None, hi: Any | None) -> bool:
    ok = True
    if lo is not None:
        ok = ok and version_ge(version, lo)
    if hi is not None:
        ok = ok and version_lt(version, hi)
    return bool(ok)


# --------------------------------------------------------------------------
# files / serialisation
# --------------------------------------------------------------------------


MAX_HOSTS = 4096  # per-range ceiling; larger targets must be split deliberately


def atomic_write(path: str | os.PathLike, data: str | bytes) -> str:
    """Write via temp file + rename so a crash never leaves a half report."""
    p = os.fspath(path)
    folder = os.path.dirname(os.path.abspath(p)) or "."
    os.makedirs(folder, exist_ok=True)
    tmp = None
    try:
        tmp_fd, tmp = tempfile.mkstemp(prefix=".netmap-", dir=folder)
        with os.fdopen(tmp_fd, "wb" if isinstance(data, bytes) else "w", encoding=None if isinstance(data, bytes) else "utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        shutil.move(tmp, p)
    finally:
        if tmp and os.path.exists(tmp):
            with contextlib.suppress(OSError):
                os.remove(tmp)
    return p


def write_json(path: str | os.PathLike, obj: Any, *, indent: int = 2, compact: bool = False) -> str:
    text = json.dumps(obj, indent=None if compact else indent, sort_keys=False, default=_json_default)
    return atomic_write(path, text + "\n")


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return iso(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", "replace")
        except Exception:  # pragma: no cover
            return obj.hex()
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dataclass_fields__"):
        return dataclass_to_dict(obj)
    return str(obj)


def dataclass_to_dict(obj: Any) -> dict:
    from dataclasses import fields, is_dataclass

    if is_dataclass(obj):
        return {f.name: dataclass_to_dict(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, dict):
        return {k: dataclass_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [dataclass_to_dict(v) for v in obj]
    if isinstance(obj, datetime):
        return iso(obj)
    if isinstance(obj, set):
        return sorted(obj)
    return obj



def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")


def clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def retry(fn, *, attempts: int = 2, delay: float = 0.05):
    last = None
    for _ in range(max(1, attempts)):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(delay)
    raise last  # type: ignore[misc]


# --------------------------------------------------------------------------
# terminal rendering
# --------------------------------------------------------------------------


def sys_stdout_tty() -> bool:
    try:
        import sys

        return bool(sys.stdout and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None)
    except Exception:  # pragma: no cover
        return False


class Color:
    enabled = sys_stdout_tty()

    @staticmethod
    def _wrap(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if Color.enabled else text

    def __getattr__(self, name: str):
        codes = {
            "red": "31",
            "green": "32",
            "yellow": "33",
            "blue": "34",
            "magenta": "35",
            "cyan": "36",
            "bold": "1",
            "dim": "2",
        }

        def fn(text: Any, _c=codes.get(name, "")) -> str:
            return Color._wrap(_c, str(text)) if _c else str(text)

        return fn


color = Color()

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHT = {"critical": 9.5, "high": 7.0, "medium": 4.5, "low": 2.0, "info": 0.5}
SEVERITY_COLOR = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def sev(severity: str) -> str:
    getattr_ok = severity if severity in SEVERITY_ORDER else "info"
    return getattr(color, SEVERITY_COLOR[getattr_ok])(severity.upper())


def table(headers: list[str], rows: list[list[Any]], *, align: str = "left") -> str:
    rows = [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], max((len(p) for p in cell.split("\n")), default=0))
    out = ["  ".join(h.ljust(widths[i]) if align == "left" else h.rjust(widths[i]) for i, h in enumerate(headers))]
    out.append("  ".join("-" * w for w in widths))
    for row in rows:
        out.append("  ".join((cell or "").ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(out)

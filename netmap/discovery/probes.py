"""Service, TLS and HTTP probing.

Everything here is read-only by construction: the only writes to a target are
protocol handshakes (ClientHello, STARTTLS, an unauthenticated ``HELP``/
``EHLO``, a GET). No exploitation payloads, no credential attempts.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any

from ..models import Certificate, Service
from ..ports import expected_encryption, port_category, port_name
from ..reference import References, get_references
from ..util import days_until

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_TOKENS = ("RC4", "DES", "NULL", "EXPORT", "MD5", "ANON", "3DES", "IDEA", "SEED")
SMALL_KEY_BITS = {"rsa": 2048, "dsa": 2048, "ec": 224}

# ports where a cleartext protocol can be upgraded before TLS
STARTTLS_COMMANDS: dict[int, bytes] = {
    25: b"EHLO netmap-probe\r\nQUIT\r\n",
    587: b"EHLO netmap-probe\r\nQUIT\r\n",
    465: b"",
    110: b"CAPA\r\nQUIT\r\n",
    143: b".CAPABILITY\r\n.QUIT\r\n",
    21: b"",
    389: b"\x30\x0c\x02\x01\x01\x63\x07\x0a\x01\x00\x04\x00\x02\x01\x00",  # LDAP bindRequest used only to learn StartTLS support
    1433: b"",
}
STARTTLS_REQUEST: dict[int, bytes] = {
    25: b"STARTTLS\r\n",
    587: b"STARTTLS\r\n",
    110: b"STLS\r\n",
    143: b". STARTTLS\r\n",
    21: b"AUTH TLS\r\n",
    389: b"\x30\x1d\x02\x01\x02\x77\x18\x80\x16\x31\x2e\x33\x2e\x36\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x31\x38\x37\x01\x00",
    674: b"STARTTLS\r\n",
}

@dataclass
class ProbeOutcome:
    service: Service
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"service": self.service.to_dict(), "detail": self.detail}


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


def classify_service(
    port: int,
    protocol: str,
    state: str,
    *,
    banner: bytes | str | None = None,
    refs: References | None = None,
    extra: dict | None = None,
) -> Service:
    """Turn a raw probe result into a fingerprinted Service."""
    refs = refs or get_references()
    if isinstance(banner, (bytes, bytearray)):
        text = bytes(banner).decode("utf-8", "replace")
    else:
        text = banner or ""
    name = port_name(port, protocol)
    category = port_category(port, protocol)
    svc = Service(port=int(port), protocol=protocol, state=state, name=name, banner=text[:2048] or None)
    hints = refs.apply_banners(int(port), text, protocol) if text else {}
    if hints:
        svc.name = str(hints.pop("name", None) or svc.name)
        svc.product = str(hints.pop("product", None) or "") or None
        svc.version = str(hints.pop("version", None) or "") or None
        svc.extrainfo = str(hints.pop("extrainfo", None) or "") or None
        enc = hints.pop("encryption", None)
        if enc:
            svc.encryption = str(enc)
        hints.pop("code", None)
        rules = hints.pop("_rules", None)
        if rules:
            svc.probe = ",".join(rules)
        for key, value in hints.items():
            svc.config.setdefault(key, value)
        svc.confidence = 0.9 if svc.product else 0.75
    else:
        svc.confidence = 0.6 if state.startswith("open") else 0.4
    if state in ("open|filtered", "filtered") and not text:
        svc.confidence = min(svc.confidence, 0.35)
    if not svc.encryption or svc.encryption == "unknown":
        svc.encryption = expected_encryption(int(port), protocol)
    if category in ("management", "remote", "database", "file") and svc.encryption == "none":
        svc.config.setdefault("cleartext_expected_tls", expected_encryption(int(port), protocol) != "none")
    if extra:
        for k, v in extra.items():
            if v is not None:
                setattr(svc, k, v) if hasattr(svc, k) else svc.config.setdefault(k, v)
    return svc


def service_summary(service: Service) -> str:
    """One-line product/version string for tables and tooltips."""
    blob = " ".join(part for part in (service.product, service.version, service.extrainfo) if part)
    if blob:
        return blob
    line = (service.banner or "").strip().splitlines()
    return line[0][:120] if line else (service.name or "")


# ---------------------------------------------------------------------------
# protocol-specific probes
# ---------------------------------------------------------------------------


async def grab_banner(host: str, port: int, *, timeout: float = 1.25, banner_bytes: int = 1024) -> bytes:
    """Connect, speak the small talk this port expects, read once."""
    payload = _greeter(port)
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=timeout)
        if payload:
            writer.write(payload)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(banner_bytes), timeout=timeout)
        return data or b""
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return b""
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass


def _greeter(port: int) -> bytes | None:
    if port in (25, 587, 465, 2525):
        return b"EHLO netmap-probe\r\n"
    if port in (110,):
        return b"CAPA\r\n"
    if port in (143,):
        return b".CAPABILITY\r\n"
    if port in (21, 990, 2121):
        return b""
    if port in (80, 8080, 8000, 81, 8008, 8888, 3000, 591, 8081):
        return b"HEAD / HTTP/1.0\r\nUser-Agent: netmap-probe\r\n\r\n"
    if port in (389,):
        return b"\x30" + b"\x0c\x02\x01\x01\x63\x07\x0a\x01\x00\x04\x00\x02\x01\x00"
    return None  # rely on whatever the service sends unsolicited


TLS_PROBE_TIMEOUT = 3.0


def tls_probe_sync(
    host: str,
    port: int = 443,
    *,
    sni: str | None = None,
    timeout: float = TLS_PROBE_TIMEOUT,
    verify: bool = False,
    starttls_on: bool = False,
) -> dict:
    """Synchronous TLS handshake. Returns negotiated protocol/cipher + cert facts.

    ``verify=False`` is deliberate: we must be able to read the certificate of a
    server whose chain we distrust -- that distrust is itself a finding.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # allow the whole range so we can *observe* legacy negotiation instead of failing
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    result: dict[str, Any] = {"port": int(port), "host": host}
    sock: socket.socket | None = None
    raw_ctx = ctx
    try:
        # MINIMUM_VERSION=TLSv1 keeps 1.0/1.1 reachable for detection; Python 3.12+
        # also honours the security-level knob above.
        if hasattr(ssl, "TLSVersion"):
            raw_ctx.minimum_version = ssl.TLSVersion.TLSv1
            raw_ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as plain:
            plain.settimeout(timeout)
            plain.connect((host, int(port)))
            if starttls_on and port in STARTTLS_REQUEST:
                plain.sendall(STARTTLS_COMMANDS.get(port, b""))
                plain.recv(4096)
                plain.sendall(STARTTLS_REQUEST[port])
                pre = plain.recv(4096)
                result["starttls_banner"] = pre.decode("utf-8", "replace")[:400]
                if not pre or (b"220" not in pre and b"+ OK" not in pre and b"TLS" not in pre.upper() and b"\x61" not in pre[:2]):
                    result["error"] = "starttls declined"
                    plain.close()
                    return result
            sock = raw_ctx.wrap_socket(plain, server_hostname=sni or (host if not _is_ip(host) else None))
        negotiated = sock.version() or "?"
        cipher = sock.cipher() or (None, None, None)
        der = sock.getpeercert(binary_form=True)
        result.update(
            {
                "protocol": negotiated,
                "cipher": cipher[0],
                "cipher_bits": cipher[2],
                "cipher_alg": cipher[1],
                "compression": getattr(sock, "compression", None),
                "alpn": getattr(sock, "selected_alpn_protocol", lambda: None)(),
                "verified": False,
            }
        )
        if der:
            from ..protocols.x509 import hostname_matches, parse_certificate

            cert = parse_certificate(der)
            cert["der_len"] = len(der)
            na = cert.get("not_after")
            if na is not None:
                left = (na - _utcnow()).total_seconds() / 86400
                cert["days_left"] = round(left, 1)
            names = cert.get("names") or cert.get("san") or []
            cert["hostname_match"] = hostname_matches(sni or host, names)
            result["certificate"] = {k: v for k, v in cert.items() if k not in {"der"}}
            result["certificate"]["serial"] = cert.get("serial")
            result["fingerprint_sha256"] = _sha256(der)
            try:
                ctx2 = ssl.create_default_context()
                ctx2.load_default_certs()
                with socket.socket(family, socket.SOCK_STREAM) as plain2:
                    plain2.settimeout(timeout)
                    plain2.connect((host, int(port)))
                    verified = ctx2.wrap_socket(plain2, server_hostname=sni or host)
                    result["verified"] = True
                    result["verified_version"] = verified.version()
                    verified.close()
            except (ssl.SSLError, OSError) as exc:
                result["verify_error"] = f"{type(exc).__name__}: {exc}"
        sock.close()
    except ssl.SSLError as exc:
        result["error"] = f"tls alert: {exc.reason or exc}"
        if "unsupported protocol" in str(exc).lower() or "no protocols" in str(exc).lower():
            result["error"] = "no tls on this port"
    except (ConnectionResetError, BrokenPipeError) as exc:
        result["error"] = f"reset: {exc}"
    except (OSError, asyncio.TimeoutError, TimeoutError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    result["weak_protocol"] = result.get("protocol") in WEAK_PROTOCOLS
    cipher_name = str(result.get("cipher") or "")
    result["weak_cipher"] = any(tok in cipher_name.upper() for tok in WEAK_CIPHER_TOKENS)
    bits = result.get("cipher_bits") or 0
    if bits and int(bits) < 112:
        result["weak_cipher"] = True
    key_bits = ((result.get("certificate") or {}).get("key_bits")) or 0
    if key_bits and int(key_bits) < SMALL_KEY_BITS["rsa"]:
        result["weak_key"] = True
    return result


def _is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def _utcnow():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


async def tls_probe(host: str, port: int = 443, **kw: Any) -> dict:
    """Async wrapper so TLS probes run inside the sweep event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: tls_probe_sync(host, port, **kw))


async def http_probe(
    host: str,
    port: int,
    *,
    tls: bool = False,
    timeout: float = 2.0,
    paths: list[dict] | None = None,
    max_paths: int = 12,
    check_headers: bool = True,
    max_size: int = 65536,
) -> dict:
    """Cheap, safe HTTP recon: banner headers, risky paths, response headers."""
    refs = get_references()
    probes = (paths if paths is not None else refs.http_probes)[:max_paths]
    reader = writer = None
    out: dict[str, Any] = {"port": int(port), "tls": bool(tls), "paths": {}, "error": None}
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port), ssl=ctx, server_hostname=None if _is_ip(host) else host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=timeout)
        for probe in probes:
            path = str(probe.get("path", "/"))
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netmap-probe/1.0\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"
            try:
                writer.write(request.encode())
                await writer.drain()
                raw = b""
                while b"\r\n\r\n" not in raw and len(raw) < 8192:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    if not chunk:
                        break
                    raw += chunk
                if not raw:
                    break
                head, _, body = raw.partition(b"\r\n\r\n")
                body_text = body.decode("latin-1", "replace")
                text = head.decode("latin-1", "replace")
                status_line = text.splitlines()[0] if text else ""
                parts = status_line.split(" ", 2)
                status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                headers = {}
                for line in text.splitlines()[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                out["paths"][path] = {
                    "status": status,
                    "server": headers.get("server"),
                    "location": headers.get("location"),
                    "content_type": headers.get("content-type"),
                    "risky_path": bool(probe.get("risky")),
                    "matched": bool(probe.get("expect")) and (str(probe.get("expect")) in body_text) if probe.get("expect") else None,
                }
                if not out.get("headers"):
                    out["headers"] = {k: v for k, v in headers.items() if k in {
                        "server", "x-powered-by", "x-frame-options", "strict-transport-security",
                        "content-security-policy", "x-content-type-options", "www-authenticate", "set-cookie",
                    }}
                    out["status"] = status
                    out["banner"] = text[:2048]
            except (asyncio.TimeoutError, OSError, ssl.SSLError):
                break
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
    headers = out.get("headers") or {}
    out["security_headers"] = {
        "hsts": bool(headers.get("strict-transport-security")),
        "frame_options": bool(headers.get("x-frame-options")),
        "csp": bool(headers.get("content-security-policy")),
        "nosniff": bool(headers.get("x-content-type-options")),
    }
    out["directory_listing"] = any(
        r.get("status") == 200 and str(r.get("content_type") or "").startswith("text/html") and "index of" in str(r.get("server") or "").lower()
        for r in out["paths"].values()
    )
    out["exposed_admin_paths"] = sorted({p for p, r in out["paths"].items() if r.get("status") in (200, 401, 403) and out["paths"][p].get("risky_path")})
    out["leaks"] = sorted({p for p, r in out["paths"].items() if r.get("matched")})
    return out


async def fingerprint_service(
    host: str,
    result: dict,
    *,
    refs: References | None = None,
    do_tls: bool = True,
    do_http: bool = True,
    timeout: float = 1.5,
) -> tuple[Service, dict]:
    """Full service picture: banner classification + TLS + HTTP surface."""
    refs = refs or get_references()
    port = int(result["port"])
    protocol = result.get("protocol", "tcp")
    svc = classify_service(port, protocol, result.get("state", "closed"), banner=result.get("banner"), refs=refs)
    detail: dict[str, Any] = {}
    if not svc.is_open:
        return svc, detail
    name = (svc.name or "").lower()
    looks_tlsy = (
        svc.encryption == "tls"
        or name in {"https", "imaps", "pop3s", "smtps", "ldaps", "amqps", "sips", "wsmans", "ftps"}
        or port in {443, 465, 563, 636, 990, 992, 993, 995, 30443, 4443, 5443, 5986, 8443, 8883, 9091, 6443, 15672, 3000}
    )
    looks_http = name in {"http", "http-alt", "http-proxy", "https", "https-alt", "web", "printer", "ipmi"} or port in {
        80, 81, 443, 3000, 5985, 5986, 8000, 8006, 8008, 8080, 8081, 8088, 8090, 8443, 8888, 9090, 9200, 9443, 15672, 16992, 5000,
        28017, 30718, 49152, 9093, 9100, 9060, 19000, 27017, 631, 515,
    }
    if looks_http:
        try:
            http = await http_probe(host, port, tls=svc.encryption == "tls" or looks_tlsy and name != "http", timeout=timeout)
            detail["http"] = http
            if http.get("headers", {}).get("server") and not svc.product:
                svc.product = http["headers"]["server"][:80]
            if http.get("banner") and not svc.banner:
                svc.banner = http["banner"][:1024]
        except Exception as exc:  # pragma: no cover - probes must never abort a scan
            detail["http_error"] = str(exc)
    if do_tls and (looks_tlsy or port in STARTTLS_COMMANDS):
        try:
            tls = await tls_probe(host, port, timeout=timeout + 1.5, sni=None, starttls_on=port in STARTTLS_COMMANDS and not looks_tlsy)
            if tls.get("protocol"):
                svc.encryption = "tls" if not tls.get("protocol", "").startswith("SSL") else "none"
                cert = tls.get("certificate") or {}
                svc.certificate = Certificate(
                    subject_cn=(cert.get("subject_cn") or [None])[0],
                    issuer_cn=(cert.get("issuer") or [None])[0],
                    self_signed=bool(cert.get("self_signed")),
                    not_before=_iso_or_none(cert.get("not_before")),
                    not_after=_iso_or_none(cert.get("not_after")),
                    days_left=cert.get("days_left"),
                    san=cert.get("san") or [],
                    san_source=cert.get("san_source"),
                    hostname_match=cert.get("hostname_match"),
                    protocol=tls.get("protocol"),
                    cipher=tls.get("cipher"),
                    bits=tls.get("cipher_bits"),
                    key_type=cert.get("key_alg"),
                    key_bits=cert.get("key_bits"),
                    weak_cipher=bool(tls.get("weak_cipher")),
                    error=tls.get("error"),
                )
                detail["tls"] = {k: v for k, v in tls.items() if k != "certificate"}
                svc.config.update(
                    {
                        "tls_version": tls.get("protocol"),
                        "tls_cipher": tls.get("cipher"),
                        "tls_verified": bool(tls.get("verified")),
                        "weak_protocol": bool(tls.get("weak_protocol")),
                        "weak_cipher": bool(tls.get("weak_cipher")),
                        "certificate_fingerprint_sha256": tls.get("fingerprint_sha256"),
                        "san": cert.get("san") or [],
                        "san_source": cert.get("san_source"),
                        "not_after": _iso_or_none(cert.get("not_after")),
                        "self_signed": bool(cert.get("self_signed")),
                        "key_bits": cert.get("key_bits"),
                    }
                )
        except Exception as exc:  # pragma: no cover
            detail["tls_error"] = str(exc)
    return svc, detail


def _iso_or_none(value: Any) -> str | None:
    if value is None:
        return None
    from datetime import datetime

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def cert_days_left(not_after: Any) -> float | None:
    return days_until(not_after if isinstance(not_after, str) else None)


__all__ = [
    "classify_service",
    "fingerprint_service",
    "grab_banner",
    "http_probe",
    "tls_probe",
    "tls_probe_sync",
    "ProbeOutcome",
    "WEAK_PROTOCOLS",
    "WEAK_CIPHER_TOKENS",
    "STARTTLS_COMMANDS",
]

"""Minimal X.509 (DER) reader for certificate facts NetMap needs.

Avoids a `cryptography` dependency by walking the ASN.1 structure of
RFC 5280 certificates directly, reusing the BER codec from the SNMP client.
Only the fields used by risk rules are extracted; nothing here validates
signatures -- chain trust is checked separately by the TLS probe.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..protocols.ber import BERError, Reader, decode_int, decode_oid

OIDs = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.9": "street",
    "0.9.2342.19200300.100.1.25": "DC",
    "2.5.4.5": "serialNumber",
    "2.5.29.17": "subjectAltName",
    "2.5.29.15": "keyUsage",
    "2.5.29.19": "basicConstraints",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.14": "subjectKeyIdentifier",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.3.101.112": "EdDSA",
}

KEY_SIZES = {  # common RSA moduli -> bits is measured, so this maps curve OIDs
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.2.840.10045.3.1.8": ("P-384", 384),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
}

# string-ish tags we accept for AttributeValue / names
TEXT_TAGS = {0x0C, 0x13, 0x16, 0x17, 0x1E, 0x14}


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _parse_names(raw: bytes) -> list[dict[str, str]]:
    """RDNSequence -> [{CN: ..., O: ...}] one dict per RDN."""
    out: list[dict[str, str]] = []
    rdns = Reader(raw)
    try:
        while not rdns.at_end():
            set_tag, set_body, _ = rdns.read_tlv()
            items = Reader(set_body)
            rdn: dict[str, str] = {}
            while not items.at_end():
                atlv_tag, atlv_body, _ = items.read_tlv()
                atlv = Reader(atlv_body)
                try:
                    oid_tag, oid_raw, _ = atlv.read_tlv()
                    val_tag, val_raw, _ = atlv.read_tlv()
                except BERError:
                    break
                oid = decode_oid(oid_raw)
                rdn[OIDs.get(oid, oid)] = _text(val_raw)
            if rdn:
                out.append(rdn)
    except BERError:
        pass
    return out


def names_to_string(names: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for rdn in names:
        parts.append("/".join(f"{k}={v}" for k, v in rdn.items()))
    return ", ".join(parts)


def common_names(names: list[dict[str, str]], key: str = "CN") -> list[str]:
    return [rdn[key] for rdn in names if key in rdn]


def _parse_time(tag: int, raw: bytes) -> datetime | None:
    text = raw.decode("ascii", "replace").strip()
    try:
        if tag == 0x17:  # UTCTime YYMMDDHHMMDDZ
            dt = datetime.strptime(text, "%y%m%d%H%M%SZ")
            if dt.year < 1970:
                dt = dt.replace(year=dt.year + 100)
        else:
            dt = datetime.strptime(text, "%Y%m%d%H%M%SZ")
    except ValueError:
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt.replace(tzinfo=timezone.utc)


def public_key_bits(spki_body: bytes) -> int | None:
    """Bit length of the key inside a SubjectPublicKeyInfo body.

    RSA -> modulus size. EC -> size taken from the curve OID.
    """
    try:
        reader = Reader(spki_body)
        _algo_tag, algo_body, _ = reader.read_tlv()
        key_tag, bits, _ = reader.read_tlv()
    except BERError:
        return None
    if key_tag != 0x03 or len(bits) < 2:
        return None
    payload = bits[1:]  # first octet counts unused trailing bits
    alg_reader = Reader(algo_body)
    try:
        _t, alg_raw, _l = alg_reader.read_tlv()
        alg = decode_oid(alg_raw)
    except (BERError, StopIteration):
        alg = ""
    if alg == "1.2.840.10045.2.1":  # id-ecPublicKey: size comes from the curve OID
        try:
            ptag, praw, _ = alg_reader.read_tlv()
        except BERError:
            return None
        if ptag != 0x06:
            return None
        try:
            return KEY_SIZES.get(decode_oid(praw), (None, None))[1]
        except BERError:
            return None
    try:
        tag, body, _ = Reader(payload).read_tlv()
        if tag == 0x30:  # RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
            tag, body, _ = Reader(body).read_tlv()
    except BERError:
        return None
    if tag != 0x02:
        return None
    value = decode_int(body)
    return value.bit_length() or None


def _alt_names(raw: bytes) -> list[str]:
    """GeneralNames from the subjectAltName extension.

    Accepts either the wrapped SEQUENCE or an already-unwrapped body.
    """
    body = raw
    try:
        tag, inner, _ = Reader(raw).read_tlv()
        if tag == 0x30:
            body = inner
    except BERError:
        pass
    out: list[str] = []
    items = Reader(body)
    while not items.at_end():
        try:
            tag, value, _ = items.read_tlv()
        except BERError:
            break
        if tag in (0x81, 0x82):  # rfc822Name, dNSName
            out.append(_text(value).lower())
        elif tag == 0x87:  # iPAddress
            if len(value) == 4:
                out.append(".".join(str(b) for b in value))
            elif len(value) == 16:
                groups = [f"{value[i]:02x}{value[i + 1]:02x}" for i in range(0, 16, 2)]
                out.append(":".join(groups))
        elif tag == 0x86:  # uniformResourceIdentifier
            out.append(_text(value))
    return out


def _extensions(raw: bytes) -> dict[str, object]:
    """Extensions ::= SEQUENCE OF Extension; `raw` is the [3] EXPLICIT body."""
    exts: dict[str, object] = {}
    try:
        tag, body, _ = Reader(raw).read_tlv()
        if tag != 0x30:
            body = raw
    except BERError:
        return exts
    items = Reader(body)
    while not items.at_end():
        try:
            _t, ext_body, _ = items.read_tlv()
            sub = Reader(ext_body)
            oid = decode_oid(sub.read_tlv()[1])
            tag2, val2, _ = sub.read_tlv()
            critical = False
            if tag2 == 0x01:  # BOOLEAN critical
                critical = bool(val2 and val2[-1])
                tag2, val2, _ = sub.read_tlv()
        except BERError:
            break
        extn_value = val2
        if tag2 == 0x04:  # extnValue OCTET STRING wraps the real DER
            try:
                extn_value = Reader(val2).read_tlv()[1]
            except BERError:
                pass
        name = OIDs.get(oid, oid)
        if name == "subjectAltName":
            exts[name] = _alt_names(extn_value)
        elif name == "basicConstraints":
            # BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER }
            # `extn_value` has already had its outer TLV stripped above, so the
            # SEQUENCE may or may not still be there depending on the encoder.
            ca, path_len = False, None
            try:
                tag3, body3, _ = Reader(extn_value).read_tlv()
                inner = body3 if tag3 == 0x30 else extn_value
                r = Reader(inner)
                if not r.at_end():
                    btag, bval, _ = r.read_tlv()
                    if btag == 0x01:
                        ca = bool(bval and bval[-1])
                        if not r.at_end():
                            ptag, pval, _ = r.read_tlv()
                            if ptag == 0x02:
                                path_len = decode_int(pval)
            except BERError:
                pass
            exts[name] = {"ca": ca, "path_len": path_len, "critical": critical}
        elif name == "keyUsage":
            usage_bits = {
                0: "digitalSignature",
                1: "nonRepudiation",
                2: "keyEncipherment",
                3: "dataEncipherment",
                4: "keyAgreement",
                5: "keyCertSign",
                6: "cRLSign",
                7: "encipherOnly",
                8: "decipherOnly",
            }
            names = []
            if len(extn_value) >= 2:
                # BIT STRING: the leading octet counts *unused trailing* bits, the
                # named bits are numbered from the most significant bit of the
                # content, so keyCertSign in a one-octet `05 a0` is bit 5.
                body = extn_value[1:]
                bits = int.from_bytes(body, "big")
                top = len(body) * 8 - 1
                for bit, label in sorted(usage_bits.items()):
                    if top - bit >= 0 and (bits >> (top - bit)) & 1:
                        names.append(label)
            exts[name] = {"raw": extn_value.hex(), "usage": names}
        else:
            exts[name] = {"hex": extn_value.hex(), "critical": critical}
    return exts


def parse_certificate(der: bytes) -> dict:
    """Extract the fields NetMap's rules use from a DER certificate."""
    top = Reader(der)
    try:
        _tag, cert_body, _ = top.read_tlv()  # Certificate ::= SEQUENCE
    except BERError as exc:
        return {"error": f"unreadable certificate: {exc}"}
    seq = Reader(cert_body)
    try:
        _tbs_tag, tbs, _ = seq.read_tlv()
        sig_algo_seq = seq.read_tlv()[1]
    except BERError as exc:
        return {"error": f"malformed TBSCertificate: {exc}"}
    info: dict[str, Any] = {}
    inner = Reader(tbs)
    try:
        first_tag, first_val, _ = inner.read_tlv()
        if first_tag == 0xA0:  # [0] EXPLICIT version
            try:
                info["version"] = decode_int(Reader(first_val).read_tlv()[1]) + 1
            except BERError:
                info["version"] = decode_int(first_val) + 1
            first_tag, first_val, _ = inner.read_tlv()
        else:
            info["version"] = 1
        info["serial"] = f"{decode_int(first_val):x}"
        _t, sig_body, _ = inner.read_tlv()  # signature AlgorithmIdentifier
        try:
            alg_oid = decode_oid(Reader(sig_body).read_tlv()[1])
            info["sig_alg"] = OIDs.get(alg_oid, alg_oid)
        except BERError:
            info["sig_alg"] = None
        _t, issuer, _ = inner.read_tlv()
        info["issuer_names"] = _parse_names(issuer)
        _t, validity, _ = inner.read_tlv()
        vread = Reader(validity)
        nb = vread.read_tlv()
        na = vread.read_tlv()
        info["not_before"] = _parse_time(nb[0], nb[1])
        info["not_after"] = _parse_time(na[0], na[1])
        _t, subject, _ = inner.read_tlv()
        info["subject_names"] = _parse_names(subject)
        _t, spki, _ = inner.read_tlv()
        info["key_bits"] = public_key_bits(spki)
        try:
            spki_read = Reader(spki)
            algo_tag, algo_body, _ = spki_read.read_tlv()
            algo_oid = decode_oid(Reader(algo_body).read_tlv()[1]) if algo_tag else ""
            info["key_alg"] = OIDs.get(algo_oid, algo_oid)
            if algo_oid in KEY_SIZES:
                info["key_alg"], bits = KEY_SIZES[algo_oid]
                info.setdefault("key_bits", bits)
        except (BERError, StopIteration):
            info["key_alg"] = None
        # optional fields: issuerUniqueID/subjectUniqueID/extensions ([3] EXPLICIT)
        while not inner.at_end():
            try:
                tag, value, _ = inner.read_tlv()
            except BERError:
                break
            if tag == 0xA3:
                info["extensions"] = _extensions(value)
    except BERError as exc:
        info.setdefault("error", f"truncated certificate: {exc}")
    info["issuer"] = common_names(info.get("issuer_names") or [])
    info["subject_cn"] = common_names(info.get("subject_names") or [])
    info["self_signed"] = bool(
        info.get("issuer_names") and info.get("subject_names") and info["issuer_names"] == info["subject_names"]
    )
    ext_san = (info.get("extensions") or {}).get("subjectAltName") or []
    info["san"] = [str(n).lower() for n in ext_san]
    # RFC 6125 retired the common-name fallback, but legacy network gear still
    # ships CN-only certificates. Keep the two apart: `san` is what the
    # extension actually says, `names` is what may be matched (SAN, else CN),
    # and `san_source` lets reports say "no SAN" instead of "SAN matches".
    info["san_source"] = "extension" if ext_san else ("common_name" if info["subject_cn"] else "none")
    info["names"] = info["san"] or [str(c).lower() for c in (info["subject_cn"] or [])]
    if info.get("sig_alg") is None and sig_algo_seq:
        try:
            info["sig_alg"] = OIDs.get(decode_oid(Reader(sig_algo_seq).read_tlv()[1]), "unknown")
        except (BERError, IndexError):
            pass
    return info


def hostname_matches(hostname: str | None, names: list[str]) -> bool | None:
    """True/False if we could tell, None if the cert has no usable names."""
    if not hostname or not names:
        return None
    target = hostname.strip().lower().rstrip(".")
    for pat in names:
        pat = str(pat).lower().strip()
        if pat == target:
            return True
        if pat.startswith("*."):
            suffix = pat[1:]  # *.corp.example.com -> .corp.example.com
            if target.endswith(suffix) and "." not in target[: -len(suffix)]:
                return True
    return False


__all__ = ["parse_certificate", "hostname_matches", "names_to_string", "common_names"]

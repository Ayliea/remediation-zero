# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Greenbone report XML in, a typed report out. Nothing else.

Two shapes are accepted: a GMP `<get_reports_response>` wrapping a `<report>`,
and a GSA XML export whose root is `<report>`. In both, the outer `<report>`
holds an inner `<report>` with the task, status, results and hosts.

The XML is untrusted. Before it reaches the parser it is refused if it is
larger than `max_bytes`, if it is not ASCII-compatible (NUL bytes betray
UTF-16/32, which would hide a DOCTYPE from the byte check), or if it contains
`<!DOCTYPE` or `<!ENTITY` in any case. Refusing DOCTYPEs removes entity
expansion and external entities outright, so the standard-library parser is
safe to use. A result with a value that does not parse is not guessed at: it is
listed in `rejected` with a reason and, when readable, the host ip. QoD and log-level filtering are not done
here; this module returns everything structurally valid.

`scan_end` is the report's own record of when the scan finished; it orders
reports and is never read as the current time.

Standard library only. No clock is read here.
"""

import ipaddress
import math
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

MAX_REPORT_BYTES = 64 * 1024 * 1024


#: Why a document was refused. A closed set, so it can be stored and shown.
REFUSAL_REASONS = ("too_large", "unsafe_xml", "malformed")


class ReportRefused(ValueError):
    """The document was refused before or during parsing; nothing was read from it.

    `reason` is one of `REFUSAL_REASONS`; unlike the message, it is safe to persist.
    """

    def __init__(self, message: str, *, reason: str = "malformed") -> None:
        super().__init__(message)
        self.reason = reason if reason in REFUSAL_REASONS else "malformed"


@dataclass(frozen=True)
class ScannedHost:
    ip: str
    asset_id: Optional[str]
    hostname: Optional[str]
    os_cpe: Optional[str]
    open_ports: tuple[str, ...]
    finished: bool


@dataclass(frozen=True)
class Result:
    result_id: str
    ip: str
    asset_id: Optional[str]
    port: str
    protocol: Optional[str]
    nvt_oid: str
    nvt_name: str
    severity: float
    qod: int
    cve_ids: tuple[str, ...]
    description: str
    solution: str
    summary: str


@dataclass(frozen=True)
class GreenboneReport:
    report_id: str
    task_id: str
    task_name: str
    scan_status: str
    hosts: tuple[ScannedHost, ...]
    results: tuple[Result, ...]
    rejected: tuple[tuple[str, str, Optional[str]], ...]
    #: When the scan finished, ISO 8601 UTC; None when the report gives no usable time.
    scan_end: Optional[str] = None


def refuse_unsafe_xml(data: bytes, *, max_bytes: int) -> None:
    """Raise ReportRefused unless `data` is small enough and free of DTD constructs."""
    if len(data) > max_bytes:
        raise ReportRefused(f"report is larger than {max_bytes} bytes", reason="too_large")
    if b"\x00" in data:
        raise ReportRefused("report is not ASCII-compatible XML", reason="unsafe_xml")
    lowered = data.lower()
    if b"<!doctype" in lowered:
        raise ReportRefused("report contains a DOCTYPE, which is refused", reason="unsafe_xml")
    if b"<!entity" in lowered:
        raise ReportRefused("report contains an ENTITY declaration, which is refused",
                            reason="unsafe_xml")


# Everything below is copied from scanner XML into model-visible context, so it
# is validated here, at parse time, with fullmatch (`$` admits a trailing
# newline). A value that fails is dropped or the result rejected, never cleaned.
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LABEL = r"[A-Za-z0-9-]{1,63}"
_HOSTNAME_RE = re.compile(rf"{_LABEL}(\.{_LABEL})*\.?")
_CPE_RE = re.compile(r"cpe:[A-Za-z0-9:._\-~%/+]{1,255}")
_OPEN_PORT_RE = re.compile(r"[0-9]{1,5}/(tcp|udp)")
_RESULT_PORT_RE = re.compile(r"[A-Za-z0-9._/-]{1,32}")


# Strict: date, 'T', time to the second, optional fraction, and a zone. A time
# without a zone is not guessed to be UTC.
_ISO_8601_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})")


def _utc_or_none(value: str) -> Optional[str]:
    """`value` as ISO 8601 UTC (`...Z`), or None unless it is strictly ISO 8601."""
    value = value.strip()
    if not _ISO_8601_RE.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # Month 13 is well-shaped but not a time (ValueError); year 9999 with a
        # negative offset leaves the representable range in UTC (OverflowError).
        parsed = parsed.astimezone(timezone.utc)
        pattern = "%Y-%m-%dT%H:%M:%S.%fZ" if parsed.microsecond else "%Y-%m-%dT%H:%M:%SZ"
        return parsed.strftime(pattern)
    except (ValueError, OverflowError):
        return None


def _scan_end(inner: ET.Element) -> Optional[str]:
    """`scan_end`, or `timestamp` when scan_end is absent or empty. Never guessed.

    A scan_end that is present but unusable gives None, not the other element.
    """
    end = (inner.findtext("scan_end") or "").strip()
    if end:
        return _utc_or_none(end)
    return _utc_or_none(inner.findtext("timestamp") or "")


def _uuid_or_none(value: Optional[str]) -> Optional[str]:
    value = (value or "").strip()
    return value if _UUID_RE.fullmatch(value) else None


def _is_ip(value: str) -> bool:
    if "%" in value:
        return False  # a scoped IPv6 address carries free text after the %
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _hostname_or_none(value: Optional[str]) -> Optional[str]:
    value = value or ""
    return value if 1 <= len(value) <= 253 and _HOSTNAME_RE.fullmatch(value) else None


def _text(node: Optional[ET.Element]) -> str:
    return (node.text or "").strip() if node is not None else ""


def _child_text(node: ET.Element, tag: str) -> str:
    return _text(node.find(tag))


def _details(host: ET.Element) -> dict:
    out = {}
    for detail in host.findall("detail"):
        name = _child_text(detail, "name")
        if name and name not in out:
            out[name] = _child_text(detail, "value")
    return out


def _host(node: ET.Element) -> Optional[ScannedHost]:
    ip = _child_text(node, "ip")
    if not ip or not _is_ip(ip):
        return None  # not an address: the host is not covered
    details = _details(node)
    asset = node.find("asset")
    ports = tuple(p.strip() for p in details.get("ports", "").split(",")
                  if _OPEN_PORT_RE.fullmatch(p.strip()))
    cpe = details.get("best_os_cpe") or ""
    return ScannedHost(
        ip=ip,
        asset_id=_uuid_or_none(asset.get("asset_id")) if asset is not None else None,
        hostname=_hostname_or_none(details.get("hostname")),
        os_cpe=cpe if _CPE_RE.fullmatch(cpe) else None,
        open_ports=ports,
        finished=bool(_child_text(node, "end")),
    )


def _summary(tags: str) -> str:
    for part in tags.split("|"):
        if part.startswith("summary="):
            return part[len("summary="):].strip()
    return ""


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_OID_RE = re.compile(r"[0-9]+(\.[0-9]+)+")


def _result(node: ET.Element):
    """Return (Result, None) or (None, (result_id_or_?, reason, ip_or_None))."""
    rid = node.get("id") or ""
    label = rid or "?"
    host = node.find("host")
    ip = _text(host)
    if not rid or not ip:
        return None, (label, "result has no id or no host address", ip or None)
    if not _is_ip(ip):
        return None, (label, "result host is not an IP address", None)
    nvt = node.find("nvt")
    oid = (nvt.get("oid") or "").strip() if nvt is not None else ""
    if not oid:
        return None, (label, "result has no NVT oid", ip)
    # fullmatch: these values are copied into model-visible context, so a
    # trailing newline (which `$` would let through) must be refused.
    if not _OID_RE.fullmatch(oid):
        return None, (label, "NVT oid is malformed", ip)
    try:
        severity = float(_child_text(node, "severity"))
        if not math.isfinite(severity):
            raise ValueError
    except ValueError:
        return None, (label, "severity is not a number", ip)
    try:
        qod = int(_text(node.find("qod/value")))
    except ValueError:
        return None, (label, "qod is not an integer", ip)
    port_text = _child_text(node, "port")
    if not _RESULT_PORT_RE.fullmatch(port_text):
        return None, (label, "port is malformed", ip)
    port, _, proto = port_text.partition("/")
    asset = host.find("asset") if host is not None else None
    cves = tuple(
        ref.get("id").strip()
        for ref in nvt.findall("refs/ref")
        if ref.get("type") == "cve" and (ref.get("id") or "").strip()
    )
    if not all(_CVE_RE.fullmatch(cve) for cve in cves):
        return None, (label, "CVE reference is malformed", ip)
    return Result(
        result_id=rid,
        ip=ip,
        asset_id=_uuid_or_none(asset.get("asset_id")) if asset is not None else None,
        port=port,
        protocol=proto or None,
        nvt_oid=oid,
        nvt_name=_child_text(nvt, "name"),
        severity=severity,
        qod=qod,
        cve_ids=cves,
        description=_child_text(node, "description"),
        solution=_child_text(nvt, "solution"),
        summary=_summary(_child_text(nvt, "tags")),
    ), None


def parse_report(data: bytes, *, max_bytes: int = MAX_REPORT_BYTES) -> GreenboneReport:
    refuse_unsafe_xml(data, max_bytes=max_bytes)
    try:
        return _parse(data)
    except (ReportRefused, MemoryError):
        # Running out of memory says nothing about the report: let the pull fail
        # and retry, rather than record a good report as refused.
        raise
    except Exception:  # noqa: BLE001 - any surprise while validating untrusted input
        # Nothing from the document is guessed at or echoed: refuse it whole.
        raise ReportRefused("report could not be validated", reason="malformed") from None


def _parse(data: bytes) -> GreenboneReport:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise ReportRefused("report is not well-formed XML") from None
    outer = root.find("report") if root.tag == "get_reports_response" else root
    if outer is None or outer.tag != "report":
        raise ReportRefused("document holds no report")
    inner = outer.find("report")
    if inner is None:
        inner = outer
    task = inner.find("task")
    if task is None:
        task = outer.find("task")
    task_id = (task.get("id") or "").strip() if task is not None else ""
    if not task_id:
        raise ReportRefused("report names no task")
    hosts = tuple(h for h in (_host(n) for n in inner.findall("host")) if h is not None)
    results, rejected = [], []
    for node in inner.findall("results/result"):
        result, bad = _result(node)
        if result is not None:
            results.append(result)
        else:
            rejected.append(bad)
    return GreenboneReport(
        report_id=(outer.get("id") or inner.get("id") or "").strip(),
        task_id=task_id,
        task_name=_child_text(task, "name"),
        scan_status=_child_text(inner, "scan_run_status"),
        hosts=hosts,
        results=tuple(results),
        rejected=tuple(rejected),
        scan_end=_scan_end(inner),
    )

# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""A read-only Greenbone Management Protocol (GMP) client. Nothing else.

gvmd speaks GMP: one XML request element per command, one `<X_response status=...>`
element back, over a Unix socket or TLS. This client can send exactly three commands,
`authenticate`, `get_tasks` and `get_reports`; `_send` parses the outgoing element and
refuses any other root tag, so no scan can be created, started, modified or deleted
through it.

Everything gvmd sends back is untrusted. It is read with a hard byte cap, fed to the
parser as it arrives, and every chunk (plus a short overlap with the one before it, so a
DOCTYPE split across chunks is still seen) passes `refuse_unsafe_xml` before the parser
sees it. A server that trickles bytes is stopped by an overall deadline per request.
Credentials come only from the environment, are never part of an exception message or a
repr, and are scrubbed from any server text echoed into an error.

TLS always verifies the certificate and the host name (TLS 1.2 or newer). There is no
option to turn that off.

Standard library only. The clock is never read for a lifecycle record; `time.monotonic`
here is a runtime deadline and is never persisted.
"""

import re
import select
import socket
import ssl
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Optional
from xml.sax.saxutils import escape, quoteattr

from tools.greenbone_report import MAX_REPORT_BYTES, ReportRefused, refuse_unsafe_xml

READ_ONLY_COMMANDS = ("authenticate", "get_tasks", "get_reports")

MAX_RESPONSE_BYTES = 1024 * 1024
_CHUNK = 64 * 1024
_OVERLAP = 16  # longer than "<!doctype", the longest construct refuse_unsafe_xml looks for
_DEADLINE_FACTOR = 4
_STATUS_TEXT_MAX = 200
_NAME_MAX = 200
_REPORT_FILTER = "apply_overrides=0 min_qod=0 levels=hmlgf rows=-1"

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_STATUS_RE = re.compile(r"[0-9]{3}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")


class GmpError(RuntimeError):
    """A GMP exchange failed. The message never carries credentials or request text."""


class GmpAuthError(GmpError):
    """Credentials are missing or gvmd rejected them."""


class GmpReportRefused(GmpError):
    """gvmd's response was refused as a document: too large, unsafe XML, or not well-formed.

    `reason` is one of "too_large", "unsafe_xml", "malformed", so a caller can
    record why a report was refused without keeping any server text. The client
    is still poisoned afterwards, like any GmpError.
    """

    REASONS = ("too_large", "unsafe_xml", "malformed")

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason if reason in self.REASONS else "malformed"


@dataclass(frozen=True)
class GmpTarget:
    transport: str  # "unix" | "tls"
    socket_path: Optional[str]
    host: Optional[str]
    port: int = 9390
    ca_file: Optional[str] = None
    timeout: float = 30.0


def credentials_from_env(environ: Mapping[str, str]) -> tuple[str, str]:
    username = environ.get("RZ_GREENBONE_USERNAME") or ""
    password = environ.get("RZ_GREENBONE_PASSWORD") or ""
    if not username or not password:
        raise GmpAuthError("RZ_GREENBONE_USERNAME and RZ_GREENBONE_PASSWORD must be set")
    return username, password


def _clean(text: Optional[str]) -> str:
    return _CONTROL_RE.sub("", text or "")[:_STATUS_TEXT_MAX]


def _uuid(value: str, what: str) -> str:
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        raise GmpError(f"{what} is not a UUID")
    return value


class GmpClient:
    def __init__(self, target: GmpTarget, username: str, password: str,
                 total_timeout: Optional[float] = None):
        self._target = target
        self._total_timeout = total_timeout  # one absolute deadline for the whole session, if set
        self._total_deadline: Optional[float] = None
        self._username = username
        self._password = password
        self._sock: Optional[socket.socket] = None
        # (report UUID or "?", fixed reason). Never server text.
        self.refused_reports: list[tuple[str, str]] = []
        self.skipped_tasks = 0

    def __repr__(self) -> str:
        return f"GmpClient(target={self._target!r})"

    __str__ = __repr__

    def _cap(self, deadline: float) -> float:
        """A per-phase deadline, never later than the session's total deadline."""
        if self._total_deadline is None:
            return deadline
        return min(deadline, self._total_deadline)

    def _remaining(self, per_op: float, deadline: float) -> float:
        remaining = self._cap(deadline) - time.monotonic()
        if remaining <= 0:
            raise GmpError("the GMP session ran out of time")
        return min(per_op, remaining)

    def __enter__(self) -> "GmpClient":
        if self._total_timeout is not None:
            self._total_deadline = time.monotonic() + self._total_timeout
        try:
            self._connect()
            self._authenticate()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # -- transport ---------------------------------------------------------------------

    def _connect(self) -> None:
        target = self._target
        # One overall deadline for connect and handshake, as for every request.
        deadline = self._cap(time.monotonic() + target.timeout * _DEADLINE_FACTOR)
        try:
            if target.transport == "unix":
                if not target.socket_path:
                    raise GmpError("a unix GMP target needs a socket path")
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.settimeout(self._remaining(target.timeout, deadline))
                    sock.connect(target.socket_path)
                except BaseException:
                    sock.close()
                    raise
            elif target.transport == "tls":
                if not target.host:
                    raise GmpError("a tls GMP target needs a host")
                context = ssl.create_default_context(cafile=target.ca_file)
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                raw = self._tcp_connect(target, deadline)
                try:
                    sock = context.wrap_socket(raw, server_hostname=target.host,
                                               do_handshake_on_connect=False)
                except BaseException:
                    raw.close()
                    raise
                try:
                    self._handshake(sock, deadline)
                except BaseException:
                    sock.close()
                    raise
            else:
                raise GmpError("GMP transport must be 'unix' or 'tls'")
        except GmpError:
            raise
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise GmpError(f"could not connect to gvmd ({type(exc).__name__})") from None
        self._sock = sock

    @staticmethod
    def _tcp_connect(target: GmpTarget, deadline: float) -> socket.socket:
        last: Optional[BaseException] = None
        for family, kind, proto, _, address in socket.getaddrinfo(
                target.host, target.port, type=socket.SOCK_STREAM):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GmpError("connecting to gvmd took too long")
            sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(min(target.timeout, remaining))
                sock.connect(address)
                return sock
            except OSError as exc:
                sock.close()
                last = exc
        raise GmpError(f"could not connect to gvmd ({type(last).__name__ if last else 'no address'})")

    @staticmethod
    def _handshake(sock: ssl.SSLSocket, deadline: float) -> None:
        sock.setblocking(False)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GmpError("the TLS handshake with gvmd took too long")
            try:
                sock.do_handshake()
                return
            except ssl.SSLWantReadError:
                select.select([sock], [], [], remaining)
            except ssl.SSLWantWriteError:
                select.select([], [sock], [], remaining)

    def _authenticate(self) -> None:
        request = ("<authenticate><credentials>"
                   f"<username>{escape(self._username)}</username>"
                   f"<password>{escape(self._password)}</password>"
                   "</credentials></authenticate>")
        self._send(request)

    def _read_response(self, deadline: float, max_bytes: int) -> tuple[ET.Element, bytes]:
        sock = self._sock
        if sock is None:
            raise GmpError("not connected to gvmd")
        timeout = self._target.timeout
        parser = ET.XMLPullParser(("start", "end"))
        received = bytearray()
        root: Optional[ET.Element] = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GmpError("gvmd did not finish its response in time")
            sock.settimeout(min(timeout, remaining))
            try:
                chunk = sock.recv(_CHUNK)
            except (OSError, ssl.SSLError) as exc:
                raise GmpError(f"reading from gvmd failed ({type(exc).__name__})") from None
            if not chunk:
                raise GmpError("gvmd closed the connection before the response was complete")
            if len(received) + len(chunk) > max_bytes:
                raise GmpReportRefused(f"gvmd response is larger than {max_bytes} bytes",
                                       reason="too_large")
            try:
                # The overlap makes this equivalent to checking everything received so far,
                # without re-lowercasing a 64 MiB report once per chunk.
                refuse_unsafe_xml(bytes(received[-_OVERLAP:]) + chunk, max_bytes=max_bytes)
            except ReportRefused as exc:
                raise GmpReportRefused(f"gvmd response refused: {exc}",
                                       reason=exc.reason) from None
            received += chunk
            try:
                parser.feed(chunk)
                for event, element in parser.read_events():
                    if event == "start" and root is None:
                        root = element
                    elif event == "end" and element is root:
                        return root, bytes(received)
            except ET.ParseError:
                raise GmpReportRefused("gvmd response is not well-formed XML",
                                       reason="malformed") from None

    def _send(self, xml: str, *, max_bytes: int = MAX_RESPONSE_BYTES) -> tuple[ET.Element, bytes]:
        """Send one allowed command; return the response root and its raw bytes."""
        try:
            command = ET.fromstring(xml).tag
        except ET.ParseError:
            raise GmpError("refusing to send a request that is not well-formed XML") from None
        if command not in READ_ONLY_COMMANDS:
            raise GmpError("refusing to send a GMP command that is not read-only")
        sock = self._sock
        if sock is None:
            raise GmpError("not connected to gvmd")
        deadline = self._cap(time.monotonic() + self._target.timeout * _DEADLINE_FACTOR)
        try:
            try:
                sock.settimeout(self._remaining(self._target.timeout, deadline))
                sock.sendall(xml.encode("utf-8"))
            except (OSError, ssl.SSLError) as exc:  # GmpError (out of time) passes through
                raise GmpError(f"writing to gvmd failed ({type(exc).__name__})") from None
            root, raw = self._read_response(deadline, max_bytes)
            self._check_status(command, root)
        except BaseException:
            # Whatever went wrong, the stream may still carry this request's response. Never
            # reuse it: a late reply must not be read as the answer to the next request.
            self.close()
            raise
        return root, raw

    def _check_status(self, command: str, root: ET.Element) -> None:
        error = GmpAuthError if command == "authenticate" else GmpError
        if root.tag != f"{command}_response":
            raise error(f"unexpected GMP response to {command}")
        status = root.get("status") or ""
        if not _STATUS_RE.fullmatch(status):
            raise error(f"{command} response carried no valid status")
        if status.startswith("2"):
            return
        text = root.get("status_text") or ""
        for secret in (self._password, self._username):  # before cleaning and truncating
            if secret:
                text = text.replace(secret, "[redacted]")
        text = _clean(text)
        raise error(f"{command} failed with GMP status {status}: {text}")

    # -- read-only operations ----------------------------------------------------------

    def list_tasks(self) -> list[dict]:
        root, _ = self._send('<get_tasks filter="rows=-1"/>')
        tasks = []
        for task in root.findall("task"):
            task_id = task.get("id") or ""
            if not _UUID_RE.fullmatch(task_id):
                self.skipped_tasks += 1  # an id we could not safely echo back is not offered
                continue
            tasks.append({"task_id": task_id, "name": _clean(task.findtext("name"))[:_NAME_MAX]})
        return tasks

    def finished_reports(self, task_id: str) -> list[dict]:
        """Every report gvmd lists for `task_id`, oldest first, with its status as reported.

        Whether a report is Done is the caller's decision. A report whose own task id is not
        `task_id` is dropped, whatever gvmd listed it under.
        """
        _uuid(task_id, "task id")
        request = (f"<get_reports filter={quoteattr(f'task_id={task_id} rows=-1')}"
                   ' details="0" ignore_pagination="1"/>')
        root, _ = self._send(request, max_bytes=MAX_REPORT_BYTES)
        found = []
        for outer in root.findall("report"):
            inner = outer.find("report")
            inner = inner if inner is not None else outer
            report_id = outer.get("id") or inner.get("id") or ""
            task = inner.find("task")
            own_task = (task.get("id") if task is not None else None) or ""
            if own_task != task_id:
                continue
            if not _UUID_RE.fullmatch(report_id):
                self.refused_reports.append(("?", "bad report id"))
                continue
            status = _clean(inner.findtext("scan_run_status")).strip()
            if not status or len(status) > 40:
                self.refused_reports.append((report_id, "bad status"))
                continue
            stamp = (inner.findtext("timestamp") or outer.findtext("creation_time")
                     or inner.findtext("scan_end") or "").strip()
            try:
                instant = self._instant(stamp)
            except GmpError:
                self.refused_reports.append((report_id, "bad timestamp"))
                continue
            found.append((instant, {
                "report_id": report_id, "task_id": own_task, "status": status, "timestamp": stamp}))
        found.sort(key=lambda pair: pair[0])
        return [entry for _, entry in found]

    @staticmethod
    def _instant(stamp: str) -> float:
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            raise GmpError("a report carried a timestamp that is not ISO 8601") from None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()

    def report_xml(self, report_id: str) -> bytes:
        _uuid(report_id, "report id")
        request = (f"<get_reports report_id={quoteattr(report_id)} details=\"1\" "
                   f"ignore_pagination=\"1\" filter={quoteattr(_REPORT_FILTER)}/>")
        root, raw = self._send(request, max_bytes=MAX_REPORT_BYTES)
        reports = root.findall("report")
        if len(reports) != 1 or reports[0].get("id") != report_id:
            self.close()  # the stream is out of step with our requests
            raise GmpError("gvmd answered with a report other than the one requested")
        return raw

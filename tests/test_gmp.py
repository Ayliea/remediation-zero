# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The read-only GMP client, against a fake gvmd running in a thread of this test.

Nothing here reaches a real gvmd or the network: the fake listens on a Unix socket in
tmp_path, or on 127.0.0.1 for TLS with a certificate generated at test time. Task and
report ids, hostnames and credentials are synthetic.
"""
import shutil
import socket
import ssl
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

import pytest

from tools.gmp import (
    READ_ONLY_COMMANDS, GmpAuthError, GmpClient, GmpError, GmpTarget, credentials_from_env,
)

TASK_A = "11111111-1111-4111-8111-111111111111"
TASK_B = "22222222-2222-4222-8222-222222222222"
REPORT_1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
REPORT_2 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
REPORT_3 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"
USER = "scanreader"
PASSWORD = "s3cret-Pa55-synthetic"

OK_AUTH = b'<authenticate_response status="200" status_text="OK"/>'


def tasks_response(*pairs):
    body = "".join(f'<task id="{i}"><name>{n}</name></task>' for i, n in pairs)
    return f'<get_tasks_response status="200" status_text="OK">{body}</get_tasks_response>'.encode()


def report_entry(report_id, task_id, status, stamp):
    return (f'<report id="{report_id}"><report id="{report_id}"><task id="{task_id}"/>'
            f'<scan_run_status>{status}</scan_run_status><timestamp>{stamp}</timestamp>'
            f'</report></report>')


def reports_response(*entries):
    return (f'<get_reports_response status="200" status_text="OK">{"".join(entries)}'
            f'</get_reports_response>').encode()


class FakeGvmd:
    """Serves one connection at a time; `handler(tag, request_bytes)` returns response chunks."""

    def __init__(self, listener, handler, wrap=None):
        self.listener = listener
        self.handler = handler
        self.wrap = wrap
        self.requests = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.listener.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            try:
                self._session(conn)
            except Exception:  # a refused client (bad TLS, closed early) is not a test failure
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _session(self, conn):
        conn.settimeout(5)
        if self.wrap:
            conn = self.wrap(conn)
        while not self.stop.is_set():
            parser = ET.XMLPullParser(("start", "end"))
            raw, root, done = b"", None, False
            while not done:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                raw += chunk
                parser.feed(chunk)
                for event, elem in parser.read_events():
                    if event == "start" and root is None:
                        root = elem
                    elif event == "end" and elem is root:
                        done = True
            self.requests.append(raw)
            chunks = self.handler(root.tag, raw)
            if chunks is None:
                time.sleep(30)  # silent server
                return
            for chunk in chunks:
                if callable(chunk):
                    if chunk(conn) is False:
                        return
                    continue
                conn.sendall(chunk)
                time.sleep(0.05)

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=3)


@pytest.fixture
def unix_target(tmp_path_factory, fake_endpoints):
    sock_dir = tmp_path_factory.mktemp("g")
    path = str(sock_dir / "gvmd.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(4)
    fake_endpoints.unix(path)
    servers = []

    def start(handler, timeout=5.0):
        servers.append(FakeGvmd(listener, handler))
        return GmpTarget(transport="unix", socket_path=path, host=None, timeout=timeout), servers[-1]

    yield start
    for server in servers:
        server.close()


def default_handler(extra=None):
    extra = extra or {}

    def handler(tag, raw):
        if tag in extra:
            return extra[tag]
        if tag == "authenticate":
            return [OK_AUTH]
        if tag == "get_tasks":
            return [tasks_response((TASK_A, "Weekly LAN"), (TASK_B, "DMZ"))]
        return [f'<{tag}_response status="404" status_text="Not found"/>'.encode()]
    return handler


def test_lists_tasks_over_unix_socket(unix_target):
    target, server = unix_target(default_handler())
    with GmpClient(target, USER, PASSWORD) as client:
        tasks = client.list_tasks()
    assert tasks == [{"task_id": TASK_A, "name": "Weekly LAN"}, {"task_id": TASK_B, "name": "DMZ"}]
    assert [ET.fromstring(r).tag for r in server.requests] == ["authenticate", "get_tasks"]


def test_auth_failure_is_gmp_auth_error_without_the_password(unix_target):
    bad = ['<authenticate_response status="400" status_text="Authentication failed"/>'.encode()]
    target, _ = unix_target(default_handler({"authenticate": bad}))
    with pytest.raises(GmpAuthError) as caught:
        with GmpClient(target, USER, PASSWORD):
            pass
    assert PASSWORD not in str(caught.value)
    assert PASSWORD not in repr(caught.value)
    assert "400" in str(caught.value)


def test_auth_error_scrubs_a_password_the_server_echoes(unix_target):
    echo = [f'<authenticate_response status="400" status_text="bad {PASSWORD} here"/>'.encode()]
    target, _ = unix_target(default_handler({"authenticate": echo}))
    with pytest.raises(GmpAuthError) as caught:
        GmpClient(target, USER, PASSWORD).__enter__()
    assert PASSWORD not in str(caught.value)


def test_password_is_xml_escaped(unix_target):
    password = "a</password><x>&"
    target, server = unix_target(default_handler())
    with GmpClient(target, USER, password):
        pass
    sent = server.requests[0]
    root = ET.fromstring(sent)  # still well-formed, so nothing was injected
    assert root.find("credentials/password").text == password
    assert root.find("credentials/x") is None
    assert b"a&lt;/password&gt;&lt;x&gt;&amp;" in sent


def test_refuses_to_send_a_write_command():
    client = GmpClient(GmpTarget(transport="unix", socket_path="/nonexistent", host=None), USER, PASSWORD)
    with pytest.raises(GmpError):
        client._send("<create_task/>")


@pytest.mark.parametrize("xml", ["<get_tasks_extra/>", "<authenticate_all/>", "<get_reportsX/>",
                                 "<delete_task task_id='x'/>", "<modify_config/>", "get_tasks"])
def test_rejects_a_command_whose_tag_only_starts_with_an_allowed_name(xml):
    client = GmpClient(GmpTarget(transport="unix", socket_path="/nonexistent", host=None), USER, PASSWORD)
    with pytest.raises(GmpError):
        client._send(xml)


def test_only_the_three_read_commands_are_allowed():
    assert READ_ONLY_COMMANDS == ("authenticate", "get_tasks", "get_reports")


def test_doctype_in_response_is_refused(unix_target):
    evil = [b'<!DOCTYPE x [<!ENTITY a "b">]><get_tasks_response status="200"/>']
    target, _ = unix_target(default_handler({"get_tasks": evil}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.list_tasks()


def test_doctype_in_a_later_chunk_is_refused(unix_target):
    chunks = [b'<get_tasks_response status="200" status_text="OK">',
              f'<task id="{TASK_A}"><name>ok</name></task>'.encode(),
              b'<!DocType x><task/>', b'</get_tasks_response>']
    target, _ = unix_target(default_handler({"get_tasks": chunks}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.list_tasks()


def test_doctype_split_across_chunks_is_refused(unix_target):
    chunks = [b'<get_tasks_response status="200" status_text="OK"><!DOC', b'TYPE x>',
              b'</get_tasks_response>']
    target, _ = unix_target(default_handler({"get_tasks": chunks}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.list_tasks()


def test_oversized_response_is_refused(unix_target):
    big = [b'<get_tasks_response status="200"><task id="x"><name>' + b"a" * (1024 * 1024 + 10)
           + b"</name></task></get_tasks_response>"]
    target, _ = unix_target(default_handler({"get_tasks": big}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.list_tasks()


def test_silent_server_times_out(unix_target):
    target, _ = unix_target(lambda tag, raw: [OK_AUTH] if tag == "authenticate" else None, timeout=0.5)
    started = time.monotonic()
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.list_tasks()
    assert time.monotonic() - started < 2


def test_trickling_server_hits_the_overall_deadline(unix_target):
    def trickle(conn):
        deadline = time.monotonic() + 10
        conn.sendall(b'<get_tasks_response status="200"')
        while time.monotonic() < deadline:
            try:
                conn.sendall(b" ")
            except OSError:
                return False
            time.sleep(0.1)
        return False

    target, _ = unix_target(default_handler({"get_tasks": [trickle]}), timeout=0.4)
    started = time.monotonic()
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.list_tasks()
    elapsed = time.monotonic() - started
    assert 1.0 < elapsed < 4  # timeout x 4 = 1.6s; each recv alone never timed out


def test_connection_closed_before_the_root_closes_is_an_error(unix_target):
    target, _ = unix_target(default_handler({"get_tasks": [b'<get_tasks_response status="200">',
                                                           lambda conn: False]}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.list_tasks()


def test_server_error_status_raises_with_sanitized_text(unix_target):
    text = "boom&#10;&#133;&#8232;" + "x" * 500  # newline, NEL, line separator: valid XML, still control text
    resp = [f'<get_tasks_response status="500" status_text="{text}"/>'.encode()]
    target, _ = unix_target(default_handler({"get_tasks": resp}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError) as caught:
            client.list_tasks()
    message = str(caught.value)
    assert "500" in message and "boom" in message
    assert not any(c in message for c in "\n\x85\u2028")
    assert message.count("x") <= 200


def test_finished_reports_sorted_oldest_first(unix_target):
    resp = reports_response(
        report_entry(REPORT_3, TASK_A, "Done", "2026-03-03T10:00:00Z"),
        report_entry(REPORT_1, TASK_A, "Done", "2026-01-01T10:00:00Z"),
        report_entry(REPORT_2, TASK_A, "Stopped", "2026-02-02T10:00:00+00:00"))
    target, server = unix_target(default_handler({"get_reports": [resp]}))
    with GmpClient(target, USER, PASSWORD) as client:
        reports = client.finished_reports(TASK_A)
    assert [r["report_id"] for r in reports] == [REPORT_1, REPORT_2, REPORT_3]
    assert reports[1] == {"report_id": REPORT_2, "task_id": TASK_A, "status": "Stopped",
                          "timestamp": "2026-02-02T10:00:00+00:00"}
    request = ET.fromstring(server.requests[-1])
    assert request.tag == "get_reports"
    assert TASK_A in request.get("filter")


def test_report_of_another_task_is_not_returned(unix_target):
    resp = reports_response(
        report_entry(REPORT_1, TASK_A, "Done", "2026-01-01T10:00:00Z"),
        report_entry(REPORT_2, TASK_B, "Done", "2026-02-01T10:00:00Z"))
    target, _ = unix_target(default_handler({"get_reports": [resp]}))
    with GmpClient(target, USER, PASSWORD) as client:
        reports = client.finished_reports(TASK_A)
    assert [r["report_id"] for r in reports] == [REPORT_1]


def test_report_xml_returns_the_raw_response_with_the_exact_request(unix_target):
    resp = reports_response(report_entry(REPORT_1, TASK_A, "Done", "2026-01-01T10:00:00Z"))
    target, server = unix_target(default_handler({"get_reports": [resp]}))
    with GmpClient(target, USER, PASSWORD) as client:
        data = client.report_xml(REPORT_1)
    assert data == resp
    request = ET.fromstring(server.requests[-1])
    assert request.attrib == {"report_id": REPORT_1, "details": "1", "ignore_pagination": "1",
                              "filter": "apply_overrides=0 min_qod=0 levels=hmlgf rows=-1"}


@pytest.mark.parametrize("bad", ["", "not-a-uuid", REPORT_1 + "\n", REPORT_1 + '" x="y',
                                 "../" + REPORT_1, REPORT_1.replace("a", "g", 1)])
def test_bad_report_id_is_refused_before_sending(unix_target, bad):
    target, server = unix_target(default_handler())
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.report_xml(bad)
        with pytest.raises(GmpError):
            client.finished_reports(bad)
    assert [ET.fromstring(r).tag for r in server.requests] == ["authenticate"]


def test_repr_never_shows_credentials():
    target = GmpTarget(transport="unix", socket_path="/run/gvmd.sock", host=None)
    client = GmpClient(target, USER, PASSWORD)
    for text in (repr(client), str(client), repr(target)):
        assert PASSWORD not in text and USER not in text


def test_missing_credentials_message():
    for env in ({}, {"RZ_GREENBONE_USERNAME": "u"}, {"RZ_GREENBONE_PASSWORD": "p"},
                {"RZ_GREENBONE_USERNAME": "", "RZ_GREENBONE_PASSWORD": "p"}):
        with pytest.raises(GmpAuthError) as caught:
            credentials_from_env(env)
        assert str(caught.value) == "RZ_GREENBONE_USERNAME and RZ_GREENBONE_PASSWORD must be set"
    assert credentials_from_env({"RZ_GREENBONE_USERNAME": "u", "RZ_GREENBONE_PASSWORD": "p"}) == ("u", "p")


def test_target_must_name_its_endpoint():
    with pytest.raises(GmpError):
        GmpClient(GmpTarget(transport="unix", socket_path=None, host=None), USER, PASSWORD).__enter__()
    with pytest.raises(GmpError):
        GmpClient(GmpTarget(transport="tls", socket_path=None, host=None), USER, PASSWORD).__enter__()
    with pytest.raises(GmpError):
        GmpClient(GmpTarget(transport="carrier-pigeon", socket_path=None, host=None), USER, PASSWORD).__enter__()


# --- TLS ---------------------------------------------------------------------------------

@pytest.fixture
def fake_gvmd_tls(tmp_path_factory, fake_endpoints):
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    work = tmp_path_factory.mktemp("tls")
    cert, key = str(work / "cert.pem"), str(work / "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost", "-days", "1", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    fake_endpoints.tcp(listener)
    server = FakeGvmd(listener, default_handler(), wrap=lambda c: context.wrap_socket(c, server_side=True))
    yield GmpTarget(transport="tls", socket_path=None, host="localhost", port=port,
                    ca_file=cert, timeout=5.0), port, server
    server.close()


def test_tls_verifies_against_ca_file(fake_gvmd_tls):
    target, port, _ = fake_gvmd_tls
    with GmpClient(target, USER, PASSWORD) as client:
        assert [t["task_id"] for t in client.list_tasks()] == [TASK_A, TASK_B]
    no_ca = GmpTarget(transport="tls", socket_path=None, host="localhost", port=port, ca_file=None, timeout=5.0)
    with pytest.raises(GmpError) as caught:
        GmpClient(no_ca, USER, PASSWORD).__enter__()
    assert PASSWORD not in str(caught.value)


def test_tls_refuses_a_name_the_certificate_does_not_cover(fake_gvmd_tls):
    target, port, _ = fake_gvmd_tls
    wrong = GmpTarget(transport="tls", socket_path=None, host="127.0.0.1", port=port,
                      ca_file=target.ca_file, timeout=5.0)
    with pytest.raises(GmpError):
        GmpClient(wrong, USER, PASSWORD).__enter__()


# --- review fixes --------------------------------------------------------------------------

def test_timeout_poisons_the_client(unix_target):
    target, _ = unix_target(lambda tag, raw: [OK_AUTH] if tag == "authenticate" else None, timeout=0.4)
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.report_xml(REPORT_1)
        with pytest.raises(GmpError, match="not connected"):
            client.report_xml(REPORT_2)
        with pytest.raises(GmpError, match="not connected"):
            client.list_tasks()


def test_report_with_another_id_is_refused(unix_target):
    resp = reports_response(report_entry(REPORT_1, TASK_A, "Done", "2026-01-01T10:00:00Z"))
    target, _ = unix_target(default_handler({"get_reports": [resp]}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.report_xml(REPORT_2)
        with pytest.raises(GmpError, match="not connected"):
            client.report_xml(REPORT_1)


def test_report_response_with_two_reports_is_refused(unix_target):
    resp = reports_response(report_entry(REPORT_1, TASK_A, "Done", "2026-01-01T10:00:00Z"),
                            report_entry(REPORT_2, TASK_A, "Done", "2026-01-02T10:00:00Z"))
    target, _ = unix_target(default_handler({"get_reports": [resp]}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError):
            client.report_xml(REPORT_1)


def test_status_text_scrubs_a_long_password_and_one_with_a_control_character(unix_target):
    for password in ("p" + "w" * 300, "pa&#10;ss-synthetic-1"):
        shown = "bad " + password + " tail"
        resp = [f'<authenticate_response status="400" status_text="{shown}"/>'.encode()]
        target, _ = unix_target(default_handler({"authenticate": resp}))
        with pytest.raises(GmpAuthError) as caught:
            GmpClient(target, USER, ET.fromstring(f"<a>{password}</a>").text).__enter__()
        message = str(caught.value)
        plain = ET.fromstring(f"<a>{password}</a>").text
        assert plain not in message and plain[:12] not in message
        assert "[redacted]" in message


def test_status_text_scrubs_the_username(unix_target):
    resp = [f'<authenticate_response status="400" status_text="no user {USER}"/>'.encode()]
    target, _ = unix_target(default_handler({"authenticate": resp}))
    with pytest.raises(GmpAuthError) as caught:
        GmpClient(target, USER, PASSWORD).__enter__()
    assert USER not in str(caught.value)


def test_a_bad_report_is_skipped_and_recorded_not_fatal(unix_target):
    resp = reports_response(
        report_entry(REPORT_1, TASK_A, "Done", "2026-01-01T10:00:00Z"),
        report_entry(REPORT_2, TASK_A, "Done", "last tuesday &lt;script&gt;"),
        report_entry(REPORT_3, TASK_A, "", "2026-01-03T10:00:00Z"),
        report_entry("not-a-uuid-" + "z" * 40, TASK_A, "Done", "2026-01-04T10:00:00Z"))
    target, _ = unix_target(default_handler({"get_reports": [resp]}))
    with GmpClient(target, USER, PASSWORD) as client:
        reports = client.finished_reports(TASK_A)
        refused = client.refused_reports
    assert [r["report_id"] for r in reports] == [REPORT_1]
    assert refused == [(REPORT_2, "bad timestamp"), (REPORT_3, "bad status"), ("?", "bad report id")]
    assert not any("tuesday" in text or "script" in text for pair in refused for text in pair)


def test_non_uuid_tasks_are_counted_as_skipped(unix_target):
    resp = [tasks_response((TASK_A, "ok"), ("nope", "bad"), ("../x", "worse"))]
    target, server = unix_target(default_handler({"get_tasks": resp}))
    with GmpClient(target, USER, PASSWORD) as client:
        assert [t["task_id"] for t in client.list_tasks()] == [TASK_A]
        assert client.skipped_tasks == 2
    assert ET.fromstring(server.requests[-1]).get("filter") == "rows=-1"


def test_connect_is_bounded_by_the_overall_deadline(fake_endpoints, tmp_path_factory):
    """A TLS peer that accepts and never speaks must not hold the handshake past timeout x 4."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    fake_endpoints.tcp(listener)
    held = []
    thread = threading.Thread(target=lambda: held.append(listener.accept()[0]), daemon=True)
    thread.start()
    target = GmpTarget(transport="tls", socket_path=None, host="localhost",
                       port=listener.getsockname()[1], ca_file=None, timeout=0.3)
    started = time.monotonic()
    with pytest.raises(GmpError):
        GmpClient(target, USER, PASSWORD).__enter__()
    assert time.monotonic() - started < 3
    for conn in held:
        conn.close()
    listener.close()


def test_total_timeout_bounds_a_multi_request_session(unix_target):
    """Each reply is within the per-operation timeout, but together they exceed total_timeout."""
    def slow(conn):
        time.sleep(0.4)

    def handler(tag, raw):
        if tag == "authenticate":
            return [slow, OK_AUTH]
        return [slow, tasks_response((TASK_A, "Weekly LAN"))]
    target, _ = unix_target(handler, timeout=5.0)
    started = time.monotonic()
    with pytest.raises(GmpError):
        with GmpClient(target, USER, PASSWORD, total_timeout=0.6) as client:
            client.list_tasks()
    assert time.monotonic() - started < 2.0


def test_total_timeout_unset_changes_nothing(unix_target):
    target, _ = unix_target(default_handler())
    with GmpClient(target, USER, PASSWORD, total_timeout=None) as client:
        assert len(client.list_tasks()) == 2
    with GmpClient(target, USER, PASSWORD, total_timeout=5.0) as client:
        assert len(client.list_tasks()) == 2



@pytest.mark.parametrize("chunks, reason", [
    ([b'<get_tasks_response status="200"><task id="x"><name>' + b"a" * (1024 * 1024 + 10)
      + b"</name></task></get_tasks_response>"], "too_large"),
    ([b'<!DOCTYPE x [<!ENTITY a "b">]><get_tasks_response status="200"/>'], "unsafe_xml"),
    ([b'<get_tasks_response status="200"><task></nope></get_tasks_response>'], "malformed"),
])
def test_refused_responses_carry_a_closed_reason(unix_target, chunks, reason):
    from tools.gmp import GmpReportRefused
    target, _ = unix_target(default_handler({"get_tasks": chunks}))
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpReportRefused) as refused:
            client.list_tasks()
        assert refused.value.reason == reason
        assert isinstance(refused.value, GmpError)
        with pytest.raises(GmpError, match="not connected"):  # still poisoned
            client.list_tasks()


def test_other_failures_are_not_report_refusals(unix_target):
    from tools.gmp import GmpReportRefused
    target, _ = unix_target(lambda tag, raw: [OK_AUTH] if tag == "authenticate" else None,
                            timeout=0.5)
    with GmpClient(target, USER, PASSWORD) as client:
        with pytest.raises(GmpError) as failed:
            client.list_tasks()
        assert not isinstance(failed.value, GmpReportRefused)

# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Settings -> Context over real sockets: owner-only forms, re-confirmed and audited, a
spreadsheet previewed before it is applied, and label names screened with `serial` released.
Synthetic data only: `.example` hosts and documentation addresses."""
import http.client
import re
import socket
import threading
from urllib.parse import urlencode

import pytest

from scripts import local, local_context
from tools import local_settings
from tools.guardrail import ArmorVerdict

HOSTS = {"ast-01": {"hostname": "files.client.example", "ip": "192.0.2.10"},
         "ast-02": {"hostname": "web.client.example", "ip": "192.0.2.20"}}


@pytest.fixture(autouse=True)
def no_reverse_lookup(monkeypatch):
    monkeypatch.setattr(socket, "getfqdn", lambda name="": name)


class Guard:
    def __init__(self, blocked=False, during=None):
        self.blocked, self.during, self.screened = blocked, during, []

    def screen(self, text):
        self.screened.append(text)
        if self.during:
            self.during()
        return ArmorVerdict(blocked=self.blocked, screened=True)


class Server:
    def __init__(self, port, ws, site):
        self.port, self.ws, self.site = port, ws, site

    def csrf(self, who="owner"):
        return self.site.accounts.session({"owner": self.site.owner_token, "tech": self.site.tech_token}[who]).csrf

    def request(self, method, path, body=b"", content_type="application/x-www-form-urlencoded", who="owner"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        host = f"127.0.0.1:{self.port}"
        headers = {"Host": host, "Cookie": self.site.cookie(who)}
        if method == "POST":
            headers.update({"Origin": f"http://{host}", "Sec-Fetch-Site": "same-origin",
                            "Content-Type": content_type})
        conn.request(method, path, body=body or None, headers=headers)
        response = conn.getresponse()
        text = response.read().decode()
        conn.close()
        return response, text

    def post(self, path, fields, who="owner", token=True):
        pairs = list(fields.items()) if isinstance(fields, dict) else list(fields)
        if token:
            pairs.append(("token", self.csrf(who)))
        return self.request("POST", path, urlencode(pairs).encode(), who=who)

    def upload(self, data, who="owner"):
        boundary = "rzboundary0042"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n{self.csrf(who)}\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"report\"; filename=\"hosts.csv\"\r\n"
                f"Content-Type: text/csv\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
        return self.request("POST", "/context/upload", body, f"multipart/form-data; boundary={boundary}", who)

    def page(self, who="owner"):
        return self.request("GET", "/?view=settings&section=context", who=who)

    def asset(self, asset_id):
        return self.ws.docs_for("dashboard").collection("assets").document(asset_id).get().to_dict()

    def events(self, prefix="context_"):
        return [dict(r) for r in self.site.accounts.store.events(1000) if r["event"].startswith(prefix)]

    def account_id(self, email):
        return self.site.accounts.store.account_by_email(email)["id"]


@pytest.fixture
def server(tmp_path, fake_endpoints, signed_in, monkeypatch):
    guard = Guard()
    monkeypatch.setattr(local, "guard_for", lambda roles: guard)
    ws = local.open_workspace(tmp_path / "ws")
    seed = ws.docs_for("seed")
    for asset_id, row in HOSTS.items():
        seed.collection("assets").document(asset_id).set(dict(row))
    config_path = local_settings.settings_path(ws.root)
    docs = ws.docs_for("dashboard")
    cls = local.handler(local._View(docs), False, config_path, "python3 -S -m scripts.local", None,
                        accounts=signed_in.accounts, workspace=ws)
    httpd = local.DashboardServer(("127.0.0.1", 0), cls)
    fake_endpoints.tcp(httpd.socket)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    result = Server(httpd.server_port, ws, signed_in)
    result.guard = guard
    yield result
    httpd.shutdown()
    httpd.server_close()
    docs.close()


def test_tech_sees_context_without_forms(server):
    response, text = server.page("tech")
    assert response.status == 200
    assert "files.client.example" in text and "Only an owner can change business context" in text
    assert 'action="/context/' not in text


def test_tech_post_is_403_before_body_read(server):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    host = f"127.0.0.1:{server.port}"
    # Announces a body it never sends: a server that read it would wait, not answer.
    conn.putrequest("POST", "/context/facts", skip_host=True)
    for name, value in {"Host": host, "Origin": f"http://{host}", "Sec-Fetch-Site": "same-origin",
                        "Cookie": server.site.cookie("tech"), "Content-Length": "500",
                        "Content-Type": "application/x-www-form-urlencoded"}.items():
        conn.putheader(name, value)
    conn.endheaders()
    assert conn.getresponse().status == 403
    conn.close()
    assert server.asset("ast-01").get("context_facts") is None


def test_owner_sets_fact_and_audit_row_written(server):
    response, _ = server.post("/context/facts", [("asset", "ast-01"), ("criticality", "high")])
    assert response.status == 303 and "done=saved" in response.getheader("Location")
    asset = server.asset("ast-01")
    assert asset["context_facts"]["criticality"] == "high"
    assert asset["context_provenance"]["criticality"]["account"] == "owner@client.example"
    (event,) = server.events()
    assert event["event"] == "context_facts_set" and '"criticality"' in event["detail"]
    _, text = server.request("GET", response.getheader("Location"))
    assert "Saved." in text and "Criticality: high" in text


def test_unconfirmed_owner_is_sent_to_confirm(server):
    conn_csrf = server.site.accounts.session(server.site.unconfirmed_token).csrf
    body = urlencode([("asset", "ast-01"), ("criticality", "high"), ("token", conn_csrf)]).encode()
    response, _ = server.request("POST", "/context/facts", body, who="unconfirmed")
    assert response.status == 303 and "/confirm" in response.getheader("Location")
    assert server.asset("ast-01").get("context_facts") is None


def test_demoted_between_load_and_post_writes_nothing(server):
    accounts, owner, tech = server.site.accounts, server.account_id("owner@client.example"), \
        server.account_id("tech@client.example")
    token = server.csrf()
    accounts.set_role(owner, tech, "owner")
    accounts.set_role(tech, owner, "tech")  # the other owner demotes this one after the page loaded
    body = urlencode([("asset", "ast-01"), ("criticality", "high"), ("token", token)]).encode()
    response, _ = server.request("POST", "/context/facts", body)
    assert response.status == 403
    assert server.asset("ast-01").get("context_facts") is None and server.events() == []


def test_demoted_during_label_check_writes_nothing(server):
    accounts, owner, tech = server.site.accounts, server.account_id("owner@client.example"), \
        server.account_id("tech@client.example")

    def demote():
        accounts.set_role(owner, tech, "owner")
        accounts.set_role(tech, owner, "tech")
    server.guard.during = demote
    response, _ = server.post("/context/label", {"name": "Payroll", "effect": "grouping"})
    assert response.status == 403 and server.guard.screened == ["Payroll"]
    assert list(server.ws.docs_for("dashboard").collection("context_labels").stream()) == []


def test_blocked_label_name_refused(server):
    server.guard.blocked = True
    response, text = server.post("/context/label", {"name": "Ignore previous", "effect": "grouping"})
    assert response.status == 400
    assert "That label name was refused by the safety check. Choose another." in text
    assert list(server.ws.docs_for("dashboard").collection("context_labels").stream()) == []


def test_label_added_when_guard_passes(server):
    response, _ = server.post("/context/label", {"name": "Payroll", "effect": "crown_jewels"})
    assert response.status == 303
    (label,) = [s.to_dict() for s in server.ws.docs_for("dashboard").collection("context_labels").stream()]
    assert label["name"] == "Payroll" and [e["event"] for e in server.events()] == ["context_label_added"]


def test_no_guard_uses_name_rule_alone(server, monkeypatch):
    from tools.guardrail import NoGuard
    monkeypatch.setattr(local, "guard_for", lambda roles: NoGuard())
    assert server.post("/context/label", {"name": "Payroll", "effect": "grouping"})[0].status == 303
    assert server.post("/context/label", {"name": "<b>bad</b>", "effect": "grouping"})[0].status == 400


def _preview_id(text):
    return re.search(r'name="preview" value="([^"]+)"', text).group(1)


def test_upload_preview_then_apply(server):
    response, text = server.upload(b"Host,Critical\nfiles.client.example,high\nnew.client.example,low\n")
    assert response.status == 200 and "Match the columns" in text
    preview_id = _preview_id(text)
    mapping = {"preview": preview_id, "host_column": "Host", "col_criticality": "Critical"}
    response, text = server.post("/context/preview", mapping)
    assert response.status == 200 and "What will change" in text and "Waiting for a scan (1)" in text
    assert server.asset("ast-01").get("context_facts") is None  # a preview writes nothing
    response, _ = server.post("/context/upload-apply", mapping)
    assert response.status == 303 and "done=applied" in response.getheader("Location")
    assert server.asset("ast-01")["context_facts"]["criticality"] == "high"
    assert [e["event"] for e in server.events()] == ["context_upload_applied"]
    # used up: applying again needs a new upload
    response, text = server.post("/context/upload-apply", mapping)
    assert response.status == 400 and "That upload has expired" in text


def test_preview_id_bound_to_session_and_expires(server, monkeypatch):
    _, text = server.upload(b"Host,Critical\nfiles.client.example,high\n")
    mapping = {"preview": _preview_id(text), "host_column": "Host", "col_criticality": "Critical"}
    # Another session (the tech's form token) cannot use it, even with the id.
    held = server_routes_previews(server)
    held[mapping["preview"]]["csrf"] = "someone-else"
    response, text = server.post("/context/preview", mapping)
    assert response.status == 400 and "That upload has expired" in text
    held[mapping["preview"]]["csrf"] = server.csrf()
    clock = [local_context.time.monotonic() + local_context.PREVIEW_SECONDS + 1]
    monkeypatch.setattr(local_context.time, "monotonic", lambda: clock[0])
    response, text = server.post("/context/preview", mapping)
    assert response.status == 400 and "That upload has expired" in text


def server_routes_previews(server):
    """The routes' in-memory previews, found through the one ContextRoutes the handler made."""
    import gc
    (routes,) = [o for o in gc.get_objects() if isinstance(o, local_context.ContextRoutes)
                 and o._ws is server.ws]
    return routes._previews


def test_page_escapes_csv_host_cells(server):
    _, text = server.upload(b'Host,Critical\n"<script>x</script>",high\n')
    mapping = {"preview": _preview_id(text), "host_column": "Host", "col_criticality": "Critical"}
    _, text = server.post("/context/preview", mapping)
    assert "<script>x</script>" not in text and "&lt;script&gt;x&lt;/script&gt;" in text


def test_questions_untouched_hosts_stay_not_known(server):
    response, _ = server.post("/context/questions", [("question", "1"), ("asset", "ast-01")])
    assert response.status == 303
    assert server.asset("ast-01")["context_facts"]["criticality"] == "high"
    assert server.asset("ast-02").get("context_facts") is None
    _, text = server.page()
    assert "1 host has no business context yet." in text


def test_rule_suggests_and_owner_approves(server):
    response, _ = server.post("/context/rule", {"kind": "cidr", "pattern": "192.0.2.0/28",
                                                "internet_facing": "yes"})
    assert response.status == 303
    _, text = server.page()
    assert "Suggested (1)" in text and server.asset("ast-01").get("context_facts") is None
    rule_id = re.search(r'name="source" value="([^"]+)"', text).group(1)
    response, _ = server.post("/context/decide", [("source", rule_id), ("asset", "ast-01"),
                                                  ("decision", "approve")])
    assert response.status == 303 and server.asset("ast-01")["context_facts"]["internet_facing"] is True
    assert "Suggested" not in server.page()[1]


def test_questions_pre_tick_only_facts_set_directly(server):
    """A host that is Crown jewels only through a custom label is not pre-ticked, so saving the
    answer does not turn the label's effect into a fact that outlives the label."""
    assert server.post("/context/label", {"name": "Payroll", "effect": "crown_jewels"})[0].status == 303
    _, text = server.page()
    label_id = re.search(r'<option value="(lbl-[0-9a-f]+)">Payroll', text).group(1)
    assert server.post("/context/tag", [("asset", "ast-01"), ("label", label_id), ("action", "add")])[0].status == 303
    _, text = server.page()
    first = text.split("Which of these would stop the business if they went down?")[1].split("</fieldset>")[0]
    assert 'value="ast-01" checked' not in first

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
"""Business context from a spreadsheet: read any CSV, match rows to hosts, preview, then apply."""
import pytest

from tools.clock import ClockMode, SimClock
from tools.context_import import (MAX_CSV_BYTES, MAX_PENDING_ROWS, ROW_TTL_SECONDS, ColumnMapping,
                                  match_host, preview, read_csv)
from tools.context_store import ContextWriter
from tools.local_layout import Workspace

OWNER = "owner@example.invalid"
HOSTS = [{"asset_id": "ast-001", "hostname": "files.example.invalid", "ip": "192.0.2.10"},
         {"asset_id": "ast-002", "hostname": "web.example.invalid", "ip": "192.0.2.11"},
         {"asset_id": "ast-003", "hostname": "web.other.invalid", "ip": "192.0.2.11"}]
MAPPING = ColumnMapping("Host", {"criticality": "Importance", "environment": "Env",
                                 "internet_facing": "Public", "sensitive_data": "PII"})


def test_excel_csv_with_bom_and_semicolons():
    data = "﻿Host;Importance;Env\r\nfiles.example.invalid;high;prod\r\n\"web.example.invalid\";low;\r\n".encode()
    header, rows = read_csv(data)
    assert header == ["Host", "Importance", "Env"]
    assert rows == [["files.example.invalid", "high", "prod"], ["web.example.invalid", "low", ""]]


def test_tab_separated_is_read():
    header, rows = read_csv(b"Host\tEnv\nfiles.example.invalid\tdev\n")
    assert header == ["Host", "Env"] and rows == [["files.example.invalid", "dev"]]


@pytest.mark.parametrize("data,words", [(b"", "empty"), (b"\xff\xfe\x00H", "UTF-8"),
                                        (b"Host\n" + b"a\n" * 10_001, "10,000"),
                                        (b"Host\n" + b"x" * MAX_CSV_BYTES, "5 MB")])
def test_bad_files_are_refused_in_plain_words(data, words):
    with pytest.raises(ValueError, match=words):
        read_csv(data)


def test_case_and_trailing_dot_match():
    assert match_host(HOSTS, "FILES.Example.invalid.") == ("ast-001", "matched")


def test_short_name_needs_one_match():
    assert match_host(HOSTS, "files") == ("ast-001", "matched")
    assert match_host(HOSTS, "web") == (None, "ambiguous")


def test_ip_shared_by_two_assets_is_ambiguous():
    assert match_host(HOSTS, "192.0.2.10") == ("ast-001", "matched")
    assert match_host(HOSTS, "192.0.2.11") == (None, "ambiguous")
    assert match_host(HOSTS, "198.51.100.7") == (None, "unmatched")


def test_seeded_ip_address_field_matches():
    assert match_host([{"asset_id": "a", "hostname": "h.example.invalid", "ip_address": "192.0.2.9"}],
                      "192.0.2.9") == ("a", "matched")


def test_values_are_read_per_fact():
    header = ["Host", "Importance", "Env", "Public", "PII"]
    rows = [["files.example.invalid", "High", "Production", "no", "yes"],
            ["web.example.invalid", "", "test", "Y", ""]]
    result = preview(header, rows, MAPPING, HOSTS)
    assert result.changes == {
        "ast-001": {"criticality": "high", "environment": "production", "internet_facing": False,
                    "sensitive_data": True},
        "ast-002": {"environment": "development", "internet_facing": True}}
    assert result.problems == [] and result.unmatched == []


def test_conflicting_rows_are_problems_not_changes():
    header = ["Host", "Env"]
    rows = [["files.example.invalid", "prod"], ["192.0.2.10", "dev"], ["web", "prod"],
            ["files.example.invalid", "staging-ish"]]
    result = preview(header, rows, ColumnMapping("Host", {"environment": "Env"}), HOSTS)
    assert result.changes == {}
    assert result.problems == [
        "Rows 2 and 3 disagree about files.example.invalid; neither was used.",
        "Row 4: web matches more than one host.",
        "Row 5: Environment cannot be staging-ish.",
    ]


def test_mapping_must_name_real_columns():
    with pytest.raises(ValueError, match="Nope"):
        preview(["Host"], [], ColumnMapping("Nope", {}), HOSTS)


@pytest.fixture
def ws(tmp_path):
    ws = Workspace(tmp_path / "ws")
    seed = ws.docs_for("seed")
    for host in HOSTS[:2]:
        seed.collection("assets").document(host["asset_id"]).set(dict(host))
    return ws


@pytest.fixture
def writer(ws):
    return ContextWriter(ws.docs_for("context"), SimClock(mode=ClockMode.SIM))


def test_unmatched_rows_become_suggestions_with_90_day_expiry(ws, writer):
    header = ["Host", "Env"]
    result = preview(header, [["files.example.invalid", "prod"], ["new.example.invalid", "dev"]],
                     ColumnMapping("Host", {"environment": "Env"}), HOSTS[:2])
    assert result.unmatched == [("new.example.invalid", {"environment": "development"})]
    assert writer.apply_upload(result, ColumnMapping("Host", {"environment": "Env"}), account=OWNER) == 1
    docs = ws.docs_for("dashboard")
    assert docs.collection("assets").document("ast-001").get().to_dict()["context_facts"] == {
        "environment": "production"}
    rows = [s.to_dict() for s in docs.collection("context_suggestions").stream()]
    assert len(rows) == 1 and rows[0]["kind"] == "row" and rows[0]["key"] == "new.example.invalid"
    assert rows[0]["expires_sim_ts"] - rows[0]["sim_ts"] == ROW_TTL_SECONDS == 90 * 86400


def test_mapping_remembered(ws, writer):
    mapping = ColumnMapping("Host", {"environment": "Env"})
    writer.apply_upload(preview(["Host", "Env"], [], mapping, HOSTS[:2]), mapping, account=OWNER)
    assert writer.saved_mapping() == mapping


def test_suggestion_cap(ws, writer, monkeypatch):
    monkeypatch.setattr("tools.context_store.MAX_PENDING_ROWS", 2)
    rows = [[f"n{i}.example.invalid", "dev"] for i in range(3)]
    mapping = ColumnMapping("Host", {"environment": "Env"})
    with pytest.raises(ValueError, match="2"):
        writer.apply_upload(preview(["Host", "Env"], rows, mapping, HOSTS[:2]), mapping, account=OWNER)
    assert list(ws.docs_for("dashboard").collection("context_suggestions").stream()) == []
    assert MAX_PENDING_ROWS == 5_000

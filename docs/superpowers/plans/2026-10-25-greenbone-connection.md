# Greenbone Connection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The local edition pulls finished Greenbone reports from explicitly chosen tasks (upload as fallback), turns them into assets and findings, reconciles later reports as rescans, and triages findings with or without CVEs.

**Architecture:** A safe stdlib XML parser turns a Greenbone report into a typed report object; a scanner-source layer normalises it into the existing rescan input plus asset records; a new `scanner_import` stage writes assets, findings and scans through the existing `engine/rescan` path, with reconciliation scoped to the report's task. A read-only GMP client pulls reports over the gvmd Unix socket or TLS. The triage path stops requiring `cve_id`.

**Tech Stack:** Python 3.12 standard library only for everything the local edition runs (`xml.etree`, `socket`, `ssl`, `urllib`, `sqlite3`); pytest.

**Spec:** `docs/superpowers/specs/2026-10-25-greenbone-connection-design.md`

## Schema for sign-off (owner approved in principle; confirm before Task 1)

| Record | Change |
|---|---|
| `assets` | new: `source`, `asset_key_origin` (`"greenbone_asset_id"` or `"source_ip"`), `ip`, `os_cpe`, `open_ports` (list of strings), `first_seen_scan`, `last_seen_scan`, `first_seen_real_ts`/`_sim_ts`, `last_seen_real_ts`/`_sim_ts`. `criticality`, `environment`, `internet_facing`, `owner_id` may be absent. |
| `findings` | `cve_id` optional; new: `source`, `task_id`, `nvt_oid`, `nvt_name`, `cve_ids` (list), `qod` (int), `protocol`, `solution`. Untrusted text keeps the existing `scanner_comment` field. |
| `scans` | new: `source`, `task_id`, `report_status`. |
| `scanner_state` (new collection, new file `scanner.sqlite3`) | one document per task ID: `task_id`, `last_pull_real_ts`/`_sim_ts`, `last_result` (`"imported"`, `"nothing_new"`, `"failed"`), `last_error_class`, `last_imported_report_id`, `last_imported_cycle`, `skipped` (list of `{report_id, status}`); one document `enrichment`: `last_run_real_ts`/`_sim_ts`, `fetched`, `failed`. |
| settings file | version 3, adds `scanner` object (Task 7). |

## Global Constraints

- Local edition: standard library only, runs under `python3 -S`; no new dependency anywhere.
- Every module carries the Apache 2.0 header used in the repo.
- Greenbone credentials only from `RZ_GREENBONE_USERNAME` and `RZ_GREENBONE_PASSWORD`; never written to settings, records or logs.
- GMP use is read-only: `authenticate`, `get_tasks`, `get_reports`. No other GMP command is ever sent.
- A document containing `<!DOCTYPE` or `<!ENTITY` (any case) is refused before parsing.
- Only explicitly chosen task IDs are imported; empty list means pull nothing. Every report's own task ID is checked before any write.
- Only reports with `scan_run_status` `Done` are imported. A host counts as covered only if its `<end>` is non-empty.
- Log-level results (severity 0) are skipped; results below the QoD floor (default 70) are skipped.
- One imported report per task per cycle; when a task has no imported report yet, only its newest Done report is imported.
- A finding belongs to the task that first saw it; only that task's reports may resolve, keep or reopen it.
- Seeded synthetic data and Greenbone data never share a workspace.
- Idempotency key derivation (finding, action, cycle) does not change.
- Cloud behaviour unchanged: for a finding with exactly one `cve_id` and the existing asset fields, `render_finding` output is byte-identical to today.
- Fixtures are synthetic: `.invalid` hostnames, documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), real CVE IDs. No real report is committed.
- Structured JSON logs carrying `cycle_id` and `finding_id` where one exists; error class only on failure.
- The offline suite stays offline: network tests use local fakes; `update-enrichment` is tested with an injected fetcher.
- Run the full suite with `.venv/bin/pytest -q` and `python3 -S -m scripts.verify_local_install` at the end of every task; both must pass.

## Review Focus

1. A huge real report (tens of MB, thousands of results): import must refuse cleanly above the size limit, never half-import. → Task 1 test `test_oversized_report_is_refused_before_parsing`; Task 8 test `test_refused_report_writes_nothing`.
2. A report whose hosts have no Greenbone asset ID (older gvmd, uploads): assets still keyed stably by IP fallback and visibly marked. → Task 2 test `test_host_without_asset_id_falls_back_to_ip_and_says_so`.
3. The same host scanned by two tasks with different configs: neither closes the other's findings. → Task 3 test `test_other_tasks_report_never_closes_a_finding`.
4. gvmd that answers slowly or never: pull times out, writes nothing but the failure, and the next cycle still runs triage. → Task 6 test `test_silent_server_times_out`; Task 9 test `test_failed_pull_does_not_block_the_cycle`.
5. A no-CVE critical finding someone tries to accept without a person: refused with the "no CVE" reason. → Task 4 test `test_no_cve_high_acceptance_needs_a_person`.

---

### Task 1: Safe Greenbone report parser

**Files:**
- Create: `tools/greenbone_report.py`
- Create: `tests/fixtures/greenbone/report_basic.xml`, `report_export.xml`, `report_stopped.xml`, `report_doctype.xml`
- Test: `tests/test_greenbone_report.py`

**Interfaces:**
- Produces:
  - `MAX_REPORT_BYTES = 64 * 1024 * 1024`
  - `class ReportRefused(ValueError)`
  - `@dataclass(frozen=True) class ScannedHost: ip: str; asset_id: Optional[str]; hostname: Optional[str]; os_cpe: Optional[str]; open_ports: tuple[str, ...]; finished: bool`
  - `@dataclass(frozen=True) class Result: result_id: str; ip: str; asset_id: Optional[str]; port: str; protocol: Optional[str]; nvt_oid: str; nvt_name: str; severity: float; qod: int; cve_ids: tuple[str, ...]; description: str; solution: str; summary: str`
  - `@dataclass(frozen=True) class GreenboneReport: report_id: str; task_id: str; task_name: str; scan_status: str; hosts: tuple[ScannedHost, ...]; results: tuple[Result, ...]; rejected: tuple[tuple[str, str], ...]` (rejected = `(result_id or "?", reason)`)
  - `def parse_report(data: bytes, *, max_bytes: int = MAX_REPORT_BYTES) -> GreenboneReport`
  - `def refuse_unsafe_xml(data: bytes, *, max_bytes: int) -> None` (also used by Task 6 on GMP responses)

Accepts both shapes: a GMP `<get_reports_response>` wrapping `<report>`, and a GSA XML export whose root is `<report>` with an inner `<report>`. Field sources: task from `report/task@id` and `task/name`; status from `scan_run_status`; hosts from inner `report/host` (`ip`, `asset@asset_id`, `end`, and `detail` entries named `hostname`, `best_os_cpe`, `ports`); results from `results/result` (`host` text and `host/asset@asset_id`, `port` like `443/tcp` or `general/tcp`, `nvt@oid`, `nvt/name`, `severity`, `qod/value`, `nvt/refs/ref[@type="cve"]@id`, `description`, `nvt/solution`, the `summary=` part of `nvt/tags`). Verify element names against the GMP 22.4 reference before writing fixtures. Parsing returns everything structurally valid; QoD and log filtering happen in Task 2.

- [ ] **Step 1: Write fixtures and failing tests**

Fixtures hand-written to the GMP schema: `report_basic.xml` (GMP response; task `11111111-1111-4111-8111-111111111111`; status Done; three hosts `192.0.2.10` asset `aaaa…` hostname `web.example.invalid`, `192.0.2.11` asset `bbbb…` finished with no results, `192.0.2.12` with empty `<end>`; results: CVE-2021-44228 on 192.0.2.10 port 8080/tcp severity 10.0 QoD 97; a no-CVE "SSH Weak Encryption Algorithms Supported" severity 5.3 QoD 95; one with two CVEs CVE-2023-44487 and CVE-2023-4863 severity 7.5 QoD 80; a log result severity 0.0; one with QoD 30; one with severity `abc`; all six results are on 192.0.2.10, so 192.0.2.11 is a finished clean host and 192.0.2.12 an unfinished one with no results). `report_export.xml` is the same content in GSA export shape. `report_stopped.xml` status `Stopped`. `report_doctype.xml` has a DOCTYPE with an entity.

```python
def test_parses_gmp_response_and_export_alike():
    a = parse_report(FIX("report_basic.xml")); b = parse_report(FIX("report_export.xml"))
    assert a.report_id == b.report_id and a.task_id == "11111111-1111-4111-8111-111111111111"
    assert a.scan_status == "Done" and len(a.hosts) == 3
    assert [r.nvt_oid for r in a.results] == [r.nvt_oid for r in b.results]

def test_hosts_report_whether_they_finished():
    hosts = {h.ip: h for h in parse_report(FIX("report_basic.xml")).hosts}
    assert hosts["192.0.2.11"].finished and not hosts["192.0.2.12"].finished
    assert hosts["192.0.2.10"].hostname == "web.example.invalid"

def test_cves_are_collected_and_absent_cves_are_empty():
    by_name = {r.nvt_name: r for r in parse_report(FIX("report_basic.xml")).results}
    assert by_name["SSH Weak Encryption Algorithms Supported"].cve_ids == ()
    assert len([r for r in by_name.values() if len(r.cve_ids) == 2]) == 1

def test_malformed_result_is_rejected_with_a_reason_not_guessed():
    report = parse_report(FIX("report_basic.xml"))
    assert len(report.rejected) == 1 and "severity" in report.rejected[0][1]

def test_doctype_is_refused_before_parsing():
    with pytest.raises(ReportRefused, match="DOCTYPE"):
        parse_report(FIX("report_doctype.xml"))
    with pytest.raises(ReportRefused):
        parse_report(b'<report><!entity x "y"></report>')

def test_oversized_report_is_refused_before_parsing():
    with pytest.raises(ReportRefused, match="larger than"):
        parse_report(b"<report>" + b" " * 2048 + b"</report>", max_bytes=1024)

def test_report_without_task_is_refused():
    with pytest.raises(ReportRefused, match="task"):
        parse_report(b'<report id="r"><report id="r"><scan_run_status>Done</scan_run_status></report></report>')

def test_parser_is_stdlib_only():  # run module under `python3 -S -c "import tools.greenbone_report"`
    ...
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_greenbone_report.py -v` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement** `parse_report` and `refuse_unsafe_xml` in `tools/greenbone_report.py` using `xml.etree.ElementTree.fromstring` after `refuse_unsafe_xml`; values that fail to parse as their type go to `rejected`.
- [ ] **Step 4: Run** the test file, then the full suite and `verify_local_install` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Parse Greenbone reports safely, refusing DOCTYPEs and oversized input"`

### Task 2: Scanner-source normalisation

**Files:**
- Create: `engine/scanner_source.py`
- Test: `tests/test_scanner_source.py`

**Interfaces:**
- Consumes: `GreenboneReport`, `ScannedHost`, `Result` (Task 1).
- Produces:
  - `DEFAULT_QOD_FLOOR = 70`
  - `@dataclass(frozen=True) class NormalisedScan: scan_id: str; source: str; task_id: str; report_status: str; assets: tuple[dict, ...]; findings: tuple[dict, ...]; covered_asset_ids: tuple[str, ...]; skipped: dict[str, int]` (`skipped` keys: `log`, `below_qod`, `rejected`)
  - `def asset_key(source: str, host_asset_id: Optional[str], ip: str) -> tuple[str, str]` → `(asset_id, origin)`: `("gb-" + host_asset_id, "greenbone_asset_id")` or `("gb-ip-" + ip, "source_ip")`
  - `def finding_key(asset_id: str, nvt_oid: str, port: str) -> str` → `f"{asset_id}:{nvt_oid}:{port}"`
  - `def normalise_greenbone(report: GreenboneReport, *, qod_floor: int = DEFAULT_QOD_FLOOR) -> NormalisedScan`
  - `def to_rescan_input(scan: NormalisedScan) -> dict` → `{"scan_id", "covered_asset_ids", "findings", "task_id", "source", "report_status"}`
  - `class ScannerSource(Protocol)`: `list_tasks() -> list[dict]` (each `{"task_id", "name"}`), `finished_reports(task_id: str) -> list[dict]` (each `{"report_id", "task_id", "status", "timestamp"}`, oldest first), `fetch(report_id: str) -> NormalisedScan`

Finding dict fields: `finding_id`, `asset_id`, `source="greenbone"`, `task_id`, `nvt_oid`, `nvt_name`, `cve_ids` (list), `cve_id` (only when exactly one CVE), `port`, `protocol`, `scanner_severity` (float), `scanner_cvss` (same float), `qod`, `solution`, `scanner_comment` (untrusted: summary + "\n\n" + description), `status="open"`, `first_seen_scan`. Asset dict fields per the schema table; `open_ports` from the host `ports` detail.

- [ ] **Step 1: Write failing tests**

```python
def test_log_and_low_qod_results_are_skipped_and_counted():
    scan = normalise_greenbone(parse_report(FIX("report_basic.xml")))
    assert scan.skipped == {"log": 1, "below_qod": 1, "rejected": 1}
    assert len(scan.findings) == 3

def test_qod_floor_is_configurable():
    assert len(normalise_greenbone(parse_report(FIX("report_basic.xml")), qod_floor=20).findings) == 4

def test_only_finished_hosts_are_covered():
    scan = normalise_greenbone(parse_report(FIX("report_basic.xml")))
    ips = {a["ip"]: a["asset_id"] for a in scan.assets}
    assert ips["192.0.2.11"] in scan.covered_asset_ids      # finished, clean
    assert ips["192.0.2.12"] not in scan.covered_asset_ids  # unfinished

def test_host_without_asset_id_falls_back_to_ip_and_says_so():
    assert asset_key("greenbone", None, "192.0.2.20") == ("gb-ip-192.0.2.20", "source_ip")
    assert asset_key("greenbone", "abc", "192.0.2.20") == ("gb-abc", "greenbone_asset_id")

def test_finding_key_is_stable_across_reports():
    a = normalise_greenbone(parse_report(FIX("report_basic.xml")))
    b = normalise_greenbone(parse_report(FIX("report_export.xml")))
    assert {f["finding_id"] for f in a.findings} == {f["finding_id"] for f in b.findings}

def test_single_cve_sets_cve_id_and_multi_or_none_does_not():
    by = {len(f["cve_ids"]): f for f in normalise_greenbone(parse_report(FIX("report_basic.xml"))).findings}
    assert by[1]["cve_id"] == "CVE-2021-44228"
    assert "cve_id" not in by[0] and "cve_id" not in by[2]

def test_rescan_input_matches_engine_contract():
    data = to_rescan_input(normalise_greenbone(parse_report(FIX("report_basic.xml"))))
    assert {"scan_id", "covered_asset_ids", "findings"} <= set(data)
    assert all(f["asset_id"] in data["covered_asset_ids"] for f in data["findings"])
```

- [ ] **Step 2: Run** — Expected: FAIL. **Step 3: Implement** in `engine/scanner_source.py` (stdlib only). A result on a host not marked finished: the host is still added to assets but the result is kept only if its host is covered (otherwise reconcile would raise); count it under `rejected` with reason "host not finished".
- [ ] **Step 4: Run** file, full suite, `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Normalise Greenbone reports into assets, findings and coverage"`

### Task 3: Task-scoped reconciliation

**Files:**
- Modify: `tools/rescan.py` (`reconcile`), `engine/rescan.py` (`run_rescan`)
- Test: `tests/test_rescan.py` (extend), `tests/test_engine_stages.py` (extend)

**Interfaces:**
- Produces: `reconcile(*, previous, scan, covered_asset_ids, scan_id, task_id: Optional[str] = None)`. When `task_id` is given, `previous` is first filtered to findings whose `task_id` equals it; a scan finding whose ID exists in `previous` under a different task is dropped from the scan (no NEW, no change) and counted in a new `Reconciliation.foreign: tuple[str, ...]`. `run_rescan` passes `scan.get("task_id")` and writes `source`, `task_id`, `report_status` (when present) onto the scan manifest via `ScanWriter.record_scan`.

- [ ] **Step 1: Write failing tests**

```python
def test_other_tasks_report_never_closes_a_finding():
    previous = [{"finding_id": "F1", "asset_id": "A", "status": "open", "task_id": "T1"}]
    rec = reconcile(previous=previous, scan=[], covered_asset_ids=["A"], scan_id="S2", task_id="T2")
    assert rec.of(Outcome.RESOLVED) == ()

def test_same_finding_seen_by_another_task_is_not_duplicated():
    previous = [{"finding_id": "F1", "asset_id": "A", "status": "open", "task_id": "T1"}]
    rec = reconcile(previous=previous, scan=[{"finding_id": "F1", "asset_id": "A"}],
                    covered_asset_ids=["A"], scan_id="S2", task_id="T2")
    assert rec.of(Outcome.NEW) == () and rec.foreign == ("F1",)

def test_own_task_still_resolves():
    previous = [{"finding_id": "F1", "asset_id": "A", "status": "open", "task_id": "T1"}]
    rec = reconcile(previous=previous, scan=[], covered_asset_ids=["A"], scan_id="S2", task_id="T1")
    assert [o.finding_id for o in rec.of(Outcome.RESOLVED)] == ["F1"]

def test_untasked_scan_keeps_todays_behaviour():  # seed/demo scans
    previous = [{"finding_id": "F1", "asset_id": "A", "status": "open"}]
    rec = reconcile(previous=previous, scan=[], covered_asset_ids=["A"], scan_id="S2")
    assert len(rec.of(Outcome.RESOLVED)) == 1

def test_scan_manifest_records_source_and_task():  # in test_engine_stages, via run_rescan on a local workspace
    ...  # assert scans[<id>] has source == "greenbone", task_id == "T1", report_status == "Done"
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** `counts` gains `"foreign"` only when non-zero, so existing count shapes are unchanged.
- [ ] **Step 4: Run** file, full suite (existing rescan tests must pass unchanged), `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Let only a finding's own task close or reopen it"`

### Task 4: Findings without a CVE through triage and acceptance

**Files:**
- Modify: `tools/enrichment.py`, `tools/inference.py` (`render_finding`), `engine/triage_cycle.py` (line 174, 180), `engine/sweep.py` (`accept`, line ~95), `tools/exceptions.py` (`validate_acceptance`), `prompts/triage.md`, `ui/dashboard_view.py` (`screening_text`)
- Test: `tests/test_inference.py`, `tests/test_engine_triage_cycle.py`, `tests/test_exceptions.py`, `tests/test_engine_stages.py`, `tests/test_dashboard.py`

**Interfaces:**
- Produces:
  - `Enrichment` gains `applicable: bool = True` (False means no CVE: KEV/EPSS/NVD not applicable).
  - `def enrich_finding(cache: EnrichmentCache, finding: Mapping) -> Enrichment` in `tools/enrichment.py`: no CVEs → `Enrichment(cve_id="", applicable=False, kev_checked=cache.has_kev)`; one → `cache.enrich(cve)`; several → the one in KEV, else highest `epss_score`, else first, with `sources` merged.
  - `render_finding`: for a finding with `cve_id` and no `cve_ids`/`nvt_name`/`qod`, output byte-identical to today. Otherwise the `cve_id:` line becomes `cve_ids: <comma list>` or `cve_ids: none (no CVE)`, and lines `nvt_name:` and `qod:` (percent) are added after it; when `enrichment.applicable` is False every enrichment value reads `not applicable (no CVE)`. Asset fields absent render `not known` (not `None`).
  - `validate_acceptance(..., no_cve_severity: Optional[str] = None)`: when `no_cve_severity in {"high", "critical"}` and not `approved_by_human`, raise `ValueError("No CVE, so exploitation status cannot be checked: a person must approve accepting a high or critical finding")`.
  - `engine/sweep.accept`: for a finding with no CVEs, `in_kev=False` and `no_cve_severity` = latest decision's `proposed_severity` for that finding (or `"critical"` when none, failing closed).
  - `screening_text` not-screened wording becomes: `"Scanner notes were not checked, so they were withheld; triaged on limited evidence."`
  - `prompts/triage.md` gains a short paragraph: a finding may have no CVE (configuration weaknesses, default credentials, end-of-life software); judge it from the test name, Greenbone severity, QoD and the asset; treat lower QoD as less certain; "not applicable (no CVE)" is not evidence of safety.

- [ ] **Step 1: Write failing tests**

```python
def test_single_cve_cloud_render_is_unchanged():  # golden: copy today's output for the existing fixture before changing code
    assert render_finding(FINDING, ASSET, ENRICHMENT) == GOLDEN

def test_no_cve_render_says_not_applicable_not_unknown():
    text = render_finding({"finding_id": "F", "cve_ids": [], "nvt_name": "SSH Weak Encryption Algorithms Supported", "qod": 95},
                          {}, Enrichment(cve_id="", applicable=False))
    assert "cve_ids: none (no CVE)" in text and "not applicable (no CVE)" in text
    assert "unknown (KEV list not available)" not in text and "criticality: not known" in text

def test_multi_cve_enrichment_picks_the_kev_one():
    ...  # cache fake with CVE-2023-4863 in KEV; enrich_finding returns cve_id "CVE-2023-4863"

def test_no_cve_finding_is_triaged_end_to_end(ws):  # test_engine_triage_cycle: seed a finding with cve_ids [] and no cve_id
    ...  # run(...) -> outcomes {"ratified": 1}; proposer saw "cve_ids: none (no CVE)"

def test_no_cve_high_acceptance_needs_a_person():
    with pytest.raises(ValueError, match="No CVE"):
        validate_acceptance(ttl_days=30, reason="r", in_kev=False, approved_by_human=False, no_cve_severity="high")
    validate_acceptance(ttl_days=30, reason="r", in_kev=False, approved_by_human=False, no_cve_severity="medium")

def test_limited_evidence_wording():
    assert "triaged on limited evidence" in dashboard_view.screening_text({"screening": {"screened": False, "blocked": True}})
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** per the interfaces; update the existing screening wording test in `tests/test_dashboard.py` to the new sentence.
- [ ] **Step 4: Run** the five test files, full suite, `verify_local_install` — PASS. Confirm the golden test passes on the cloud fixture.
- [ ] **Step 5: Commit** `git commit -m "Triage findings with no CVE, and say 'not applicable' rather than 'unknown'"`

### Task 5: Enrichment refresh

**Files:**
- Create: `tools/enrichment_fetch.py`
- Modify: `scripts/fetch-enrichment.py` (use the module), `scripts/local.py` (new `update-enrichment` command; `cycle` reads the workspace cache), `tools/enrichment.py` (no change to the reading path beyond `cache_dir`)
- Test: `tests/test_enrichment_fetch.py`, `tests/test_local_commands.py`

**Interfaces:**
- Produces:
  - `def workspace_cache_dir(root: Path) -> Path` → `root / "enrichment"` (in `tools/enrichment_fetch.py`).
  - `def refresh(cves: Iterable[str], cache_dir: Path, *, get: Callable[[str], bytes], sleep: Callable[[float], None] = time.sleep, nvd_api_key: Optional[str] = None) -> dict` → `{"kev": "ok"|"failed", "epss": "ok"|"failed", "nvd_fetched": int, "nvd_failed": list[str], "nvd_skipped": int}`. Writes atomically (temp file + `os.replace`); resumable (skips CVEs already in `nvd.json`); NVD delay 6.5 s without a key, 0.7 s with one; URLs are the three already in `scripts/fetch-enrichment.py`; `apiKey` header when a key is given.
  - `scripts.local update-enrichment` collects CVEs from all workspace findings (`cve_ids` or `cve_id`), prints "This reaches the internet: CISA, FIRST EPSS and NVD." first, calls `refresh` with `NVD_API_KEY` from the environment, writes the `scanner_state/enrichment` document, prints the summary. `cycle` uses `EnrichmentCache(workspace_cache_dir(ws.root))` and the warning names that path.

- [ ] **Step 1: Write failing tests** (all with a fake `get`; never real network)

```python
def test_refresh_writes_all_three_and_resumes(tmp_path):
    calls = []
    first = refresh(["CVE-2021-44228"], tmp_path, get=fake_get(calls), sleep=lambda s: None)
    assert first["kev"] == "ok" and first["nvd_fetched"] == 1
    again = refresh(["CVE-2021-44228"], tmp_path, get=fake_get(calls), sleep=lambda s: None)
    assert again["nvd_skipped"] == 1 and again["nvd_fetched"] == 0
    assert EnrichmentCache(tmp_path).has_kev

def test_one_failing_cve_does_not_stop_the_rest(tmp_path): ...
def test_failed_kev_download_keeps_the_previous_file(tmp_path): ...
def test_api_key_is_sent_as_header_and_never_logged(tmp_path, caplog): ...
def test_cycle_reads_the_workspace_cache(tmp_path): ...  # test_local_commands: cache written to <ws>/enrichment is used; no stderr warning
def test_update_enrichment_says_it_reaches_the_internet(tmp_path, capsys, monkeypatch): ...  # monkeypatch refresh's get
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** Keep `scripts/fetch-enrichment.py` behaviour (repo `data/cache`, synthetic corpus) by calling `refresh` with `urllib` `get`.
- [ ] **Step 4: Run** files, full suite, `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Add update-enrichment, the one command that reaches the internet"`

### Task 6: Read-only GMP client

**Files:**
- Create: `tools/gmp.py`
- Test: `tests/test_gmp.py` (with an in-test fake gvmd: a thread serving canned XML over a Unix socket, and over TLS using a certificate generated at test time with `openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1`; skip the TLS tests if `openssl` is not on PATH)

**Interfaces:**
- Consumes: `refuse_unsafe_xml`, `parse_report`, `MAX_REPORT_BYTES` (Task 1).
- Produces:
  - `class GmpError(RuntimeError)`, `class GmpAuthError(GmpError)`
  - `@dataclass(frozen=True) class GmpTarget: transport: str ("unix"|"tls"); socket_path: Optional[str]; host: Optional[str]; port: int = 9390; ca_file: Optional[str] = None; timeout: float = 30.0`
  - `class GmpClient`: `__init__(self, target: GmpTarget, username: str, password: str)`; context manager; `list_tasks() -> list[dict]` (`{"task_id","name"}`); `finished_reports(task_id) -> list[dict]` (`{"report_id","task_id","status","timestamp"}`, oldest first, status as reported); `report_xml(report_id) -> bytes`.
  - `def credentials_from_env(environ: Mapping[str,str]) -> tuple[str, str]` raising `GmpAuthError("RZ_GREENBONE_USERNAME and RZ_GREENBONE_PASSWORD must be set")`.
  - Allowed commands constant `READ_ONLY_COMMANDS = ("authenticate", "get_tasks", "get_reports")`; `_send` refuses any other root element.

Responses are read until the root element closes (`xml.etree.ElementTree.XMLPullParser` fed in chunks), each chunk accumulated and checked with `refuse_unsafe_xml` and the size limit. Username and password are XML-escaped (`xml.sax.saxutils.escape`). TLS uses `ssl.create_default_context(cafile=ca_file)` with hostname checking on; no option disables verification. Reports are fetched with `<get_reports report_id="…" details="1" ignore_pagination="1" filter="apply_overrides=0 min_qod=0 levels=hmlgf rows=-1"/>` so filtering is ours (Task 2), not the report format's.

- [ ] **Step 1: Write failing tests**

```python
def test_lists_tasks_over_unix_socket(fake_gvmd_unix): ...
def test_auth_failure_is_gmp_auth_error_without_the_password(fake_gvmd_unix): ...  # assert password not in str(exc)
def test_password_is_xml_escaped(fake_gvmd_unix): ...  # password 'a</password><x>' reaches the server escaped
def test_refuses_to_send_a_write_command():
    with pytest.raises(GmpError): client._send("<create_task/>")
def test_doctype_in_response_is_refused(fake_gvmd_unix): ...
def test_oversized_response_is_refused(fake_gvmd_unix): ...
def test_silent_server_times_out(fake_gvmd_unix_silent): ...  # timeout=0.5 -> GmpError within 2 s
def test_tls_verifies_against_ca_file(fake_gvmd_tls): ...  # succeeds with ca_file, fails (GmpError) without
def test_missing_credentials_message(): ...
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** file, full suite, `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Add a read-only GMP client over Unix socket and verified TLS"`

### Task 7: Scanner settings (v3) and the Scanner section

**Files:**
- Modify: `tools/local_settings.py`, `ui/settings_view.py`, `scripts/local.py` (POST handler)
- Test: `tests/test_local_settings.py`, `tests/test_local_edition.py`

**Interfaces:**
- Produces: settings `version` 3 with `scanner = {"transport": "unix"|"tls", "socket_path": str, "host": str, "port": int, "ca_file": str, "task_ids": list[str], "qod_floor": int, "auto_enrichment": bool}`; defaults `{"transport": "unix", "socket_path": "", "host": "", "port": 9390, "ca_file": "", "task_ids": [], "qod_floor": 70, "auto_enrichment": False}`. v2 files upgrade to v3 with defaults (v1 → v2 → v3). Validation: task IDs match `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, deduplicated; `qod_floor` 0–100; port 1–65535; TLS needs `host`; no field may hold a credential (no `username`/`password` keys accepted). `def gmp_target(settings: dict) -> GmpTarget`.
  - `SECTIONS` gains `'scanner': 'Scanner'`. The section shows connection fields, task IDs (one per line, typed by hand), QoD floor, the auto-enrichment checkbox (off), and a note that credentials come from `RZ_GREENBONE_USERNAME`/`RZ_GREENBONE_PASSWORD`. When a connection works, the page lists the account's tasks with tick-boxes (from `GmpClient.list_tasks`, read when the section is opened; failure shows "Could not reach Greenbone: <error class>"). A "Test connection" submit posts `section=scanner_test` and shows what succeeded (connect, authenticate, list tasks) without saving.
  - POST accepts `section=scanner` with exactly the scanner fields and the existing CSRF token, Host and Origin checks.

- [ ] **Step 1: Write failing tests**

```python
def test_v2_settings_upgrade_to_v3_with_scanner_defaults(tmp_path): ...
def test_empty_task_list_is_valid_and_means_pull_nothing(): ...
def test_bad_task_id_is_rejected(): ...
def test_credentials_cannot_be_saved(): ...  # scanner with "password" key -> ValueError
def test_tls_requires_host(): ...
def test_scanner_section_renders_and_saves(tmp_path): ...  # via the served handler, as existing settings tests do
def test_scanner_section_never_shows_the_password(monkeypatch, tmp_path): ...
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** files, full suite, `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Add Scanner settings: chosen tasks, connection, QoD floor"`

### Task 8: Import stage

**Files:**
- Create: `engine/scanner_import.py`
- Modify: `tools/local_layout.py` (`AGENT_FILES["scanner"] = ("scanner_state",)`; `STAGE_WRITES["scanner_import"] = {"assets", "findings", "scans", "scanner_state"}`), `engine/seed.py` (refuse seeding when any finding has `source == "greenbone"`), `engine/snapshot.py` (include `scanner_state`)
- Test: `tests/test_scanner_import.py`, `tests/test_local_layout.py`

**Interfaces:**
- Consumes: Tasks 1–3, 6 (`GmpClient` via `ScannerSource`), Task 7 (`settings["scanner"]`).
- Produces:
  - `class GreenboneSource(ScannerSource)` wrapping a `GmpClient` and `qod_floor`.
  - `class ImportRefused(ValueError)`
  - `def import_scan(ports: Ports, cycle: int, scan: NormalisedScan, *, chosen_task_ids: Collection[str]) -> dict` — refuses (writes nothing) if `scan.task_id` not chosen, if `scan.report_status != "Done"`, if the workspace holds seeded findings (any finding without `source`), or if `scanner_state[task].last_imported_cycle == cycle`; otherwise upserts assets (merge: keeps `first_seen_*`, updates `last_seen_*`, never overwrites owner/criticality/environment/internet_facing), then `run_rescan(ports, cycle, to_rescan_input(scan), dry_run=False)`, then writes `scanner_state[task]`. Returns the rescan summary plus `skipped`.
  - `def pull(ports: Ports, cycle: int, source: ScannerSource, *, chosen_task_ids: Collection[str]) -> dict` — per chosen task: if no `last_imported_report_id`, import only the newest Done report; else the oldest Done report newer than the last imported one. Records non-Done reports met along the way in `skipped`. Any exception from the source: writes only `scanner_state[task]` with `last_result="failed"` and the error class, logs, continues with other tasks. Empty `chosen_task_ids` returns `{"pulled": [], "reason": "no tasks chosen"}` and writes nothing.
  - `def import_upload(ports, cycle, data: bytes, *, chosen_task_ids, qod_floor, add_task: bool = False) -> dict` — parses, normalises, and calls `import_scan`; when the task is not chosen and `add_task` is False raises `ImportRefused("report is from task <name> (<id>), which is not chosen for this install")`.

- [ ] **Step 1: Write failing tests** (local `Workspace`, synthetic fixtures, a fake `ScannerSource` serving `NormalisedScan`s built from fixture variants)

```python
def test_unchosen_task_is_refused_and_nothing_written(ws): ...
def test_refused_report_writes_nothing(ws): ...  # Stopped report -> ImportRefused; every collection unchanged
def test_first_pull_imports_only_the_newest_done_report(ws): ...
def test_one_report_per_task_per_cycle(ws): ...  # second pull same cycle imports nothing
def test_resolved_regressed_resolved_across_three_reports(ws): ...  # cycles 1,2,3: final status resolved
def test_unfinished_host_closes_nothing(ws): ...
def test_assets_keep_first_seen_and_never_lose_owner(ws): ...
def test_failed_pull_records_failure_only(ws): ...  # source raises GmpError -> scanner_state failed, findings untouched
def test_empty_choice_pulls_nothing(ws): ...
def test_demo_and_real_never_mix_either_way(ws): ...  # seed then import refused; import then seed refused
def test_repeated_pull_writes_nothing(ws): ...
def test_upload_from_unchosen_task_needs_add_task(ws): ...
def test_scanner_state_file_is_written_only_by_import_stage(ws): ...  # test_local_layout
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** files, full suite, `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Import Greenbone reports through the rescan path, task by task"`

### Task 9: Commands and the cycle timer

**Files:**
- Modify: `scripts/local.py` (new `greenbone` command group), `scripts/local_launcher.py` (interval tick pulls before the cycle), `CLAUDE.md` (Commands block), `docs/development/local-edition.md`
- Test: `tests/test_local_commands.py`, `tests/test_local_edition.py`

**Interfaces:**
- Produces commands: `greenbone tasks` (lists `task_id  name`), `greenbone test` (connect / authenticate / list tasks, one line each), `greenbone pull [--cycle N]` (default `next_cycle(ws)`), `greenbone upload FILE [--add-task] [--cycle N]` (`--add-task` saves the task ID to settings only after the report parses and prints "Adding task <name> (<id>) to this install."), `update-enrichment` (Task 5). All read credentials via `credentials_from_env`; exit 2 with the message on missing credentials; error class only on other failures.
  - Interval tick: `pull` then, if `settings["scanner"]["auto_enrichment"]` and the pull added findings with new CVEs, `update-enrichment` for those; then the existing `cycle`. A pull failure is logged and the cycle still runs.

- [ ] **Step 1: Write failing tests**

```python
def test_greenbone_tasks_lists_from_a_fake_server(...): ...
def test_missing_credentials_exit_2_with_the_variable_names(...): ...
def test_pull_then_cycle_triages_imported_findings(...): ...  # fake source + fake models: findings decided
def test_failed_pull_does_not_block_the_cycle(...): ...
def test_upload_add_task_saves_the_task_only_after_parsing(...): ...
def test_auto_enrichment_off_by_default_never_fetches(...): ...
def test_no_credential_reaches_stdout_stderr_or_records(...): ...
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement**; add every new command to the CLAUDE.md Commands block and the local-edition guide. **Step 4: Run** files, full suite, `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Add greenbone commands and pull on the cycle timer"`

### Task 10: Dashboard: scanner status and upload

**Files:**
- Modify: `ui/dashboard_view.py` (infrastructure view), `scripts/local.py` (upload POST)
- Test: `tests/test_dashboard.py`, `tests/test_local_edition.py`

**Interfaces:**
- Produces: the infrastructure view shows, per chosen task: name, last pull time (both clocks via `stamp`), result (`imported`, `nothing new`, `failed: <error class>`), last imported report and what it changed (new, resolved, reopened, kept, unverifiable), skipped counts (log, below QoD, rejected, not finished); "No scan tasks chosen — nothing is imported" when the list is empty; enrichment last run and failures. A "last pull failed" state never reads as "no new findings". Upload form: `POST /upload` (`multipart/form-data`, one file field `report`, an `add_task` checkbox, the CSRF token; Host/Origin checks as `/settings`; body capped at `MAX_REPORT_BYTES`), parsed with `email.parser.BytesParser(policy=email.policy.HTTP)`; result shown on redirect. Same `import_upload` call as the command.

- [ ] **Step 1: Write failing tests**

```python
def test_infrastructure_shows_failed_pull_as_failed(): ...
def test_infrastructure_says_when_no_tasks_are_chosen(): ...
def test_skipped_counts_are_shown(): ...
def test_upload_imports_through_the_same_path(tmp_path): ...
def test_upload_rejects_cross_origin_and_oversized(tmp_path): ...
def test_upload_from_unchosen_task_without_add_task_shows_the_refusal(tmp_path): ...
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** files, full suite, `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Show scanner status on the dashboard and accept report uploads"`

### Task 11: End-to-end lifecycle and the manual real-gvmd check

**Files:**
- Create: `tests/test_lifecycle_greenbone.py`, `docs/development/greenbone.md`
- Modify: `README.md` (local-edition section: one paragraph pointing at the guide)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the lifecycle test** over a fake gvmd (Unix socket, from Task 6's fixture) and fake models: cycle 1 pulls the baseline and triages (including one no-CVE finding, decided with "not applicable" in the proposer's input); cycle 2 pulls a report where the CVE-2021-44228 finding is absent on a covered host → resolved and its ticket closed by chase; cycle 3 a report where it is back → regressed; a second task's report on the same host changes nothing; a Stopped report is skipped and shown; no credential appears anywhere in the workspace files.
- [ ] **Step 2: Run** — make it pass with fixes in the owning modules only.
- [ ] **Step 3: Write `docs/development/greenbone.md`:** setup (socket vs TLS, CA file, environment variables, choosing tasks), what is imported and skipped and why, how closure works, and the manual end-to-end check against a real gvmd ("never commit a real report").
- [ ] **Step 4: Run** full suite and `verify_local_install` — PASS.
- [ ] **Step 5: Commit** `git commit -m "Prove the Greenbone lifecycle end to end and document setup"`

## Spec coverage check (self-review)

| Spec requirement | Task |
|---|---|
| Pull from chosen tasks, fail closed when none | 8, 9 |
| Upload fallback, same path, add-task with confirmation | 8, 9, 10 |
| Unix socket and verified TLS, env credentials, read-only GMP | 6, 7 |
| DOCTYPE refusal, size bound, typed parsing | 1, 6 |
| Asset key from Greenbone host ID, IP fallback visible | 2 |
| Finding key host + OID + port; multi-CVE; log skip; QoD floor | 2, 4 |
| No-CVE findings triaged; "not applicable" wording; limited evidence | 4 |
| No-CVE high/critical acceptance needs a person | 4 |
| Per-task ownership of findings | 3 |
| Newest-only baseline; one report per task per cycle | 8 |
| Only Done reports; unfinished hosts not covered | 1, 2, 8 |
| Demo and real never mix | 8 |
| update-enrichment, internet only there, auto off by default | 5, 9 |
| Settings Scanner section, typed task IDs, test connection | 7 |
| Observability on dashboard and logs | 8, 10 |
| Synthetic fixtures; manual real-gvmd check documented | 1, 11 |

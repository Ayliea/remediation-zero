# Business Context and Ranking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the owner say what matters to the business (labels on hosts, by questions, CSV or suggesting rules), and make triage, a fixed floor, and deadlines follow it.

**Architecture:** Host facts (criticality, internet-facing, environment, sensitive data) with provenance live on the asset document; labels, rules, suggestion decisions and CSV mappings live in a new `context` workspace file written only by a new `context` stage. Pure logic sits in `tools/context*.py`; the cycle reads the facts, applies a deterministic floor after adjudication, and moves an open SLA clock's deadline instead of restarting it. Pages are server-rendered forms under Settings → Context, wired like the accounts forms.

**Tech Stack:** Python 3.12, standard library only for the local edition (`python3 -S`), SQLite through `tools/sqlite_docstore.py`, pytest offline suite.

**Spec:** `docs/superpowers/specs/2026-10-29-business-context-design.md`

## Global Constraints

- Standard library only in everything the local edition imports; must run under `python3 -S`.
- Every persisted business time comes from `SimClock`; every new record carries `real_ts` and `sim_ts`.
- Owner only: setting facts, labels, rules, suggestion decisions, uploads. A tech sees the Context page read-only. New access action `manage_context`.
- Every change writes an audit row through `Accounts` in the same request; detail keys must be allowed by `tools/account_store.ALLOWED_DETAIL_KEYS`.
- Custom label names: at most 40 characters of letters, digits, spaces and `- _ .`; screened by the configured guard when saved, refused if blocked.
- Fixed floor: Crown jewels (`criticality == "high"`) and any CVE in CISA KEV → severity never below `high`; SLA ≤ 14 days, or days until the KEV due date when that date is in the future and sooner. KEV unknown → no floor, and the record says so.
- Re-rank: open findings on a host whose effective facts changed after the finding's newest decision. New due = max(original start + new SLA days, re-rank time + 1 day). Moves in both directions; no move record when due is unchanged.
- Unmatched CSV rows → pending suggestions, expire after 90 days, cap 5,000.
- Tests use synthetic data only: `.invalid` / `example` host names, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
- Never add Claude attribution to commit messages. Commits are signed; do not touch git config.

## Rulings made while planning (spec gaps)

- **KEV due dates in the past.** Most KEV entries' due dates are years old; using them would set a 1-day SLA on nearly everything. The KEV date tightens the floor only when it is in the future. Cost if wrong: floored SLAs are 14 days where the owner wanted sooner.
- **CSV limits.** The Greenbone 64 MB limit is for XML reports. CSV is capped at 5 MB and 10,000 data rows. Cost if wrong: a very large asset export must be split.
- **No re-confirm for context changes.** Like the Settings form, context forms need the owner role and the form token, not a fresh password + code. Cost if wrong: one extra step added later.
- **Breached clocks are not moved.** A re-rank on a finding already past its deadline records "already overdue, not moved". Cost if wrong: a lowered label cannot un-breach a finding.
- **Suggestions are computed on read.** Rule suggestions are worked out from hosts, rules and stored decisions when the page renders; only decisions (approve/deny) and unmatched CSV rows are stored.

## Review Focus

1. A CSV saved by Excel: UTF-8 BOM, `;` delimiter in some locales, CRLF, quoted cells. Expect it to parse; a delimiter guess between `,` `;` and tab. (Task 3.)
2. Host names differing by case or a trailing dot (`FILES.example.invalid.`). Expect a match. (Task 3.)
3. A custom label deleted while hosts carry it, or while it is the reason a fact is "yes". Expect the effect to stop and the host to be re-ranked. (Task 1.)
4. An owner who is demoted between loading the page and posting. Expect 403 and nothing written. (Task 7.)
5. A finding with several CVEs where only one is in KEV, and a finding with no CVE on a Crown-jewels host. Expect floor for the first, none for the second. (Task 5.)

---

### Task 1: Facts, labels and provenance (pure logic)

**Files:**
- Create: `tools/context.py`
- Test: `tests/test_context.py`

**Interfaces:**
- Produces:
  - `FACTS = ("criticality", "internet_facing", "environment", "sensitive_data")`
  - `BUILTIN_LABELS`: `{"crown_jewels": ("criticality", "high"), "internet_facing": ("internet_facing", True), "production": ("environment", "production"), "sensitive_data": ("sensitive_data", True)}` plus the lowering statements `development` → (`environment`, `"development"`) and `not_internet_facing` → (`internet_facing`, `False`).
  - `EFFECTS = ("crown_jewels", "sensitive_data", "grouping")` for custom labels.
  - `@dataclass(frozen=True) class Provenance: source: str; account: str; real_ts: float; sim_ts: float` with `source in {"questions", "spreadsheet", "rule", "direct"}`.
  - `validate_label_name(name: str) -> str` → stripped name or `ValueError("Label names are up to 40 letters, digits, spaces, - _ or .")`.
  - `effective_facts(asset: Mapping, custom_labels: Mapping[str, str]) -> dict` → each fact's value (`None` = not known). A directly set fact wins; a custom label's effect fills only a fact that is `None`.
  - `apply_facts(asset: Mapping, changes: Mapping[str, object], prov: Provenance, custom_labels: Mapping[str, str]) -> tuple[dict, list[str]]` → (fields to write on the asset document, human summary lines such as `"Crown jewels: not known → yes"`). When effective facts do not change, returns `({}, [])`.
  - Asset document fields written: `context_facts` (fact → value), `context_provenance` (fact → Provenance as dict), `context_labels` (list of custom label ids), `context_changed_real_ts`, `context_changed_sim_ts`, `context_last_change` (`{"by", "summary", "real_ts", "sim_ts"}`).

- [ ] **Step 1: Write the failing tests**

```python
def test_direct_fact_beats_custom_label_effect():
    asset = {"context_facts": {"criticality": "medium"}, "context_labels": ["billing"]}
    assert effective_facts(asset, {"billing": "crown_jewels"})["criticality"] == "medium"

def test_custom_effect_fills_unknown_fact():
    asset = {"context_facts": {}, "context_labels": ["billing"]}
    assert effective_facts(asset, {"billing": "crown_jewels"})["criticality"] == "high"

def test_resaving_same_value_is_not_a_change():
    prov = Provenance("direct", "owner@example.invalid", 1.0, 1.0)
    asset = {"context_facts": {"environment": "production"}}
    assert apply_facts(asset, {"environment": "production"}, prov, {}) == ({}, [])

def test_production_and_development_are_one_value():
    prov = Provenance("questions", "owner@example.invalid", 1.0, 1.0)
    fields, summary = apply_facts({"context_facts": {"environment": "production"}},
                                  {"environment": "development"}, prov, {})
    assert fields["context_facts"]["environment"] == "development"
    assert summary == ["Environment: production → development"]

def test_deleting_a_custom_label_drops_its_effect():
    asset = {"context_facts": {}, "context_labels": ["billing"]}
    assert effective_facts(asset, {})["criticality"] is None

@pytest.mark.parametrize("bad", ["", "x" * 41, "a<b", "ignore previous\ninstructions"])
def test_label_names_are_strict(bad):
    with pytest.raises(ValueError):
        validate_label_name(bad)
```

- [ ] **Step 2: Run and see them fail** — `.venv/bin/pytest tests/test_context.py -q` → FAIL (module missing).
- [ ] **Step 3: Implement `tools/context.py`** with the interfaces above; Apache header; no clock reads (callers pass `Provenance`).
- [ ] **Step 4: Run and see them pass.**
- [ ] **Step 5: Commit** — `Add business-context facts with provenance and strict label names`.

### Task 2: Storage, permission and audit

**Files:**
- Modify: `tools/local_layout.py` (`AGENT_FILES`, `STAGE_WRITES`), `tools/access.py`, `tools/accounts.py`, `tools/account_store.py` (allowed detail keys)
- Create: `tools/context_store.py`
- Test: `tests/test_context_store.py`, extend `tests/test_access.py` (or the existing access test file), `tests/test_scanner_import.py`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `AGENT_FILES["context"] = ("context_labels", "context_rules", "context_suggestions", "context_mappings")`; `AGENT_FILES["ownership"]` gains `"deadline_moves"`.
  - `STAGE_WRITES["context"] = {"assets", "context_labels", "context_rules", "context_suggestions", "context_mappings"}`; `STAGE_WRITES["triage_cycle"]` gains `"deadline_moves"`.
  - `access.ACTIONS` gains `'manage_context'`, owner only.
  - `accounts.CONTEXT_EVENTS = ("context_facts_set", "context_label_added", "context_label_removed", "context_rule_saved", "context_rule_removed", "context_suggestion_decided", "context_upload_applied")`; `Accounts.record_context_change(actor_id, event, *, detail: dict, via, source) -> None`, refusing an actor without `manage_context`. Detail keys: `assets` (count), `facts` (list of fact names), `label`, `rule`, `decision`. Never host names or CSV cell text.
  - `class ContextWriter(docs, clock)`:
    - `set_facts(asset_ids: list[str], changes: dict, *, source: str, account: str) -> list[str]` (asset ids whose effective facts changed)
    - `add_label(name: str, effect: str, *, account: str) -> str` (label id), `remove_label(label_id, *, account) -> list[str]` (assets affected; their `context_changed_*` is bumped)
    - `tag(asset_ids, label_id, *, account)`, `untag(asset_ids, label_id, *, account)`

- [ ] **Step 1: Write the failing tests**
  - `test_tech_may_not_manage_context`: `access.allowed('tech', 'manage_context') is False`, owner True.
  - `test_only_context_stage_writes_context_collections`: a `docs_for("dashboard")` write to `context_labels` raises `PermissionError`; `docs_for("context")` write succeeds.
  - `test_set_facts_bumps_marker_only_on_change`: second identical `set_facts` returns `[]` and leaves `context_changed_sim_ts` unchanged.
  - `test_record_context_change_refuses_tech` and `test_context_audit_detail_has_no_host_names` (a `detail` with `host` key raises `ValueError`).
  - `test_scanner_import_keeps_context_fields`: import a report over an asset that has `context_facts`; the fields survive (extends existing import test).
- [ ] **Step 2: Run, see failures.**
- [ ] **Step 3: Implement.** Existing workspaces gain the `context.sqlite3` file through `init()`, created 0600 like the others.
- [ ] **Step 4: Run focused tests plus `tests/test_local_layout*.py`.**
- [ ] **Step 5: Commit** — `Store business context in its own file, owner-only and audited`.

### Task 3: Spreadsheet import and host matching

**Files:**
- Create: `tools/context_import.py`
- Test: `tests/test_context_import.py`

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces:
  - `MAX_CSV_BYTES = 5 * 1024 * 1024`, `MAX_CSV_ROWS = 10_000`
  - `normalise_host(name: str) -> str` (lower case, strip one trailing dot)
  - `match_host(hosts: list[Mapping], key: str) -> tuple[Optional[str], str]` → (asset id or None, `"matched" | "ambiguous" | "unmatched"`). Full name match on `hostname`; short name only if exactly one host's first label equals it; IP only if exactly one asset has it.
  - `read_csv(data: bytes) -> tuple[list[str], list[list[str]]]` (header, rows): strips a UTF-8 BOM, sniffs `,` `;` or tab, refuses over the limits with `ValueError` in plain words.
  - `@dataclass Mapping_: host_column: str; fact_columns: dict[str, str]` (fact → column). Values read as yes/no/blank (`yes, y, true, 1, x` / `no, n, false, 0` / empty → no change).
  - `preview(header, rows, mapping, hosts) -> Preview` with `changes: dict[asset_id, dict]`, `problems: list[str]` (ambiguous rows, rows that disagree about one host, unknown values; each names the row number, never echoes more than the host cell escaped by the page), `unmatched: list[tuple[str, dict]]`.
  - `ContextWriter.apply_upload(preview, *, account) -> int` (Task 2 writer gains it): writes changes with source `spreadsheet`; stores each unmatched row in `context_suggestions` (`kind: "row"`, host key, facts, `expires_sim_ts = now + 90 days`), refusing beyond 5,000 pending; saves the mapping in `context_mappings` under id `default`.

- [ ] **Step 1: Write the failing tests** — `test_excel_csv_with_bom_and_semicolons`, `test_case_and_trailing_dot_match`, `test_short_name_needs_one_match`, `test_ip_shared_by_two_assets_is_ambiguous`, `test_conflicting_rows_are_problems_not_changes`, `test_unmatched_rows_become_suggestions_with_90_day_expiry`, `test_suggestion_cap_5000`, `test_over_5mb_refused`, `test_mapping_remembered`.
- [ ] **Step 2–4: Fail, implement, pass.**
- [ ] **Step 5: Commit** — `Import business context from a CSV with a preview and host matching`.

### Task 4: Rules and suggestions

**Files:**
- Create: `tools/context_rules.py`
- Test: `tests/test_context_rules.py`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces:
  - `@dataclass(frozen=True) class Rule: rule_id: str; kind: str ("cidr" | "suffix"); pattern: str; facts: dict` — `validate_rule` uses `ipaddress.ip_network(strict=False)` for CIDR and `normalise_host` for suffixes.
  - `suggestions(hosts, rules, decided: Mapping[tuple[str, str], str], pending_rows, now_sim_ts) -> list[Suggestion]` where `Suggestion(rule_id_or_row_id, asset_id, facts)`; excludes hosts already decided for that rule, hosts whose facts already equal the suggestion, and expired rows. A pending row whose host key now matches exactly one host becomes a suggestion.
  - A fact set by hand on the host after a row was stored drops that fact from the row's suggestion.
  - `ContextWriter.decide(source_id, asset_id, approve: bool, *, account)`; approve applies facts with source `rule`; denial is stored as `(rule_id, asset_id) → "denied"`.
  - `ContextWriter.save_rule(rule, *, account)`. Pending suggestions are computed on read, so editing a rule replaces its pending suggestions; approvals already made stay (they are facts) and denials stay. Removing a rule removes its denials.

- [ ] **Step 1: Write the failing tests** — `test_rule_never_applies_itself` (after `save_rule`, asset facts unchanged), `test_each_host_approved_or_denied`, `test_denied_host_stays_denied`, `test_row_suggestion_appears_when_host_is_scanned`, `test_expired_row_not_suggested`, `test_hand_set_fact_supersedes_row`.
- [ ] **Step 2–4: Fail, implement, pass.**
- [ ] **Step 5: Commit** — `Suggest business context from rules; the owner approves each host`.

### Task 5: Triage input and the fixed floor

**Files:**
- Modify: `tools/inference.py` (`render_finding`), `prompts/triage.md`, `tools/adjudication.py` (`Adjudication.floor`), `tools/decisions.py`, `engine/triage_cycle.py` (`_one_finding`, `_assign`), readers of severity: `tools/metrics.py:86`, `tools/delivery.py:172-174`, `ui/dashboard_view.py:52-126`, `engine/sweep.py:101`, `ui/app.py:518`
- Create: `tools/context_floor.py`
- Test: `tests/test_context_floor.py`, extend `tests/test_inference*.py`, `tests/test_decisions*.py`

**Interfaces:**
- Consumes: Task 1 `effective_facts`.
- Produces:
  - `render_finding` ASSET block reads `effective_facts`: `criticality`, `environment`, `internet_facing`, new `sensitive_data`, and `business_labels` (custom label names, which pass the strict name rule). `None` renders `not known`.
  - `prompts/triage.md` "Asset context" section: adds sensitive data, and "A fact shown as not known is missing context: report it, do not assume low."
  - `FLOOR_SLA_DAYS = 14`; `apply_floor(adjudication, facts: Mapping, enrichment, now_sim_ts: float) -> Adjudication` returns the adjudication with `floor` set: `{"applied": bool, "reason": str, "severity": str, "sla_days": int}` or `{"applied": False, "reason": "KEV list not available"}`; untouched (`floor=None`) when the host is not Crown jewels or no CVE is in KEV.
  - `effective_severity(doc: Mapping) -> Optional[str]` and `effective_sla_days(doc: Mapping) -> Optional[int]` in `tools/decisions.py`: floor values when applied, else proposed.
  - Decision document gains `floor` (absent when `None`); `restore` reads it back.

- [ ] **Step 1: Write the failing tests**

```python
def test_floor_raises_medium_to_high_with_14_days():
    out = apply_floor(adj(severity="medium", sla=60), {"criticality": "high"},
                      enr(in_kev=True, kev_due_date="2020-01-01"), NOW)
    assert out.floor == {"applied": True, "severity": "high", "sla_days": 14,
                         "reason": "raised to High: Crown jewels and actively exploited"}

def test_future_kev_due_date_tightens_sla():
    out = apply_floor(adj(severity="critical", sla=30), {"criticality": "high"},
                      enr(in_kev=True, kev_due_date=date_in_days(NOW, 5)), NOW)
    assert out.floor["severity"] == "critical" and out.floor["sla_days"] == 5

def test_no_floor_when_kev_unknown():
    out = apply_floor(adj(severity="low", sla=90), {"criticality": "high"},
                      enr(in_kev=False, kev_checked=False), NOW)
    assert out.floor == {"applied": False, "reason": "KEV list not available"}

def test_no_floor_without_crown_jewels():
    assert apply_floor(adj(), {"criticality": None}, enr(in_kev=True), NOW).floor is None

def test_no_cve_crown_jewel_is_not_floored(): ...
def test_floor_survives_restore(): ...
def test_assignment_uses_floored_sla(): ...
def test_render_shows_sensitive_data_and_not_known(): ...
```

- [ ] **Step 2–4: Fail, implement, pass.** In `_one_finding`, apply the floor to the adjudication before `writer.record`; log `floor_applied` with finding and cycle ids.
- [ ] **Step 5: Run every test touching decisions, delivery, metrics, dashboard and sweep.**
- [ ] **Step 6: Commit** — `Give triage the owner's business context and floor Crown jewels under active exploitation`.

### Task 6: Re-ranking and moving deadlines

**Files:**
- Modify: `engine/triage_cycle.py` (`pending_findings`), `tools/assignments.py` (`record`, `_start_sla`), `engine/chase.py` and `tools/delivery.py` (the moved-deadline comment)
- Test: `tests/test_rerank.py`

**Interfaces:**
- Consumes: Tasks 2 and 5.
- Produces:
  - `pending_findings` also returns open findings whose asset's `context_changed_sim_ts` is newer than the finding's newest decision `sim_ts`, when that decision was ratified or approved (held, human-queue and rejected findings pick up context at their next normal triage).
  - `AssignmentWriter.record(..., context_change: Optional[Mapping] = None)`: when an SLA clock for the finding exists with `status == "open"`, compute `new_due = max(started_sim_ts + sla_days * 86400, now.sim_ts + 86400)`; if it differs from `due_sim_ts`, update `due_sim_ts`, `sla_days`, set `last_move_id`, and write `deadline_moves/<finding_id>-c<cycle>`: `{finding_id, cycle, old_due_sim_ts, new_due_sim_ts, asset_id, changed_by, change_summary, real_ts, sim_ts}`. A `breached` clock is left alone and the move record says `"already overdue, not moved"`. Other statuses keep today's restart behaviour.
  - Chase delivers one comment per move id: `"**Deadline moved** · cycle N\n\nThe fix-by date moved from YYYY-MM-DD to YYYY-MM-DD because {changed_by} changed this host's business context ({summary}) on YYYY-MM-DD."` It supersedes an older undelivered reminder, as other lifecycle events do.

- [ ] **Step 1: Write the failing tests** — `test_label_change_reranks_open_findings_once` (two changes before a cycle → one new decision), `test_unchanged_host_not_rerun`, `test_deadline_shortened_keeps_original_start`, `test_deadline_never_less_than_one_day_away`, `test_deadline_can_lengthen`, `test_same_due_writes_no_move`, `test_breached_clock_not_moved`, `test_resumed_cycle_moves_once` (idempotency), `test_moved_deadline_comment_text`.
- [ ] **Step 2–4: Fail, implement, pass.**
- [ ] **Step 5: Run `tests/test_idempotency.py tests/test_clock.py` and the chase/delivery tests.**
- [ ] **Step 6: Commit** — `Re-rank open findings when business context changes and record each moved deadline`.

### Task 7: Settings → Context page and routes

**Files:**
- Create: `ui/context_view.py`, `scripts/local_context.py`
- Modify: `ui/settings_view.py` (`SECTIONS` gains `'context': 'Context'`), `scripts/local.py` (`POST_ACTIONS`, body limits, GET section), `scripts/local_auth.py` only if a shared helper is needed
- Test: `tests/test_context_routes.py`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  - `PATHS = {'/context/facts', '/context/questions', '/context/label', '/context/label-remove', '/context/tag', '/context/upload', '/context/upload-apply', '/context/rule', '/context/rule-remove', '/context/decide'}`; `ACTION = 'manage_context'`. Plain HTML forms with the form token (no page script, so no CSP hash change). `/context/upload` is multipart, limited to `MAX_CSV_BYTES + UPLOAD_OVERHEAD`, and returns the preview page; `/context/upload-apply` carries a server-held preview id bound to the session, valid 10 minutes, so the CSV is not re-posted.
  - Writes run under `serial`, through `docs_for("context")`, and resolve the session again just before writing (a demoted owner gets 403, nothing written).
  - Guard check for a new custom label name runs with `serial` released, like a connection test; blocked → the page says "That label name was refused by the safety check. Choose another." Without a configured guard, the strict name rule alone applies.
  - `render_context(state, token, *, owner: bool, message='') -> str`: label tiles with counts; the three ways in (questions flow of four screens; upload; rules); pending suggestions listing each host with Approve / Deny; host list (unlabeled first, with count) showing labels and "where it came from" (source, account, date). Tech view: same page, no forms.
  - Questions copy, verbatim from the spec: "Which of these would stop the business if they went down?", "Which can be reached from the internet?", "Which hold patient, client or payment records?", "Which are for testing or development only?" Unticked hosts stay not known.

- [ ] **Step 1: Write the failing tests** — `test_tech_sees_context_without_forms`, `test_tech_post_is_403_before_body_read`, `test_owner_sets_fact_and_audit_row_written`, `test_demoted_between_load_and_post_writes_nothing`, `test_upload_preview_then_apply`, `test_preview_id_bound_to_session_and_expires`, `test_blocked_label_name_refused`, `test_page_escapes_csv_host_cells`, `test_questions_untouched_hosts_stay_not_known`.
- [ ] **Step 2–4: Fail, implement, pass.**
- [ ] **Step 5: Commit** — `Add Settings > Context: labels, questions, CSV upload and rule suggestions`.

### Task 8: Dashboard nudge, finding view and docs

**Files:**
- Modify: `ui/dashboard_view.py`, `engine/snapshot.py` (counts and per-finding context), `docs/development/local-edition.md`
- Test: extend `tests/test_dashboard_view*.py`, `tests/test_snapshot*.py`

**Interfaces:**
- Consumes: Tasks 1, 5, 6.
- Produces:
  - Snapshot gains `context_unknown_hosts: int` and, per finding, `labels`, `floor`, `deadline_moves`.
  - Dashboard nudge when `context_unknown_hosts > 0`: "N hosts have no business context — label them" linking to `/?view=settings&section=context` (owner) or saying "Ask the owner to label them" (tech).
  - Finding view: host labels; the floor line when applied; each deadline move in plain words; the recommendation's business reason ("This is {host}, labeled {labels}.") shown above the remediation steps.
  - Docs: a "Business context" section in `docs/development/local-edition.md` describing the page, the floor and re-ranking. No README or public docs change.

- [ ] **Step 1–4: Tests first (`test_nudge_counts_unknown_hosts`, `test_finding_view_shows_floor_and_moves`), implement, pass.**
- [ ] **Step 5: Commit** — `Show business context on the dashboard and finding view`.

### Task 9: Finish

- [ ] Full suite once: `.venv/bin/pytest -q` → all pass.
- [ ] `python3 -S -m scripts.verify_local_install` → PASS.
- [ ] One short scripted browser check on the lab: owner labels a host Crown jewels, runs a cycle, sees the moved deadline; tech sees the page read-only.
- [ ] One whole-branch review (Sonnet; split by area, each diff ≤ ~100 KB).
- [ ] Ask the owner before merging and pushing.

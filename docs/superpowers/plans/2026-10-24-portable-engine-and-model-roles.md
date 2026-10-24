# Portable Engine and Model Roles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the full remediation lifecycle from one engine in both editions, with models configured by role over three request formats.

**Architecture:** Part A adds model roles behind a small adapter interface and moves the
standard-library parts of `tools/review_models.py` into `tools/inference.py`, so the
cloud path already uses roles before anything else moves. Part B adds a neutral
document-store API that mirrors the slice of Firestore the writers already use, a
standard-library SQLite implementation of it, and an `engine/` package holding one
stage function per agent process. Cloud scripts and workers become thin wiring
around those stages. Contract tests run every port implementation against the same
assertions.

**Tech Stack:** Python 3.12, standard library only for `engine/`, the local
implementations and `scripts/local.py`. Firestore, `google-genai` and FastAPI
remain in the cloud wiring only. pytest.

**Spec:** `docs/superpowers/specs/2026-10-24-portable-engine-and-model-roles-design.md` (commit `b024292`)

## Global Constraints

- No new dependencies. `engine/`, `tools/inference.py`, `tools/models/`, `tools/model_transport.py`, `tools/model_roles.py`, `tools/guardrail.py`, `tools/docstore.py` (neutral parts), `tools/sqlite_docstore.py`, `tools/local_layout.py`, `tools/local_memory.py` and `scripts/local.py` must import only the standard library and each other. Check with `python3 -S -c "import <module>"`.
- Every new module carries the repository's Apache 2.0 header.
- Prompts are files in `prompts/`; never inline instructions.
- Structured logs only: `json.dumps({"event": ..., "cycle_id": ..., "finding_id": ..., ...}, sort_keys=True)`.
- Every persisted lifecycle record carries `real_ts` and `sim_ts` from `SimClock`. No `datetime.now()` / `time.time()` for persisted business time.
- Every authoritative state change goes through `IdempotencyGuard` with keys from `derive_record(finding_id, action, cycle)`. Existing keys must not change.
- Cloud behavior is unchanged: command-line flags, log event names and fields, Firestore document shapes (except the decision fields added in Task 5), service accounts, and the chase-only GitHub token.
- Existing tests keep their assertions. A test may be edited only to retarget a monkeypatch to a symbol's new location, or to give a fake client the neutral sentinels of Task 9. Say which in the commit message.
- Model transport rules, unchanged from `tools/model_endpoint.py`: HTTPS unless the host is loopback; no redirects; no inherited proxies; no URL credentials, query or fragment; input ≤ 32768 bytes; response ≤ 65536 bytes; socket timeout 60 s; `max_tokens` 2048.
- API keys only from environment variables `RZ_PROPOSER_API_KEY`, `RZ_REVIEWER_API_KEY`, `RZ_SUMMARIZER_API_KEY`, `RZ_GUARD_API_KEY`; `RZ_MODEL_API_KEY` is the proposer fallback. Never written to settings, records or logs.
- Commits are signed (`git commit -S`) with no Claude attribution trailer (the user's home CLAUDE.md forbids it; a commit-msg hook rejects it).
- The offline suite blocks the network (`tests/offline_guard.py`). Nothing in this plan calls a real model or a cloud service.

## Review Focus

1. **Settings saved by the current release** (flat `endpoint` / `model` fields) must load as a proposer role with the other roles unset, not fail validation. Test in Task 4.
2. **Model output wrapped in a markdown fence or a sentence of prose** (common from Anthropic and local models, which have no JSON mode) must parse when a single JSON object is present and fail closed otherwise. Test in Task 3.
3. **Configuration changed between two runs of the same cycle** (new endpoint, model, family or same-family policy) must stop that cycle for human review with the existing `ValueError`, not loop or silently replay the old results. Test in Task 4.
4. **A first run or a partially copied workspace** (some per-agent SQLite files missing) must create the missing files before any read-only open, never crash on `unable to open database file`. Test in Task 11.
5. **Two local runs at once** (the interval scheduler and a manual `cycle`) must not double-apply any transition and must not fail with `database is locked` before the 10 s busy timeout. Test in Task 10.

---

# Part A — Model roles

Part A ends with: the cloud cycle running through role adapters with unchanged
behavior; decisions recording `review_independence`, `models` and
`same_family_policy`; and local Settings configuring four roles.

### Task 1: Shared model transport

**Files:**
- Create: `tools/model_transport.py`
- Modify: `tools/model_endpoint.py` (use the transport; keep `ModelEndpoint`'s public behavior)
- Test: `tests/test_model_transport.py`; `tests/test_model_endpoint.py` (if present) must pass unchanged

**Interfaces:**
- Produces:
  - `validate_endpoint(url: str) -> str`: returns the normalized URL (trailing `/` stripped). Raises `ValueError` with today's message, `'Use an HTTPS endpoint, or HTTP on loopback; no URL credentials, query or fragment'`.
  - `post_json(url: str, body: dict, headers: dict[str, str]) -> dict`: one POST with no proxies, no redirects and a 60 s timeout, reading at most 65537 bytes. HTTP 408, 429, 500, 502, 503 and 504, `URLError` and `TimeoutError` raise `CapacityError`. Any other HTTP error raises `ValueError('Model endpoint rejected request')`. A body over 65536 bytes, or one that isn't JSON, raises `ValueError`.
  - Constants `MAX_INPUT_BYTES = 32768`, `MAX_RESPONSE_BYTES = 65536`, `MAX_OUTPUT_TOKENS = 2048`, `TIMEOUT_SECONDS = 60`.

- [ ] **Step 1: Write failing tests** in `tests/test_model_transport.py`:
  - `test_rejects_plain_http_off_loopback`: `validate_endpoint("http://example.test/v1")` raises `ValueError`.
  - `test_allows_http_on_loopback`: covers `http://127.0.0.1:11434/v1/chat/completions` and `http://localhost:8080/x`.
  - `test_rejects_credentials_query_fragment`.
  - `test_overload_is_capacity`: for each code in `(408, 429, 500, 502, 503, 504)`, a stubbed opener raising `HTTPError(code)` makes `post_json` raise `CapacityError`.
  - `test_other_http_error_is_rejection`: 401 raises `ValueError` and not `CapacityError`.
  - `test_oversized_response_rejected`: a 65537-byte body raises `ValueError`.
  - `test_redirect_not_followed` and `test_proxy_env_ignored`, with `HTTPS_PROXY` set.

  Stub the network by monkeypatching `tools.model_transport._open`, the single function that builds the opener and calls `.open(request, timeout=60)`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_model_transport.py -v`. Expected: FAIL, module not found.
- [ ] **Step 3: Implement** `tools/model_transport.py` by moving the URL checks, the `NoRedirects` and `ProxyHandler({})` opener, and the error mapping out of `ModelEndpoint`. Make `ModelEndpoint.__init__` call `validate_endpoint` and `ModelEndpoint.propose` call `post_json`.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_model_transport.py tests/test_local_edition.py tests/test_local_settings.py -q` and `python3 -S -c "import tools.model_transport"`. Expected: all pass, and the import prints nothing.
- [ ] **Step 5: Commit** with `git commit -S -m "Move model transport rules into one shared module"`.

### Task 2: Request-format adapters

**Files:**
- Create: `tools/models/__init__.py`, `tools/models/openai_chat.py`, `tools/models/anthropic_messages.py`, `tools/models/gemini_api.py`
- Test: `tests/test_model_adapters.py`, with fixtures in `tests/fixtures/model_responses/` (one JSON file per format: success, refusal or incomplete, malformed)

**Interfaces:**
- Consumes: `post_json`, `validate_endpoint` and the constants from Task 1.
- Produces, in `tools/models/__init__.py`:
  - `class ChatAdapter(Protocol)`, with `complete(self, system: str, user: str, *, json_output: bool) -> str`.
  - `build_adapter(format: str, endpoint: str, model: str, api_key: str | None) -> ChatAdapter`, where `format` is one of `"openai_chat"`, `"anthropic_messages"` or `"gemini_api"`. Any other value raises `ValueError`.
  - `FORMATS = ("openai_chat", "anthropic_messages", "gemini_api")`.
- Wire contracts (the request body each adapter sends):
  - **openai_chat:** POSTs `{"model", "messages": [{"role":"system"}, {"role":"user"}], "stream": false, "max_tokens": 2048}`, adding `"response_format": {"type": "json_object"}` when `json_output`. Sends `Authorization: Bearer <key>` when a key is set. Accepts only `finish_reason == "stop"` with no `tool_calls`.
  - **anthropic_messages:** POSTs `{"model", "system", "messages": [{"role":"user","content":user}], "max_tokens": 2048}` with headers `x-api-key` and `anthropic-version: 2023-06-01`. Accepts only `stop_reason == "end_turn"` and returns the concatenated `text` blocks. Ignores `json_output`, because the prompt asks for JSON.
  - **gemini_api:** POSTs to `<endpoint>` (the full `…/models/<model>:generateContent` URL) with `{"systemInstruction": {"parts":[{"text":system}]}, "contents":[{"role":"user","parts":[{"text":user}]}], "generationConfig": {"maxOutputTokens": 2048}}`, adding `"responseMimeType":"application/json"` when `json_output`. Sends header `x-goog-api-key`. Accepts only `finishReason == "STOP"`.
  - Every adapter raises `ValueError("input exceeds 32768 bytes")` when `system + user` is over the limit, before any request.

- [ ] **Step 1: Write failing tests**, one class per format:
  - `test_request_body_matches_contract`: captures the `post_json` arguments and asserts the exact dict and headers above.
  - `test_returns_text_on_success`.
  - `test_incomplete_response_rejected` (`length` / `max_tokens` / `MAX_TOKENS` stop reasons raise `ValueError`).
  - `test_capacity_passes_through` (`post_json` raises `CapacityError`, and the adapter re-raises it unchanged).
  - `test_no_key_header_when_key_absent`.
  - `test_build_adapter_unknown_format_rejected`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_model_adapters.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the three adapters. Each is a small class taking `(endpoint, model, api_key)` and calling `validate_endpoint` in `__init__`.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_model_adapters.py -q && python3 -S -c "import tools.models"`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Add OpenAI-compatible, Anthropic Messages and Gemini adapters"`.

### Task 3: Shared inference over adapters; Vertex as one adapter

**Files:**
- Create: `tools/inference.py` (standard library only), `tools/vertex_models.py` (cloud only)
- Modify: `tools/review_models.py` (becomes a re-export shim: `from tools.inference import *` plus `from tools.vertex_models import VertexAdapter, vertex_client as _client`), `scripts/cycle.py`, `scripts/graph_cycle.py`
- Test: `tests/test_inference.py`; the existing `tests/test_review_models*.py`, `tests/test_cycle_script.py` and `tests/test_graph_cycle.py` pass

**Interfaces:**
- Consumes: `ChatAdapter` from Task 2.
- Produces in `tools/inference.py`:
  - Moved unchanged from `review_models`: `render_finding`, `FENCE_BEGIN`, `FENCE_END`, `_defang_fence`, `parse_proposal_payload`, `parse_review_text`, `_strip_fences`, `_with_backoff`, `_is_capacity`, `_load`, `MAX_MODEL_ATTEMPTS`, `BASE_BACKOFF_SECONDS`.
  - `propose(prompt_text: str, adapter: ChatAdapter, *, finding_id: str, retry: bool = True) -> Proposal`: system is `triage.md` and `json_output=True`. Parses with `extract_json_object(text)` and then `parse_proposal_payload`.
  - `review(prompt_text: str, adapter: ChatAdapter, *, retry: bool = True) -> Verdict`: the user turn is `reviewer.md + "\n\n---\n\n" + prompt_text`, with an empty system string, exactly as today.
  - `extract_json_object(text: str) -> dict`: strips a single surrounding code fence. If the remainder isn't a JSON object, it takes the substring from the first `{` to its matching last `}`, and only if that is the only top-level object. Otherwise it raises `ValueError`.
- Produces in `tools/vertex_models.py`:
  - `vertex_client() -> genai.Client`, which is today's `_client()`.
  - `VertexAdapter(client, model: str)`, implementing `ChatAdapter` through `client.models.generate_content`. When `system` is empty it sends no `system_instruction`, because Gemma has no system role. It uses `temperature=0.2` when `json_output` and `0.1` otherwise, matching today's triage and review values, and sets `response_mime_type="application/json"` when `json_output`.
- The `inference_fingerprint` signature is replaced in Task 4. Until then, keep the old one in `tools/inference.py`.

- [ ] **Step 1: Write failing tests** in `tests/test_inference.py`:
  - `test_propose_uses_triage_prompt_as_system_and_json` (fake adapter records its calls).
  - `test_review_prepends_instruction_with_empty_system`.
  - `test_extract_json_object_strips_fence`: the input is a fenced JSON block with `{"a":1}` inside.
  - `test_extract_json_object_from_prose`: `'Here is the result: {"a": 1} Thanks.'` gives `{"a": 1}`.
  - `test_extract_json_object_rejects_two_objects`: `'{"a":1} {"b":2}'` raises `ValueError`.
  - `test_extract_json_object_rejects_array`.
  - `test_inference_module_is_stdlib_only`: `subprocess.run([sys.executable, "-S", "-c", "import tools.inference"], cwd=REPO_ROOT, check=True)`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_inference.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the move. In `scripts/cycle.py` and `scripts/graph_cycle.py`, replace `rm.propose(rendered, model, genai_client, ...)` with `rm.propose(rendered, VertexAdapter(genai_client, model), ...)`, and do the same for `rm.review`. Log events don't change.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: full suite passes (719 plus the new tests).
- [ ] **Step 5: Commit** with `git commit -S -m "Run triage and review through adapters; Vertex is one of them"`.

### Task 4: Role configuration and the inference fingerprint

**Files:**
- Create: `tools/model_roles.py`
- Modify: `tools/local_settings.py` (schema v2), `tools/inference.py` (`inference_fingerprint`), `scripts/cycle.py` and `scripts/graph_cycle.py` (build roles from the environment), `.env.example`
- Test: `tests/test_model_roles.py`, `tests/test_local_settings.py`

**Interfaces:**
- Consumes: `build_adapter` and `FORMATS` (Task 2), `VertexAdapter` (Task 3; cloud only).
- Produces in `tools/model_roles.py`:
  - `ROLES = ("proposer", "reviewer", "summarizer", "guard")`.
  - `FAMILIES = ("gemini", "gemma", "llama", "claude", "gpt", "qwen", "mistral", "deepseek", "phi", "other")`.
  - `@dataclass(frozen=True) class RoleConfig`, with fields `role: str`, `format: str`, `endpoint: str`, `model: str`, `family: str`. Validated in `__post_init__`: `format` must be in `FORMATS` or equal `"vertex"`, `family` must be in `FAMILIES`, and the endpoint goes through `validate_endpoint` unless the format is `"vertex"`.
  - `suggest_family(model: str) -> str`: prefix rules on the lower-cased model name (`gemini`, `gemma`, `llama`, `claude`, `gpt`/`o1`/`o3`/`o4`, `qwen`, `mistral`/`mixtral`, `deepseek`, `phi`), falling back to `"other"`.
  - `@dataclass(frozen=True) class ModelRoles`, with `proposer: RoleConfig | None`, `reviewer: RoleConfig | None`, `summarizer: RoleConfig | None`, `guard: RoleConfig | None` and `same_family_policy: str` (`"wait"` | `"proceed"`).
  - `ModelRoles.independence(self) -> str`: `"unreviewed"` if there's no reviewer; `"same_family"` if the reviewer and proposer families are equal, or either family is `"other"`; otherwise `"cross_family"`.
  - `ModelRoles.provenance(self) -> dict`: `{role: {"format","model","family"}}` for each configured role. No endpoint, no key.
  - `ModelRoles.adapter(self, role: str, *, vertex_client=None) -> ChatAdapter`: reads the role's key env var (proposer falls back to `RZ_MODEL_API_KEY`).
  - `ModelRoles.from_env(environ) -> ModelRoles` for the cloud: `REASONING_MODEL` becomes a vertex proposer and `REVIEWER_MODEL` a vertex reviewer, with families from `suggest_family`. Optional overrides are `RZ_<ROLE>_FORMAT`, `RZ_<ROLE>_ENDPOINT`, `RZ_<ROLE>_MODEL` and `RZ_<ROLE>_FAMILY`. The summarizer defaults to the proposer's config. `same_family_policy="wait"`.
  - `ModelRoles.from_settings(settings: dict, environ) -> ModelRoles` for the local edition.
- `inference_fingerprint(rendered: str, roles: ModelRoles) -> str` replaces the old signature. It's a sha256 over `[rendered, roles.provenance(), the endpoint of each configured role, roles.same_family_policy, _load("triage.md"), _load("reviewer.md"), MAX_INPUT_BYTES, MAX_OUTPUT_TOKENS, REQUEST_TIMEOUT_MS]`.
- Local settings schema v2 (`tools/local_settings.py`): `{"version": 2, "roles": {role: {"format","endpoint","model","family"} | null}, "same_family_policy": "wait"|"proceed", "mode", "open_browser", "port", "cycle_interval_minutes": int (0 = off, 0–1440)}`.
  - `load` upgrades a v1 file, which has flat `endpoint` and `model`. A non-empty pair becomes `roles.proposer` with format `openai_chat` and the family from `suggest_family`. Every other role is `null` and the policy is `"wait"`.
  - `save` always writes v2. `DEFAULTS` becomes the v2 default.

- [ ] **Step 1: Write failing tests:**
  - `test_independence_cross_family`, `test_independence_same_family`, `test_independence_other_family_counts_as_same`, `test_independence_unreviewed`.
  - `test_provenance_has_no_endpoint_or_key` (set `RZ_REVIEWER_API_KEY=sk-test`; neither `"sk-test"` nor the endpoint string appears in `json.dumps(roles.provenance())`).
  - `test_from_env_matches_current_cloud`: `REASONING_MODEL=gemini-3.5-flash` and `REVIEWER_MODEL=gemma-4-26b-a4b-it-maas` give vertex roles with families `gemini` and `gemma`, independence `cross_family`.
  - `test_suggest_family` (parametrized over `llama3.1:8b` gives `llama`, `claude-sonnet-x` gives `claude`, `qwen2.5-coder` gives `qwen`, `my-model` gives `other`).
  - `test_fingerprint_changes_with_policy_family_endpoint_model` (four separate assertions).
  - `test_changed_roles_mid_cycle_requires_human_review`: run `InferenceJournal._ensure_context` once with roles A, then again for the same finding and cycle with roles B. The second raises `ValueError` containing `"changed within this cycle"`. **(Review Focus 3.)**
  - In `tests/test_local_settings.py`, add `test_v1_settings_upgrade_to_proposer_role` (a v1 file with `endpoint=http://127.0.0.1:11434/v1/chat/completions` and `model=llama3.1` loads as a proposer with format `openai_chat` and family `llama`, the other roles `None`, policy `"wait"`) **(Review Focus 1)**, and `test_save_never_writes_keys`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_model_roles.py tests/test_local_settings.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** In `scripts/cycle.py` and `scripts/graph_cycle.py`, build `roles = ModelRoles.from_env(os.environ)` once and pass `roles.adapter("proposer", vertex_client=...)` and `roles.adapter("reviewer", vertex_client=...)`. The fingerprint becomes `inference_fingerprint(rendered, roles)`.
  - **Note for the executor:** the fingerprint value changes. A cycle that is half-done at deploy time would stop for human review. Run the cloud deploy of this task only between cycles, never mid-cycle (record this in the commit message).
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Configure models by role; fingerprint covers every role"`.

### Task 5: Outcomes, the review gate and decision provenance

**Files:**
- Modify: `tools/adjudication.py`, `tools/decisions.py`, `tools/metrics.py`, `ui/dashboard_view.py`, `scripts/cycle.py`, `scripts/graph_cycle.py`
- Test: `tests/test_adjudication.py`, `tests/test_decisions.py`, `tests/test_metrics.py`, `tests/test_dashboard.py`

**Interfaces:**
- Produces:
  - `AdjudicationOutcome.UNREVIEWED = "unreviewed"` and `AdjudicationOutcome.HELD_FOR_APPROVAL = "held_for_approval"`. (`held_for_approval` is a plan-level addition to the spec. Every existing gate tests `== "ratified"`, so a distinct value fails safe. It is flagged to the owner.)
  - `adjudicate(finding, triage, review: Callable | None, max_capacity_retries=3, *, independence: str = "cross_family", same_family_policy: str = "wait") -> Adjudication`:
    - `review is None` returns `UNREVIEWED` after one triage, with note `"needs a person's review: no reviewer configured"`.
    - A ratification with `independence == "same_family"` and `same_family_policy == "wait"` returns `HELD_FOR_APPROVAL` with note `"same-family review: needs a person's approval"`, keeping the ratifying verdict in `verdicts`.
    - Everything else is unchanged.
  - `Adjudication` gains `review_independence: str = "cross_family"`, `models: Mapping = field(default_factory=dict)` and `same_family_policy: str = "wait"`.
  - `to_decision_document` writes those three fields. `DecisionWriter.restore` reads them with the same defaults when absent, so old documents restore unchanged.
  - `DecisionWriter.adjudicate_once(..., roles: ModelRoles)` passes `roles.independence()`, `roles.provenance()` and `roles.same_family_policy` through. Every outcome other than `RATIFIED` already writes a `human_queue` document. `UNREVIEWED` uses queue id `unreviewed-<decision_id>` with `kind: "unreviewed"`; `HELD_FOR_APPROVAL` uses `held-<decision_id>` with `kind: "same_family_review"`.
  - `metrics.summarize`: adds `"unreviewed"` and `"held_for_approval"` counts. They are excluded from `rejections`, `reviewer_unavailable` and the `ratification_rate` numerator; the denominator stays `len(decisions)`.
  - Dashboard labels: `unreviewed` shows "Not reviewed · needs a person"; `held_for_approval` shows "Reviewed by the same model family · waiting for your approval"; a ratified decision with `review_independence == "same_family"` shows "Reviewed by the same model family".

- [ ] **Step 1: Write failing tests:**
  - `test_no_reviewer_is_unreviewed_not_ratified`.
  - `test_same_family_wait_holds_ratification`.
  - `test_same_family_proceed_ratifies`.
  - `test_cross_family_ignores_policy`.
  - `test_capacity_still_never_rejection_under_same_family`.
  - `test_unreviewed_and_held_not_counted_as_rejections` (metrics).
  - `test_old_decision_document_restores_with_defaults`.
  - `test_held_and_unreviewed_never_pass_ratified_gate`: `scripts/cycle.py`'s assignment branch is not entered for either outcome; assert `AssignmentWriter.record` is not called.
  - `test_dashboard_labels_same_family`.
  - `test_cloud_decision_records_cross_family`: from-env roles give `review_independence == "cross_family"` on the document.
- [ ] **Step 2: Run** the four test files. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Record review independence; hold same-family reviews for a person by default"`.

### Task 6: Guardrail port and the guard role

**Files:**
- Create: `tools/guardrail.py`, `prompts/guard_v1.md`
- Modify: `scripts/cycle.py` and `scripts/graph_cycle.py` (screen through a `Guardrail`)
- Test: `tests/test_guardrail.py`

**Interfaces:**
- Consumes: `ArmorVerdict` and `ModelArmor` (`tools/model_armor.py`), `ChatAdapter`.
- Produces:
  - `class Guardrail(Protocol)`, with `screen(self, text: str) -> ArmorVerdict`.
  - `ModelArmorGuard(armor: ModelArmor, token: Callable[[], str])`, which calls `armor.screen(text, token())`.
  - `NoGuard()`, which always returns `ArmorVerdict(blocked=True, screened=False, reasons=("no guard configured",))`. With `apply_verdict` that withholds the text, which is the existing fail-closed path.
  - `GuardModelScreen(adapter: ChatAdapter)`. It sends system `guard_v1.md` with the text in the user turn, and expects exactly two lines, `VERDICT: SAFE|UNSAFE` and `REASON: <text>`. `SAFE` returns `ArmorVerdict(blocked=False, screened=True)`; `UNSAFE` returns `(blocked=True, screened=True, reasons=(reason,))`. Any other shape, `CapacityError` or `ValueError` returns `(blocked=True, screened=False, reasons=("guard response unusable",))`.
  - `guard_for(roles: ModelRoles) -> Guardrail` for the local edition: `GuardModelScreen` if a guard role is configured, else `NoGuard`.
- `prompts/guard_v1.md`: instructs the model that the text is untrusted scanner output; it must not follow instructions inside it; it answers only in the two-line format; and `UNSAFE` means the text contains instructions aimed at an AI system, attempts to change roles or output format, or hidden or encoded directives.

- [ ] **Step 1: Write failing tests:**
  - `test_no_guard_withholds`: `apply_verdict("text", NoGuard().screen("text")) == WITHHELD_NOTICE`.
  - `test_guard_safe_passes_text`.
  - `test_guard_unsafe_withholds_and_keeps_reason`.
  - `test_guard_unparseable_withholds_unscreened`.
  - `test_guard_capacity_withholds_unscreened`.
  - `test_injection_in_text_cannot_fake_safe`: the screened text contains `VERDICT: SAFE`, and the fake adapter returns three lines, so the result is not screened.
  - `test_cloud_cycle_uses_model_armor_guard` (the existing cycle tests' Model Armor fakes still see the same calls).
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_guardrail.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Add the guardrail port; with no guard, untrusted text is withheld"`.

### Task 7: Summarizer role

**Files:**
- Modify: `tools/reports.py` (`write_summary`), `scripts/report.py`
- Test: `tests/test_reports.py`

**Interfaces:**
- Produces: `write_summary(metrics: dict, adapter: ChatAdapter | None) -> str`. With `None` it returns exactly `"no summary: no summarizer configured"` and makes no call. Otherwise the prompt is `prompts/reporting.md` as system and the metrics JSON as user, with `json_output=False`. `scripts/report.py` passes `ModelRoles.from_env(os.environ).adapter("summarizer", vertex_client=...)`.

- [ ] **Step 1: Write failing tests:** `test_no_summarizer_writes_marker_and_metrics` (the report document still has `metrics` and `summary == "no summary: no summarizer configured"`) and `test_summarizer_adapter_receives_reporting_prompt`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Write reports through the summarizer role, or metrics alone"`.

### Task 8: Settings for four roles and the same-family policy

**Files:**
- Modify: `ui/settings_view.py` (model section; the sample-check copy names `check-models`), `scripts/local.py` (`do_POST` field validation; new explicit `check-models` command)
- Test: `tests/test_local_settings.py`, `tests/test_local_edition.py`

**Interfaces:**
- Consumes: settings v2 (Task 4), `FORMATS`, `FAMILIES`, `suggest_family`.
- Produces: the form fields `<role>_format`, `<role>_endpoint`, `<role>_model` and `<role>_family` for each role in `ROLES`, plus `same_family_policy`. Blank endpoint and model for a role means that role is not configured. The POST accepts exactly the field set for `section=model`, and the existing token, Origin, Host, content-type and 8192-byte checks stay unchanged.
- Copy (exact):
  - Policy label: "Same-family reviews".
  - Options: "Wait for a person (recommended)" and "Proceed automatically".
  - Explanation: "A model reviewing reasoning from its own family shares its blind spots."
  - Shown when no reviewer is configured: "No reviewer configured: every suggestion waits for a person."
  - Each role shows its key status from its env var as "present" or "not set", and never the value.
- `check-models` command: `python3 -S -m scripts.local check-models [--role ROLE]` is the explicit sample check, replacing `suggest-demo`'s role. For each configured role, or the named one, it sends the bundled synthetic example: the proposer through `propose`, the reviewer through `review` with a fixed sample proposal, the summarizer through `write_summary` with fixed sample metrics, and the guard through `GuardModelScreen.screen` with a fixed benign text. It prints one line per role, `<role>: ok` or `<role>: failed (<ExceptionClass>)`. It writes nothing to the workspace and never runs on startup, GET or save.

- [ ] **Step 1: Write failing tests:**
  - `test_settings_renders_four_role_blocks`.
  - `test_post_saves_roles_and_policy`.
  - `test_post_rejects_unknown_format` (400, nothing saved).
  - `test_post_rejects_http_hosted_reviewer` (400).
  - `test_settings_never_renders_key_values` (with `RZ_GUARD_API_KEY=secret-x` set, `"secret-x"` is not in the page).
  - `test_saving_makes_no_model_call` (the offline guard already fails any socket; assert the 303 response).
  - `test_check_models_reports_each_role` (fake adapters; one ok, one `CapacityError` gives `reviewer: failed (CapacityError)`; the workspace files are unchanged).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Then run `curl -s http://127.0.0.1:8095/dashboard` on the dev server to confirm the console still renders.
- [ ] **Step 5: Commit** with `git commit -S -m "Configure proposer, reviewer, summarizer and guard in Settings"`.

---

# Part B — Portable engine

Part B ends with: `python3 -S -m scripts.local seed|cycle|rescan|exception|approve`
running the full lifecycle on SQLite; the cloud scripts and workers calling the same
`engine/` stages; and contract tests holding both storage implementations to one
set of assertions.

### Task 9: Neutral document-store API and the Firestore adapter

**Files:**
- Create: `tools/docstore.py`
- Modify (imports only, logic unchanged): `tools/decisions.py`, `tools/assignments.py`, `tools/tickets.py`, `tools/exception_store.py`, `tools/scan_store.py`, `tools/reports.py`, `tools/finding_lookup.py`, `tools/delivery.py`. Each must import no `google.*` at module level.
- Test: `tests/test_docstore_firestore_adapter.py`; all existing writer tests

**Interfaces:**
- Produces in `tools/docstore.py` (stdlib-only names first):
  - Exceptions: `AlreadyExists(Exception)`, `FailedPrecondition(Exception)`, `NotFound(Exception)`.
  - Transforms: `DELETE_FIELD` (sentinel), `ArrayUnion(values: list)`, `Increment(n: int | float)`.
  - Queries: `FieldFilter(field_path: str, op_string: str, value)` (only `"=="` is supported); `ASCENDING`, `DESCENDING`.
  - `class DocStore(Protocol)`, with `collection(name) -> CollectionRef` and `batch() -> WriteBatch`. A `CollectionRef` supports `document(id)`, `where(filter=FieldFilter)`, `order_by(field, direction=ASCENDING)`, `limit(n)`, `stream()` and `count()`. A `count()` result's `.get()` returns `[[Aggregation(value: int)]]`, which keeps `ui/app.py`'s `count().get()[0][0].value` working. A `DocumentRef` supports `get() -> Snapshot(id, exists, to_dict(), update_time)`, `create(data)`, `set(data, merge=False)`, `update(data)` and `delete()`. A `WriteBatch` supports `create`, `set`, `update`, `delete` and `commit()`, all atomic.
  - `FirestoreDocStore(client)`: wraps a `firestore.Client` lazily, importing `google.cloud.firestore` inside the constructor. It translates the neutral transforms and filters to Firestore's, and Firestore's `AlreadyExists` / `FailedPrecondition` / `NotFound` to the neutral exceptions.
- Writers keep `client=` parameters. When none is passed they build `FirestoreDocStore(firestore.Client())` lazily inside `__init__`, never at import.

- [ ] **Step 1: Write failing tests:**
  - `test_writers_import_without_google` (for each of the eight modules, `python3 -S -c "import tools.<m>"` succeeds).
  - `test_adapter_translates_array_union_increment_delete_field` (against a recording stand-in for the Firestore client).
  - `test_adapter_translates_already_exists`.
- [ ] **Step 2: Run.** Expected: FAIL (the `-S` imports fail on `google`).
- [ ] **Step 3: Implement.** Replace `from google.cloud import firestore` and `google.api_core.exceptions` imports in the writers with `tools.docstore` names. Where a test fake checks a Google sentinel by type, give the fake the neutral sentinel instead, and name the file in the commit message.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: pass. Then run `FIRESTORE_EMULATOR_HOST=127.0.0.1:8787 .venv/bin/python -m scripts.verify_recovery_emulator` if an emulator is running (see `docs/development/emulator-validation.md`); if not, say so in the commit message.
- [ ] **Step 5: Commit** with `git commit -S -m "Give the writers a neutral document-store API"`.

### Task 10: SQLite document store and the contract suite

**Files:**
- Create: `tools/sqlite_docstore.py`, `tests/test_docstore_contract.py`
- Test: the contract suite, parametrized over implementations

**Interfaces:**
- Consumes: the `tools/docstore.py` protocol and names.
- Produces: `SQLiteDocStore(files: Mapping[str, Path], *, writable: frozenset[str] | None = None)`. `files` maps each collection name to its database file.
  - One connection per store attaches each distinct file under a schema alias. Each file has a table `docs(collection TEXT, id TEXT, data TEXT NOT NULL, update_time REAL NOT NULL, PRIMARY KEY(collection, id))`.
  - `journal_mode=DELETE` (rollback journal), `busy_timeout=10000`.
  - `batch().commit()` runs `BEGIN IMMEDIATE … COMMIT` across the attached files.
  - Files for collections outside `writable` are opened `mode=ro` through `file:` URIs. A write to one raises `PermissionError(f"{collection} is read-only for this agent")` before SQL, and SQLite would refuse it anyway.
  - Queries filter, order and limit in Python after `json.loads`.
  - `update_time` is `time.time()`. It's a runtime concurrency token, not business time, and is never shown or used for lifecycle decisions.
- Contract suite fixture `docstore` parametrized as `["sqlite", "firestore-emulator"]`. The Firestore case uses `FirestoreDocStore(firestore.Client(project="rz-contract"))` when `FIRESTORE_EMULATOR_HOST` is set, and otherwise calls `pytest.skip("FIRESTORE_EMULATOR_HOST not set: Firestore contract not run")`.

- [ ] **Step 1: Write failing contract tests:**
  - `test_create_then_create_raises_already_exists`.
  - `test_set_merge_keeps_other_fields`.
  - `test_update_missing_raises_not_found`.
  - `test_array_union_dedupes_and_appends`.
  - `test_increment_from_missing_field`.
  - `test_delete_field_removes_key`.
  - `test_where_equals_order_desc_limit`.
  - `test_count_shape`.
  - `test_batch_is_atomic_across_collections` (the second create in a batch conflicts, and the first is not visible afterwards).
  - Separately, `test_sqlite_concurrent_batches_one_wins`: two threads with separate stores on the same files each create the same id, exactly one gets `AlreadyExists`, and neither raises `database is locked`. **(Review Focus 5.)**
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_docstore_contract.py -v -rs`. Expected: SQLite cases FAIL, Firestore cases SKIP with the reason shown.
- [ ] **Step 3: Implement** `tools/sqlite_docstore.py`.
- [ ] **Step 4: Run** the same command. Expected: SQLite cases pass and Firestore cases are skipped with the reason. Then `python3 -S -c "import tools.sqlite_docstore"`.
- [ ] **Step 5: Commit** with `git commit -S -m "Add the SQLite document store and a contract suite for both stores"`.

### Task 11: Local layout and the permission boundary

**Files:**
- Create: `tools/local_layout.py`
- Modify: `tools/sqlite_store.py` (the journal lives in the shared file; constructor gains `path` pointing to it; existing behavior unchanged)
- Test: `tests/test_local_layout.py`

**Interfaces:**
- Produces:
  - `AGENT_FILES = {"orchestrator": ("cycles", "memories", "failed_runs"), "decisions": ("decisions",), "ownership": ("assignments",), "chase": ("tickets",), "exception": ("exceptions",), "reporting": ("reports",), "references": ("findings", "assets", "owners", "scans", "approvals")}`.
  - `SHARED = ("human_queue", "sla_clocks")`.
  - `STAGE_WRITES = {"triage_cycle": {"decisions", "assignments", "cycles", "memories", "failed_runs"} | set(SHARED), "chase": {"tickets"} | set(SHARED), "sweep": {"exceptions"} | set(SHARED), "report": {"reports"}, "rescan": {"findings", "scans"}, "seed": {"findings", "assets", "owners"}, "approve": {"approvals"}, "exception_accept": {"exceptions"} | set(SHARED)}`. The triage cycle writes `assignments` because `scripts/cycle.py` runs the assignment step today; the ownership agent's own file still holds `assignments`.
  - `Workspace(root: Path)`, where `.file_for(collection) -> Path` gives `root / f"{agent}.sqlite3"` and `shared.sqlite3` holds `SHARED` plus the idempotency journal.
  - `Workspace.init() -> None` creates every file and table, idempotently.
  - `Workspace.docs_for(stage: str) -> SQLiteDocStore` gives every collection, writable only for `STAGE_WRITES[stage]`.
  - `Workspace.journal() -> SQLiteStore`.
  - Unknown stage raises `KeyError`.

- [ ] **Step 1: Write failing tests:**
  - `test_report_stage_cannot_write_tickets` (`PermissionError`).
  - `test_report_stage_ticket_file_is_readonly_in_sqlite`: bypass the scope check by executing `INSERT` on the underlying connection, and assert `sqlite3.OperationalError` containing `readonly`.
  - `test_chase_cannot_write_decisions`.
  - `test_every_stage_reads_every_collection`.
  - `test_init_creates_missing_files` (delete `chase.sqlite3` after `init()`, call `docs_for("report")`, and it is recreated) **(Review Focus 4)**.
  - `test_journal_shared_across_stages` (a key acquired through one stage's journal is seen through another's).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** `docs_for` calls `init()` first.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_local_layout.py tests/test_recovery_rebuild.py -q`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Lay out the local workspace with a per-agent write boundary"`.

### Task 12: Engine ports, memory and telemetry

**Files:**
- Create: `engine/__init__.py`, `engine/ports.py`, `tools/local_memory.py`
- Modify: `tools/fleet_memory.py` (no behavior change; satisfies the `Memory` protocol), `tools/telemetry.py` (satisfies the `Telemetry` protocol)
- Test: `tests/test_engine_ports.py`, `tests/test_local_memory.py`

**Interfaces:**
- Produces in `engine/ports.py`:
  - `class Memory(Protocol)`, with `remember_cycle(cycle_id: str, counts: Mapping, real_ts: float, sim_ts: float) -> bool` and `recall(query: str) -> list[str]`.
  - `class Telemetry(Protocol)`, with `finding_span(finding_id: str, cycle_id: str, name: str = "remediation.finding") -> ContextManager`, `set_outcome(span, outcome: str) -> None` and `flush() -> None`.
  - `class NoTelemetry`, which no-ops all three.
  - `class TicketDelivery(Protocol)`, matching `GitHubDelivery.deliver`'s current signature exactly.
  - `class NoDelivery`, whose `deliver` returns `None` and logs `{"event": "delivery_skipped", "reason": "dashboard-only"}` with the finding and cycle IDs.
  - `@dataclass(frozen=True) class Ports`, with `docs: DocStore`, `journal`, `clock: SimClock`, `roles: ModelRoles | None`, `guard: Guardrail`, `delivery: TicketDelivery`, `memory: Memory` and `telemetry: Telemetry`.
- Produces in `tools/local_memory.py`: `LocalMemory(docs: DocStore)`, using the `memories` collection and `render_cycle_memory` from `tools.fleet_memory`. `recall(query)` returns up to 5 memories, most recent `sim_ts` first, containing every lower-cased term of `query` with length ≥ 3. `remember_cycle` never raises, matching `FleetMemory`. Importing `render_cycle_memory` must not pull in `google.*`; move it into `tools/fleet_memory_render.py` if needed.

- [ ] **Step 1: Write failing tests:**
  - `test_local_memory_recall_matches_terms_most_recent_first`.
  - `test_local_memory_never_raises_on_store_failure`.
  - `test_records_carry_both_clocks`.
  - `test_no_delivery_logs_and_returns_none`.
  - `test_engine_ports_stdlib_only` (`python3 -S -c "import engine.ports, tools.local_memory"`).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Define engine ports; add local memory and no-op delivery and telemetry"`.

### Task 13: Triage-cycle stage, with cycle.py and graph_cycle.py as wiring

**Files:**
- Create: `engine/triage_cycle.py`
- Modify: `scripts/cycle.py` (CLI and cloud wiring only), `scripts/graph_cycle.py` (handlers call the stage's step functions)
- Test: `tests/test_engine_triage_cycle.py`; `tests/test_cycle_script.py`, `tests/test_graph_cycle.py` and `tests/test_graph.py` pass

**Interfaces:**
- Consumes: `Ports` (Task 12), the writers with neutral docs (Task 9), adapters and roles (Tasks 2–5), `Guardrail` (Task 6).
- Produces in `engine/triage_cycle.py`:
  - `run_triage_cycle(ports: Ports, cycle: int, *, finding_ids: list[str] | None = None, enrichment: EnrichmentCache) -> dict`. Returns exactly the `{"outcomes": ..., ...}` cycle record `scripts/cycle.py` builds today, with the same log events in the same order.
  - Step functions shared with the graph: `screen_finding(ports, finding, cycle) -> tuple[dict, ArmorVerdict]`, `triage_and_review(ports, finding, asset, enrichment, cycle) -> Adjudication`, `assign_if_ratified(ports, adjudication, cycle) -> str | None` and `close_cycle(ports, cycle, outcomes) -> dict`. Each is called by both `run_triage_cycle` and `graph_cycle.build_handlers`.
  - Failed findings: when a finding raises, `close_cycle` gets the failure. Locally (`ports.docs` is a `SQLiteDocStore`), the stage also creates a `failed_runs` document `{finding_id, cycle, error_class, real_ts, sim_ts}` with id `f"{finding_id}-c{cycle:03d}"`, then re-raises as today. The cloud keeps its dead-letter path unchanged.
- `scripts/cycle.py` keeps `main()`, its flags and `_log`. It builds cloud `Ports` with `FirestoreDocStore`, `FirestoreIdempotencyStore`, `ModelArmorGuard`, `FleetMemory`, `NoTelemetry` (cycle.py emits no spans today) and `NoDelivery` (cycle.py delivers nothing today). `scripts/graph_cycle.py` passes `tools.telemetry` as its `Telemetry`.
- Monkeypatch targets used by `tests/test_cycle_script.py` stay importable from `scripts.cycle`, re-exported if they moved.

- [ ] **Step 1: Write failing tests** in `tests/test_engine_triage_cycle.py`, using `Workspace` docs and fake adapters:
  - `test_ratified_finding_is_assigned`.
  - `test_unreviewed_finding_goes_to_queue_not_assigned`.
  - `test_rerun_same_cycle_writes_nothing_new` (document counts unchanged across a second run).
  - `test_failed_finding_recorded_in_failed_runs_and_reraised`.
  - `test_engine_triage_stdlib_only` (`python3 -S -c "import engine.triage_cycle"`).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** by moving the per-finding body of `scripts/cycle.py` into the step functions.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: pass, including the unchanged cycle and graph tests.
- [ ] **Step 5: Commit** with `git commit -S -m "Run the triage cycle from one engine stage in both cycle paths"`.

### Task 14: Chase, sweep, report and rescan stages

**Files:**
- Create: `engine/chase.py`, `engine/sweep.py`, `engine/report.py`, `engine/rescan.py`, `engine/seed.py`
- Modify: `scripts/chase.py`, `scripts/exception.py`, `scripts/report.py`, `scripts/rescan.py`, `scripts/seed.py`, `worker/app.py` (still calls `scripts.chase.run_chase` / `scripts.exception.run_sweep`; those become wiring)
- Test: `tests/test_engine_stages.py`; `tests/test_worker.py`, `tests/test_chase_script.py`, `tests/test_exception_script.py`, `tests/test_rescan_script.py`, `tests/test_reports.py` pass

**Interfaces:**
- Produces:
  - `engine.chase.run_chase(ports: Ports, cycle: int) -> dict[str, int]`.
  - `engine.sweep.run_sweep(ports: Ports, cycle: int) -> dict[str, int]`.
  - `engine.sweep.accept(ports: Ports, finding_id: str, ttl_days: int, by: str, reason: str, cycle: int) -> str`.
  - `engine.report.run_report(ports: Ports, cycle: int) -> str`.
  - `engine.rescan.run_rescan(ports: Ports, cycle: int, scan: dict, dry_run: bool) -> dict`.
  - `engine.seed.seed(ports: Ports, corpus_dir: Path) -> dict[str, int]`, which reads `data/findings.json`, `assets.json` and `owners.json`.
  - Each returns what its script returns today.
- The script entry points keep their current signatures (`run_chase(cycle, advance_days=0.0, clock=None)` and so on). They build cloud `Ports` and call the engine. Chase's cloud `Ports.delivery` is `GitHubDelivery` exactly when `GITHUB_TICKET_REPO` is set, as today. No other stage receives a delivery.
- Cycle numbering is unchanged: the worker's `cycle_for_day` stays in `worker/app.py`.

- [ ] **Step 1: Write failing tests** on `Workspace` docs:
  - `test_chase_escalates_after_sla_breach` (`SimClock` in simulated mode, advanced in memory past the SLA).
  - `test_sweep_reopens_expired_exception`.
  - `test_report_without_summarizer_writes_marker`.
  - `test_rescan_dry_run_writes_nothing`.
  - `test_rescan_closes_verified_finding`.
  - `test_seed_is_idempotent`.
  - `test_stages_stdlib_only`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** by moving bodies; the scripts keep their CLIs and log events.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Move chase, sweep, report, rescan and seed into engine stages"`.

### Task 15: Local commands, the approval path and the full snapshot

**Files:**
- Modify: `scripts/local.py` (new commands; retire `suggest-demo` once `cycle` works), `scripts/local_launcher.py` (optional interval runner), `ui/dashboard_view.py` (failed runs; approval guidance)
- Create: `engine/approve.py`, `engine/snapshot.py`
- Test: `tests/test_local_commands.py`; `tests/test_local_edition.py`, `tests/test_local_launcher.py` and `tests/test_local_installer.py` updated for the retired command (the only allowed assertion change, noted in the commit)

**Interfaces:**
- Commands (all take `--database DIR`, the workspace root, defaulting as today):
  - `init`.
  - `seed`.
  - `cycle --cycle N` runs triage, chase, sweep and report in that order, each with `ws.docs_for(<stage>)`. Chase and sweep use `cycle_for_day(clock.now().real_ts)` as their cycle.
  - `rescan --cycle N --scan PATH [--dry-run]`.
  - `exception accept FINDING --ttl DAYS --by OWNER_ID --reason TEXT --cycle N`.
  - `exception list`.
  - `approve FINDING --cycle N [--by NAME]`.
  - `serve`.
- `engine.approve.approve(ports, finding_id, cycle, by) -> str`:
  - Writes `approvals/<finding_id>-c<NNN>` as `{finding_id, cycle, decision_id, approved_by, real_ts, sim_ts}`, guarded by `derive_record(finding_id, "approval", cycle)`.
  - Allowed only when the decision is `unreviewed` or `held_for_approval`; otherwise it raises `ValueError`.
  - The next `cycle` run's `assign_if_ratified` treats a decision with a matching approval as passing the gate. It logs `{"event": "approved_by_person"}`, and `models` and `review_independence` stay exactly as recorded.
- `engine.snapshot.snapshot(docs) -> dict` returns the keys of `ui.app.snapshot()`: `counts`, `decisions`, `human_queue`, `scans`, `latest_scan`, `tickets`, `sla`, `exceptions`, `cycles`, `reports`, `resolved_total` and `sim_now`, plus `failed_runs`. Collection limits are as in `ui/app.py`. `scripts/local.py serve` uses it.
- Local ticket delivery: the `cycle` command gives chase `GitHubDelivery` when both `GITHUB_TICKET_REPO` and the GitHub token variable `scripts/chase.py` reads today are set, and `NoDelivery` (dashboard-only) otherwise. No other local stage receives a delivery.
- `suggest-demo` is removed. `check-models` (Task 8) is the explicit model check.
- Interval runner: when `cycle_interval_minutes > 0`, the launcher starts one daemon thread that calls the `cycle` command's function every interval with the next cycle number (one more than the highest in `cycles`). Overlapping runs are skipped and logged with `{"event": "cycle_skipped", "reason": "previous run still active"}`.

- [ ] **Step 1: Write failing tests:**
  - `test_local_cycle_end_to_end_one_finding` (fake adapters injected through a `--roles-from` test seam).
  - `test_approve_lets_held_decision_proceed_next_cycle`.
  - `test_approve_rejects_ratified_decision`.
  - `test_snapshot_has_cloud_keys`.
  - `test_failed_runs_shown_on_dashboard`.
  - `test_interval_runner_skips_overlap`.
  - `test_local_chase_dashboard_only_without_github_env` (no GitHub variables, so the chase stage's delivery is `NoDelivery` and no socket opens).
  - `test_local_commands_stdlib_only` (`python3 -S -m scripts.local --help`).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest -q && python3 -S -m scripts.verify_local_install`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Run the full lifecycle from the local commands, with a person's approval path"`.

### Task 16: Multi-cycle lifecycle test and documentation

**Files:**
- Create: `tests/test_lifecycle_local.py`
- Modify: `docs/development/local-edition.md`, `docs/development/platform-integration.md`, `README.md`, `CLAUDE.md` (Commands section)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the lifecycle test.** It runs in one process, with `SimClock` in simulated mode advanced in memory and fake adapters returning fixed proposals and verdicts. It asserts, in order:
  1. Seed loads the corpus.
  2. Cycle 1 ratifies finding A (cross-family), holds finding B (same-family, `wait`) and leaves finding C unreviewed (reviewer removed for C's run).
  3. Only A is assigned and gets an SLA clock.
  4. After advancing past A's SLA, chase records an escalation exactly once across two chase runs.
  5. `approve B` followed by the next cycle assigns B.
  6. An exception accepted on D with `ttl=7` reopens after advancing 8 days.
  7. A rescan dry run writes nothing; the real rescan resolves A.
  8. The report shows `ratified`, `held_for_approval` and `unreviewed` counts, and its summary is the no-summarizer marker.
  9. Every document written has both `real_ts` and `sim_ts`.

  Add `test_lifecycle_firestore_emulator`, which runs the same assertions against `FirestoreDocStore` on the emulator and skips with a reason when `FIRESTORE_EMULATOR_HOST` is unset.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_lifecycle_local.py -v -rs`. Expected: pass; the emulator case skips with a reason.
- [ ] **Step 3: Update the docs.**
  - `local-edition.md` covers the commands, the four roles, the same-family setting and `approve`. It states verbatim that the local permission boundary is "enforced in the code by construction, not by the operating system: one local user owns every workspace file", along with the no-guard withholding rule and the failed-runs table.
  - `CLAUDE.md` Commands lists the new `scripts.local` commands.
  - `README.md` drops "Local suggestions have no independent review".
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** with `git commit -S -m "Prove the local lifecycle end to end and document the local edition"`.

---

## Not in this plan (needs the owner)

- Any cloud deploy. After Part A and again after Part B: `./scripts/deploy-agent.sh` is **not** needed (the Agent Engine resource is untouched). Run `./scripts/deploy-ui.sh` and `./scripts/deploy-worker.sh` only with sign-off, between cycles (Task 4's fingerprint change), then `./scripts/verify-controls.sh`.

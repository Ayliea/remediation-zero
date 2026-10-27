# Unconfirmed high and critical findings — design

Status: approved by the owner 2026-10-26; implementation plan not yet written. Builds on
`2026-10-25-greenbone-connection-design.md` (release project 1). To be built on
its own branch after `fix/local-server-release-blockers` merges.

## Why

The first real scan of the lab (gvmd 26.42, 2026-10-26) imported 6 findings and
counted 59 results as below the quality floor. 34 of those 59 were high or
critical, including Apache httpd 2.4.49's path traversal / RCE
(CVE-2021-41773 and CVE-2021-42013, both in CISA KEV). Greenbone reported them
at QoD 30: it matched the version in the server banner but did not prove the
flaw on the host. Under the current rule (skip anything below QoD 70) the
product said nothing about an actively exploited RCE except a count.

The QoD floor exists for a real reason: version-based detections are wrong
when a distribution backports a fix without changing the version number. The
owner chose option C: bring in the ones that matter most, and say plainly that
they are unconfirmed, rather than hide them (A) or let every low-confidence
result through (B).

## Goals

- A high or critical Greenbone result below the QoD floor becomes a finding,
  marked **unconfirmed**, and goes through triage and review like any other.
- Everywhere a person sees it (dashboard, ticket, evidence), it says
  unconfirmed and why: "version-based detection (QoD 30%), not verified on the
  host".
- Triage and the reviewer are told it is unconfirmed, and the recommended fix
  starts with confirming it (check the installed version or the vendor's
  backport notice) before patching.
- Low and medium results below the floor stay counted only, as today.
- The card says how many came in unconfirmed and how many stayed counted.

## Non-goals

- Merging findings across Greenbone tests. One CVE can be reported by a
  version check (QoD 30) and an active check (QoD 99) as two findings, keyed by
  test. That is how it already works; a later active-check finding does not
  replace the unconfirmed one.
- Honouring Greenbone overrides or false-positive marks (`apply_overrides=0`
  stays).
- Changing the QoD floor default (70) or anything about the cloud edition's
  seeded findings.

## Anti-goals

- An unconfirmed finding presented as if it were confirmed anywhere.
- A finding resolved because of a low-confidence absence. Resolution rules do
  not change: only a rescan that covers the host and no longer reports the
  result resolves it.
- A change to the cloud edition's model input: legacy findings render byte for
  byte as today (`test_single_cve_cloud_render_is_unchanged`, the cloud golden
  fixture).

## Design

### Which results come in **(owner: high and critical; thresholds designer's call)**

A result is imported as unconfirmed when all hold:

- Greenbone severity (`result.severity`, the one score per result whatever its
  CVE count) >= 7.0 (high or critical). The parser already rejects a result
  whose severity cannot be read, so there is no "unknown" case here;
- QoD below the configured floor and at least `UNCONFIRMED_QOD_MIN = 30`.
  30 is Greenbone's lowest version-based tier (package or banner
  "unreliable"). Below 30 are notes and guesses (the lab had one at QoD 1),
  which stay counted only. If the floor is set to 30 or less, the band is
  empty and nothing changes;
- every other existing rule passes (finished, covered host; readable ids).

Not a setting in this version **(designer's call)**: the floor stays the only
knob, which avoids a settings schema change.

Everything else below the floor is skipped and withheld exactly as today
(withheld means its absence never resolves anything).

### Where it is recorded (schema: **owner approved** 2026-10-26)

- `findings`: one new field, `unconfirmed: true`, set only on these findings.
  Absent means confirmed, so existing records do not change.
- `scanner_state.last_skipped` gains nothing; a new
  `last_imported_unconfirmed` count sits beside it. `below_qod` keeps counting
  only what was not imported.

### When a later report disagrees **(designer's call)**

The flag follows the latest report that covers the host: a finding reported
at or above the floor loses `unconfirmed`; a confirmed one reported back in
the band gains it; one that drops below 30 is withheld (stays open, as any
withheld finding). A flag change does not re-triage a ratified finding or
rewrite a sent ticket; the dashboard and the next reminder show the current
state.

### What triage and the reviewer see

- `render_finding` is what both agents see, so the reviewer gets the same
  header. The render for non-legacy findings adds one trusted header line:
  `detection: unconfirmed (version-based, QoD 30%; not verified on the host)`.
- A new versioned prompt, `prompts/triage_unconfirmed.md`, is appended for
  unconfirmed findings (as `triage_no_cve.md` is for non-legacy ones), telling
  the model: judge severity as if the finding is real, do not lower it only
  because it is unconfirmed; the remediation path starts with confirming it;
  say in the rationale that it is unconfirmed. The reviewer gets matching
  guidance in `prompts/reviewer_unconfirmed.md`, appended only for unconfirmed
  findings, so the reviewer's input for every other finding is unchanged.
  `triage_instruction` gains an `unconfirmed` argument (default False)
  **(designer's call)**.
- Inference fingerprints change for these findings only.

### Lifecycle **(owner: chase it like any other)**

After triage and review ratify, an unconfirmed finding is
assigned, gets its SLA clock and is chased like any other, with the ticket
saying unconfirmed and "confirm first". Reason: in the lab the only evidence
of a KEV RCE was QoD 30; waiting on a person would leave exactly those
findings unchased.

### When it turns out not to apply **(owner: risk acceptance for now)**

The owner records a risk acceptance with a
reason such as "not affected: distro backport, see advisory". Today's rules
apply unchanged (a KEV finding needs a person; acceptance expires and the
finding reopens at expiry, which doubles as a re-check). A dedicated
"not affected" disposition is a later design.

### Dashboard and pull line

- Card: "N high or critical results came in unconfirmed (version-based
  detection; check them before patching)." beside the existing below-floor
  count.
- Pull line: `; N unconfirmed`.
- Each unconfirmed finding shows an "Unconfirmed" badge with the QoD.
- Tickets (`tools/github_tickets.py`, the only tracker today) say
  "Unconfirmed: version-based detection (QoD N%). Confirm the installed
  version first." The evidence console is being retired and is not changed
  **(designer's call)**.

## Testing

- Normaliser: the band edges (severity 6.9 / 7.0; QoD 29 / 30 / floor-1 /
  floor); floor <= 30 leaves the band empty; an unconfirmed result on an
  uncovered host is still skipped; withheld ids for the rest unchanged.
- Reconcile: an unconfirmed finding stays open while reported and resolves
  only on a covering rescan.
- Render: header line present for unconfirmed; legacy render and the cloud
  golden fixture byte-identical.
- Prompt selection appends `triage_unconfirmed.md` only for unconfirmed.
- Card and pull-line wording; badge.
- Real check: re-pull the lab; CVE-2021-41773 arrives unconfirmed; bumping
  httpd to 2.4.62 and rescanning resolves it.

## Left to the builder

Exact prompt wording (within the rules above), badge styling, log field names.

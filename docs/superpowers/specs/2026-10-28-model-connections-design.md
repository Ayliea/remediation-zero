# Model connections: guided setup for cloud and local models

Status: approved by the owner 2026-10-28.

## Intent

The owner wants to run the local edition on their own API credits, and wants
connecting a model to feel as easy as adding a bank account through Plaid Link:
pick a provider from a searchable list, securely enter what it needs, say what
it is for, see it work. Today a model is set up by editing four per-role forms
in Settings and exporting `RZ_<ROLE>_API_KEY` variables on the server. That works,
but it is not plug-and-play, and the owner's release bar is "as plug and play as
possible" for an MSP technician in their first hour.

## What the owner decided

- **A list first.** Opening model setup shows the existing connections, each
  with options to add, modify and delete.
- **A popup to add one**: search or pick a provider, enter what it needs, say
  what it is for, test, save. The popup asks what the connection is for, and
  that part can be changed later without re-entering the key.
- **Look**: modelled on the reference the owner shared: white rounded card, a
  simple drawn icon, bold centred title, one muted line, one light and one dark
  button. Mockups: `.superpowers/brainstorm/*/content/connections-popup-v2.html`
  and `jobs-step-v3.html` (git-ignored; the descriptions below are the binding
  version).
- **Provider tiles use coloured lettermarks** (A, O, G, R, Ol, +), not logos.
  Provider logos are trademarks, not Apache-licensed artwork, and the local
  edition loads nothing from the internet at page load. Real logos may replace
  tiles one at a time later, after each provider's brand rules are checked.
- **Keys entered in the popup are stored in a locked-down file on the server**,
  provided it is not a weaker mechanism than environment variables (the
  rules are under "Key storage"). The owner noted cloud hosting can be more
  secure because keys can live in a dedicated key store; that is the cloud
  edition's implementation of the same plug-in point.
- **The jobs step recommends**, based on the chosen model, the models already
  set up, the model's capabilities, and which jobs nobody covers.
- **Cost is mentioned, never decides.** Each job card can say what a choice
  costs; cost never switches a job on or off.
- **One small bundled script runs the popup.** It is served by Remediation
  Zero itself and allowed in the CSP by its hash (`script-src 'sha256-…'`;
  everything else stays `'none'`). The typed key lives only in that page's
  memory until the final save POST. The owner confirms it's them (password or
  authenticator code) when the popup opens, not at the end, so nothing typed
  is lost to a re-confirm redirect. Pages other than the popup stay
  script-free.
- **Hard constraint 6 is reworded** to admit the owner-only key file: keys
  come from the environment or from that file, and never from settings, the
  repository, logs or pages.

## Goals

1. An owner with an API key and no knowledge of request formats or endpoints
   connects a cloud model and has a working cycle in a few minutes.
2. Every job (triage, review, screening, summaries) visibly has a model or
   visibly has none.
3. Keys entered in the browser are stored at least as safely as environment
   variables, are never shown again, and never leave the server.
4. The independent-review rule stays honest: a same-family review is allowed
   and labelled, never hidden and never silently created by an edit.

## Non-goals

- Downloading or installing local models. Ollama here connects an Ollama the
  owner already runs. The one-click download is its own design
  (memory: one-click local model); this popup will later link to it.
- Real provider logos.
- The cloud edition's key store. This design defines the plug-in point and the
  local file implementation only.
- The wider Settings refresh and moving Accounts under Settings (separate
  brainstorm).
- Any change to how models are called once configured (`tools/models.py`
  adapters, transport rules, retries).

## Anti-goals

- A key ever appearing in a page, a log line, the audit trail, settings JSON,
  a settings export, a snapshot, an error message or the repository.
- "Encryption" with a key stored on the same machine, presented as protection.
- Recommendations that silently replace an existing job or silently turn an
  independent review into a same-family one.
- A connection saved in a state that has never answered a test.

## Concepts

- **Connection**: one provider account: provider preset, request format
  (`openai_chat`, `anthropic_messages`, `gemini_api`), endpoint, optional CA
  file, and a key reference. A connection has a display name (default: the
  provider name; a second connection to the same provider needs a distinct
  name, e.g. "Anthropic (work)").
- **Job**: the existing roles. The UI says Triage (proposer), Review
  (reviewer), Screening (guard), Summaries (summarizer). Code keeps the role
  names.
- **Assignment**: job → (connection, model, family, timeout). One model per
  job, as today. A connection may serve several jobs, with the same or
  different models.

## The connections list (default view)

The Models section of Settings. It replaces today's four per-role forms.

- One row per connection: lettermark tile, display name, key hint ("ends in
  …7Qx2", "no key needed", or "set on the server"), the jobs it does with the
  model for each, and last test result with time ("Tested 2 min ago",
  "Failed: <error class>", "Not tested").
- Row actions: **Edit**, **Replace key**, **Test again**, **Delete**.
- Below the list, a coverage strip: the four jobs, each showing its connection
  and model, or "nobody" in red. When Review is set, it shows "different
  family" or "same family" next to it.
- **+ Add a connection** opens the popup.
- A tech sees the list and coverage but no add, edit, replace or delete
  controls (owner-only, as Settings writes are today).

## The add popup

Five steps, one card each, in the reference style. Back works on every step
after the first; Cancel or Escape closes without saving anything.

1. **Connect a model.** Search box and a grid of provider tiles:
   Anthropic, OpenAI, Google Gemini, OpenRouter, Ollama, Other
   (OpenAI-compatible). Search filters tiles by name. Each tile is a preset:
   format and default endpoint, key or no key, and a "Where do I find this?"
   link to the provider's key page (opened in a new tab; the only outbound
   link). "Other" asks for a format and an endpoint.
2. **Enter what it needs.** A password-type key field (no autocomplete, not
   echoed), or for Ollama an address (default `http://127.0.0.1:11434`).
   "Advanced" reveals endpoint override and CA file. The note says: saved on
   this server where only Remediation Zero can read it; never shown again.
   Existing endpoint rules apply unchanged (HTTPS unless loopback; no
   credentials, query or fragment in the URL).
3. **Pick a model.** The list comes from the provider's model-list endpoint,
   fetched once on entering this step with the key just typed, using the same
   transport rules as model calls. Each model shows a short line from the
   catalogue (strength, speed, relative cost) and "Suggested" on the catalogue's
   pick for the gaps being filled. "Type a model name" is always available. If
   the list call fails, the step says why and offers the typed name.
4. **What should it do?** The coverage strip at the top. Then one card per job,
   each with an icon, the job name, a one-line description, a badge
   (Recommended / Covered / Not suggested), a one-line reason, an optional cost
   line, and a switch. Recommended jobs start switched on. See
   "Recommendations".
5. **Test and save.** Pressing Test sends one test request per switched-on
   job with that job's model. The owner already confirmed it's them when the
   popup opened (the existing re-confirm and its 5-minute window); if that
   window has lapsed by now, the popup asks again in place, without leaving
   the page or losing what was typed. Success card: "<Provider> is connected!", the answer time, and
   what it now does; buttons "Add another" and "Done". Nothing is written
   until every switched-on job's test passes; a failure shows which job and
   the error class, and offers Back.

## Edit, replace, test, delete

- **Edit** opens the popup at step 3 (model) with current values, then 4 and 5.
  The key is not asked again. Saving re-tests the changed jobs. *Builder's
  call, recorded:* changing a connection's endpoint or CA file is done through
  Replace key's step 2 and always requires the key to be entered again, so a
  hijacked session cannot redirect a stored key to another server.
- **Replace key** opens step 2 alone, then tests every job the connection
  serves before replacing the stored key.
- **Test again** runs step 5's test for the connection's jobs and records the
  result. Owner-only, since it spends the owner's provider credit; no
  re-confirm (it changes nothing but the last-test record). Rate-limited.
- **Delete** first states what is lost ("Anthropic does Review and Summaries.
  After deleting, nobody reviews, so new triage waits for a person."), then
  re-confirm, then removes the connection, its stored key and its job
  assignments.
- Every add, edit, key replacement and delete is an audit event with the
  connection's display name and the acting account; never the key or its hint.

## Recommendations

Computed on the server from: the chosen model, the current assignments, the
model catalogue, and which jobs are uncovered. Rules, in order:

1. **Gaps first.** An uncovered job is Recommended. Triage is called out
   because without it no cycle runs.
2. **Independent review.** Review is Recommended only when the chosen model's
   family differs from the triage model's family (or triage is unset). A
   same-family review is never blocked; its card says the record will read
   "reviewed by the same model family" (hard constraint 3).
3. **Never silently replace.** A covered job starts off, badge Covered, and its
   reason names what switching it on replaces and any knock-on effect (e.g.
   "then Review would be the same family as Triage").
4. **Match the job to the model.** From the catalogue tier: Triage and Review
   prefer the strongest tier; Screening and Summaries are fine on small or
   local models. A large model suggested for Screening while a local or
   cheaper one already covers it gets Not suggested with the reason.
5. **Cost is a sentence, not a rule.** e.g. "costs more per finding", "free,
   runs on this server". Cost never changes a badge.
6. **Unknown models** (not in the catalogue) get rules 1–3 by family, and the
   card says "We don't know this model's strengths."

**Same-family policy.** The existing `same_family_policy` (`wait` | `proceed`)
stays and moves into the Models section below the coverage strip. When a
choice in step 4 would make Review the same family as Triage, the card states
what the current policy will do ("With 'wait', triage waits for a person
before anything is assigned") and links to change it. Family `other` counts as
same family, matching `ModelRoles.independence()`. *(Builder's call, recorded.)*

Family is the catalogue's value for known models, else
`model_roles.suggest_family`, and remains editable under Advanced, as today.

## Model catalogue

A small data file shipped with the code (JSON, standard library only),
versioned and reviewed like a prompt. Each entry: provider, model id pattern,
family, tier (`large` | `small` | `local`), one-line strengths, relative cost
(`higher` | `lower` | `free`). It will go stale; the UI never claims more than
the entry says, and an unmatched model falls to rule 6. No network lookup of
capabilities.

## Key storage

A **secrets port** with one method set: `put(connection_id, key)`,
`get(connection_id)`, `delete(connection_id)`, `hint(connection_id)`. The local
edition implements it as a file; the cloud edition will implement it over its
secret store later.

Local file rules:

- Next to the settings file (`<database>.secrets.json`), separate from settings,
  workspace databases and accounts. Created with `os.open(..., 0o600)` and
  `O_NOFOLLOW`, written atomically (temp file + rename, same directory, mode
  0o600 before rename), as `tools/local_layout.py` already does for databases.
- On every read, refuse to use the file if it is group- or world-readable or
  not owned by the running user, with an error naming the file and the
  `chmod 600` fix. (Windows: the builder decides the equivalent check, or
  documents that the file relies on the profile directory's ACL.)
- Read only when a model call or test needs the key; not cached in a module
  global; never passed to child processes' environments.
- Stores the key and a hint (last four characters) only. The hint is computed
  at write time so the page never needs the key.
- No encryption with a co-located key. The docs say plainly that protection at
  rest is the file mode plus full-disk encryption of the host.
- Excluded from `settings show`, from any snapshot, and from the dashboard's
  data. A settings export, if one exists or is added, never includes it.

**Environment variables still win.** If `RZ_<ROLE>_API_KEY` (or
`RZ_MODEL_API_KEY` for triage) is set, that job uses it, and the list shows the
connection's key as "set on the server": its jobs can be edited, its key
cannot be replaced from the browser.

## Settings schema

Settings move to version 6: a `connections` map (id → display name, provider
preset, format, endpoint, CA file, last test result with both clock stamps) and
`roles` entries that gain a `connection` reference while keeping `model`,
`family` and `timeout_seconds`. A version 5 file is migrated on load: each
configured role becomes its own connection, named "<Provider> (<Job>)", whose
key reference is that role's environment variables exactly as today, so no
job's model or key changes. *(Builder's call, recorded.)* This is a storage
schema change and is approved as part of this design.

**Environment variables are per job, keys stored per connection.** The
`RZ_<ROLE>_API_KEY` variables (and `RZ_MODEL_API_KEY` for triage) override per
job. A connection whose jobs differ in where their key comes from shows the
source per job in its row ("Review: set on the server · Summaries: stored
…7Qx2"). The other overrides (`RZ_MODEL`, `RZ_MODEL_ENDPOINT`,
`RZ_<ROLE>_MODEL/ENDPOINT/FORMAT/FAMILY`) keep working and show as "set on the
server" on the field they override. `settings set` for a model updates that
job's assignment and uses the connection matching its format and endpoint,
creating one if none matches. *(Builder's call, recorded.)*

## Command line

`settings set` keeps working for models. New:

- `connection list`: name, provider, key hint or "set on the server", jobs.
- `connection add PROVIDER [--name N] [--endpoint URL]`: asks for the key at
  a hidden prompt (never an argument, so never in shell history), then jobs
  and model as flags or prompts, tests, saves. `--as EMAIL` as other owner
  commands.
- `connection replace-key NAME`, `connection test NAME`,
  `connection remove NAME`, each with `--as EMAIL` where it changes anything.

Add these to the Commands list in CLAUDE.md.

## Security requirements

- Owner-only for every change, with the existing re-confirm; techs read only.
- Every form posts with the existing CSRF token and Host/Origin checks.
- The server never echoes a key back, including after a failed test; the key
  survives Back and a failed test only in the popup's own page memory.
- The popup page's CSP allows exactly the bundled script's hash and nothing
  else (`connect-src 'self'`, no inline handlers, no `eval`); every other page
  keeps `default-src 'none'` with no script.
- The model-list and test calls use the existing transport: no redirects, no
  inherited proxies, size caps, timeouts.
- Log lines name the connection and job and the error class only.
- Responses that carry connection data never include the key.
- Rate-limit test and model-list calls per session (reuse the existing limiter)
  so the page can't be used to hammer a provider with a stolen session.

## Tests that matter

- A key never appears in any rendered page, log record, audit event, settings
  file or snapshot, across add, edit, replace, test, delete and failure paths.
- The secrets file is created 0600, refused when loosened, refused through a
  symlink.
- An environment variable overrides a stored key, and the page says so.
- Nothing is saved when any switched-on job's test fails.
- Delete removes the key, the connection and its assignments, and says what
  was lost first.
- Recommendation rules 1–6, including: a covered job never starts on; a
  same-family review is labelled and never blocked.
- A version 5 settings file migrates to version 6 with no change in which model
  each job uses.
- A tech gets 403 on every change route.
- The served script's hash matches the CSP header, and no other page's CSP
  allows a script.

## Left to the builder

- Markup and CSS within the reference look; icons are simple inline SVG drawn
  for this project (the mockup's emoji are placeholders).
- The popup is a `<dialog>` driven by the one bundled script; how it is
  structured is the builder's, provided it loads nothing from elsewhere, works
  with keyboard only, and Back never loses the typed key within the same
  popup session.
- Initial catalogue contents.
- Where the provider presets live (alongside the catalogue is fine).

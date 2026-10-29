// Copyright 2026 Daviyon Daniels
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// Settings -> Models: the popup that adds, edits, re-keys, tests and deletes a model connection.
// The only script the local edition serves. It is embedded in that one page and allowed by its
// hash. It talks only to this server's /connections/* routes. Text from the server is set with
// textContent, never parsed as markup. A typed key lives in this page's memory only: in its
// input until the popup closes, and in the one request body that sends it.
(function () {
  'use strict';
  const dialog = document.getElementById('rz-dialog');
  const dataNode = document.getElementById('rz-connections');
  if (!dialog || !dataNode || typeof dialog.showModal !== 'function') {
    return;
  }
  const DATA = JSON.parse(dataNode.textContent);
  const PAGE = '/?view=settings&section=model';
  const PRESETS = new Map(DATA.presets.map((p) => [p.id, p]));
  const CONNECTIONS = new Map(DATA.connections.map((c) => [c.id, c]));
  const ROLES = DATA.jobs.map((j) => j.role);
  const JOB_NAMES = new Map(DATA.jobs.map((j) => [j.role, j.job]));
  const COLOUR = /^#[0-9a-f]{6}$/;
  const FLOWS = { add: ['provider', 'key', 'model', 'jobs', 'test'], edit: ['model', 'jobs', 'test'],
                  replace: ['key', 'test'] };
  const BADGES = { recommended: ['Recommended', 'rec'], covered: ['Covered', 'mute'],
                   not_suggested: ['Not suggested', 'warn'] };
  const NO_JOBS = 'Switch on at least one job, so the connection can be tested before it is saved.';

  let confirmed = DATA.confirmed === true;
  let state = null;        // the open popup's values; null when closed
  // The typed key, once step 2 is left. The input is emptied then, so no password manager sees
  // a filled password box disappear after a request (a "submission" to it). Back puts it back.
  let heldKey = '';
  let keyEpoch = 0;        // changes whenever the key is typed: the model list is signed with it
  let reloadOnClose = false;  // something may have changed: the list is read again on close

  const $ = (id) => document.getElementById(id);
  const card = (name) => dialog.querySelector('[data-card="' + name + '"]');
  const inCard = (name, selector) => card(name).querySelector(selector);
  const fields = { password: $('rz-password'), code: $('rz-code'), search: $('rz-search'), format: $('rz-format'),
                   address: $('rz-address'), key: $('rz-key'), base: $('rz-base'), ca: $('rz-ca'),
                   model: $('rz-model'), family: $('rz-family'), timeout: $('rz-timeout'), name: $('rz-name') };

  function text(tag, value, className) {
    const el = document.createElement(tag);
    el.textContent = value;
    if (className) {
      el.className = className;
    }
    return el;
  }

  function sentence(words) {
    return /[.!?]$/.test(words) ? words : words + '.';
  }

  function and(items) {
    return items.length < 2 ? items.join('') : items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
  }

  // --- moving between cards ----------------------------------------------------------

  function visible(el) {
    return !el.disabled && el.getClientRects().length > 0;
  }

  function show(name) {
    for (const each of dialog.querySelectorAll('[data-card]')) {
      each.hidden = each.dataset.card !== name;
    }
    const shown = card(name);
    dialog.setAttribute('aria-labelledby', shown.querySelector('h2').id);
    const at = state.flow.indexOf(name);
    const steps = shown.querySelector('[data-steps]');
    if (steps) {
      steps.textContent = at >= 0 && state.flow.length > 1 ? 'Step ' + (at + 1) + ' of ' + state.flow.length : '';
    }
    for (const back of shown.querySelectorAll('[data-do="back"]')) {
      back.textContent = at === 0 ? 'Cancel' : 'Back';
    }
    state.card = name;
    if (!dialog.open) {
      dialog.showModal();
    }
    const first = Array.from(shown.querySelectorAll('input, select, button, a[href], summary')).find(visible);
    if (first) {
      first.focus();
    }
  }

  function say(name, message, hint) {
    const error = inCard(name, '[data-error]');
    error.textContent = message || '';
    error.hidden = !message;
    const hintNode = inCard(name, '[data-hint]');
    hintNode.textContent = hint || '';
    hintNode.hidden = !hint;
  }

  function status(name, message) {
    inCard(name, '[data-status]').textContent = message || '';
  }

  function busy(on) {
    state.busy = on;
    for (const button of dialog.querySelectorAll('button')) {
      button.disabled = on;
    }
    if (!on && state.card) {
      // A disabled button loses focus: give it back to the card, not to the page behind.
      const shown = card(state.card);
      if (!shown.contains(document.activeElement)) {
        const primary = shown.querySelector('[data-primary]');
        const first = primary && visible(primary) ? primary
          : Array.from(shown.querySelectorAll('input, select, button, a[href], summary')).find(visible);
        if (first) {
          first.focus();
        }
      }
    }
  }

  function setMark(name) {
    const preset = PRESETS.get(state.provider);
    const mark = inCard(name, '[data-mark]');
    mark.textContent = preset.letter;
    mark.style.backgroundColor = COLOUR.test(preset.colour) ? preset.colour : '#a1a1aa';
  }

  function clearAll() {
    // Every typed value goes, the key first; nothing else holds it once the state is dropped.
    heldKey = '';
    fields.key.value = '';
    fields.password.value = '';
    fields.code.value = '';
    for (const input of dialog.querySelectorAll('input')) {
      input.value = input.id === 'rz-timeout' ? '60' : '';
    }
    for (const select of dialog.querySelectorAll('select')) {
      select.selectedIndex = 0;
    }
    for (const details of dialog.querySelectorAll('details')) {
      details.open = false;
    }
    for (const list of dialog.querySelectorAll('[data-models], [data-jobs], [data-cover], [data-summary]')) {
      list.replaceChildren();
    }
    for (const tile of dialog.querySelectorAll('[data-provider]')) {
      tile.hidden = false;
    }
    inCard('provider', '[data-none]').hidden = true;
    for (const name of ['confirm', 'key', 'model', 'jobs', 'test', 'delete']) {
      say(name, '');
    }
    if (state) {
      state.pending = null;
    }
    state = null;
  }

  function begin(mode, connId) {
    if (state) {
      clearAll();
    }
    for (const button of dialog.querySelectorAll('button')) {
      button.disabled = false;   // a popup closed mid-request left them disabled
    }
    const conn = connId ? CONNECTIONS.get(connId) : null;
    state = { mode: mode, flow: FLOWS[mode] || [], connection: connId || null, conn: conn,
              provider: conn ? conn.provider : null, card: null, busy: false, pending: null,
              listed: null, advised: null, cards: [], on: {}, familyTouched: false, held: null };
    if (mode === 'delete') {
      inCard('delete', '[data-title]').textContent = 'Delete ' + conn.name + '?';
      inCard('delete', '[data-line]').textContent = DATA.deletions[connId] || '';
      show('delete');
      return;
    }
    if (mode === 'test') {
      testAgain();
      return;
    }
    if (mode === 'edit') {
      const held = conn.jobs;
      state.held = held;
      if (held.length) {
        fields.model.value = held[0].model;
        fields.family.value = held[0].family;
        fields.timeout.value = String(held[0].timeout_seconds);
      }
      const note = inCard('model', '[data-note]');
      const distinct = new Set(held.map((j) => j.model));
      note.textContent = distinct.size > 1
        ? 'Its jobs use different models now. The model you pick here is used for every job you switch on.' : '';
      note.hidden = distinct.size < 2;
    }
    whenConfirmed(() => enter(state.flow[0]));
  }

  function whenConfirmed(then) {
    if (confirmed) {
      then();
      return;
    }
    state.afterConfirm = then;
    show('confirm');
  }

  function enter(name) {
    if (name === 'key') {
      prepareKey();
    } else if (name === 'model') {
      prepareModel();
    } else if (name === 'jobs') {
      prepareJobs();
    } else if (name === 'test') {
      prepareTest();
    }
    show(name);
    if (name === 'model') {
      listModels();
    } else if (name === 'jobs') {
      advise();
    }
  }

  function closeDialog() {
    heldKey = '';
    fields.key.value = '';   // now, not when the close event comes round
    dialog.close();
  }

  function back() {
    const at = state.flow.indexOf(state.card);
    if (at <= 0) {
      closeDialog();
    } else {
      enter(state.flow[at - 1]);
    }
  }

  // --- talking to the server ---------------------------------------------------------

  async function post(path, body) {
    let response;
    try {
      response = await fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
                                     redirect: 'error', headers: { 'Content-Type': 'application/json' },
                                     body: JSON.stringify(Object.assign({}, body, { token: DATA.token })) });
    } catch (error) {
      return { status: 0, data: null, retry: null };
    }
    let data = null;
    if ((response.headers.get('Content-Type') || '').indexOf('application/json') === 0) {
      try {
        data = await response.json();
      } catch (error) {
        data = null;
      }
    }
    return { status: response.status, data: data, retry: response.headers.get('Retry-After') };
  }

  function problem(result) {
    if (result.status === 0) {
      return 'The server could not be reached. Check that Remediation Zero is still running, then try again.';
    }
    if (result.status === 409 && !result.data) {
      return 'Another change from this page is still running. Wait for it to finish, then try again.';
    }
    if (result.data && typeof result.data.error === 'string') {
      const wait = result.status === 429 && /^[0-9]+$/.test(result.retry || '')
        ? ' Try again in about ' + result.retry + ' seconds.' : '';
      return result.data.error + wait;
    }
    if (result.status === 403) {
      return 'Your session ended, or your account cannot change model connections. Reload the page and sign in again.';
    }
    return 'That did not work (HTTP ' + result.status + '). Nothing was changed.';
  }

  // A change: a lapsed re-confirm (401 {"confirm": true}) asks in place, then sends the same
  // request again with the same values.
  async function change(path, body, from) {
    const mine = state;
    state.pending = { path: path, body: body, from: from };
    busy(true);
    const result = await post(path, body);
    if (state !== mine) {
      // The popup that asked was closed meanwhile: whatever happened, read the list again.
      location.assign(PAGE);
      return;
    }
    busy(false);
    if (result.status === 401 && result.data && result.data.confirm === true) {
      confirmed = false;
      state.afterConfirm = () => {
        const again = state.pending;
        show(again.from);
        change(again.path, again.body, again.from);
      };
      show('confirm');
      return;
    }
    state.pending = null;
    if (result.status === 503 || from === 'wait' || (result.status === 200 && result.data && result.data.ok === true)) {
      reloadOnClose = true;   // something changed, or may have: the list is read again on close
    }
    finished(result, from);
  }

  async function confirm() {
    const password = fields.password.value;
    const code = fields.code.value.trim();
    if (!password || !code) {
      say('confirm', 'Enter your password and a code from your authenticator app.');
      return;
    }
    const body = { password: password, code: code };
    const mine = state;
    busy(true);
    const result = await post('/connections/confirm', body);
    if (state !== mine) {
      return;
    }
    busy(false);
    fields.password.value = '';
    fields.code.value = '';
    if (result.status === 200 && result.data && result.data.ok === true) {
      confirmed = true;
      say('confirm', '');
      const then = state.afterConfirm;
      state.afterConfirm = null;
      then();
    } else {
      say('confirm', problem(result));
    }
  }

  // --- step 1: the provider -------------------------------------------------------

  function filterTiles() {
    const wanted = fields.search.value.trim().toLowerCase();
    let shown = 0;
    for (const tile of dialog.querySelectorAll('[data-provider]')) {
      const name = PRESETS.get(tile.dataset.provider).name.toLowerCase();
      tile.hidden = wanted !== '' && name.indexOf(wanted) < 0;
      shown += tile.hidden ? 0 : 1;
    }
    inCard('provider', '[data-none]').hidden = shown > 0;
  }

  function choose(provider) {
    if (state.provider !== provider) {
      // A different provider: what was typed for the other one does not carry over.
      for (const input of [fields.key, fields.address, fields.base, fields.ca]) {
        input.value = '';
      }
      heldKey = '';
      keyEpoch += 1;
      fields.format.selectedIndex = 0;
      state.listed = null;
      state.advised = null;
      state.provider = provider;
    }
    enter('key');
  }

  // --- step 2: the key, or the address ---------------------------------------------

  function prepareKey() {
    if (heldKey) {
      fields.key.value = heldKey;
      heldKey = '';
    }
    const preset = PRESETS.get(state.provider);
    const local = state.provider === 'ollama';
    const other = state.provider === 'other';
    const replacing = state.mode === 'replace';
    setMark('key');
    const title = inCard('key', '[data-title]');
    const line = inCard('key', '[data-line]');
    if (replacing) {
      title.textContent = 'A new key for ' + state.conn.name;
      line.textContent = 'Every job it does is tested with the new key before it replaces the stored one. '
        + 'Saved on this server where only Remediation Zero can read it. We\'ll never show it again.';
    } else if (local) {
      title.textContent = 'Your Ollama address';
      line.textContent = 'The address of an Ollama you already run. Nothing is downloaded or installed.';
    } else if (other) {
      title.textContent = 'Your model server';
      line.textContent = 'Its request format and address, and its key if it needs one. A key is saved on this '
        + 'server where only Remediation Zero can read it. We\'ll never show it again.';
    } else {
      title.textContent = 'Your ' + preset.name + ' key';
      line.textContent = 'Saved on this server where only Remediation Zero can read it. We\'ll never show it again.';
    }
    const showField = (name, on) => {
      inCard('key', '[data-field="' + name + '"]').hidden = !on;
    };
    showField('format', other && !replacing);
    showField('address', local || other);
    showField('key', preset.needs_key || other);
    showField('base', !(local || other));
    inCard('key', '[data-key-label]').textContent = other ? 'API key (if it needs one)' : 'API key';
    inCard('key', '[data-address-label]').textContent = replacing ? 'Address (leave blank to keep it)' : 'Address';
    fields.base.placeholder = replacing ? 'Leave blank to keep ' + (state.conn.base_url || 'the current address')
      : preset.base_url;
    if (local && !replacing && !fields.address.value) {
      fields.address.value = preset.base_url;
    }
    const link = inCard('key', '[data-keypage]');
    const page = preset.key_page || '';
    link.hidden = page.indexOf('https://') !== 0;
    if (!link.hidden) {
      link.href = page;
    }
    say('key', '');
  }

  function keyDone() {
    const preset = PRESETS.get(state.provider);
    if (preset.needs_key && !fields.key.value.trim()) {
      say('key', state.mode === 'replace' ? 'Enter the new key.' : 'Enter the key.');
      fields.key.focus();
      return;
    }
    if (state.provider === 'other' && state.mode === 'add' && !fields.address.value.trim()) {
      say('key', 'Enter the address of the model server.');
      fields.address.focus();
      return;
    }
    heldKey = fields.key.value;
    fields.key.value = '';      // before the card is hidden: see heldKey
    enter(state.flow[state.flow.indexOf('key') + 1]);
  }

  function baseUrl() {
    const typed = ['ollama', 'other'].indexOf(state.provider) >= 0 ? fields.address : fields.base;
    return typed.value.trim();
  }

  function format() {
    return state.provider === 'other' ? fields.format.value : PRESETS.get(state.provider).format;
  }

  // --- step 3: the model ----------------------------------------------------------

  function prepareModel() {
    setMark('model');
    say('model', '');
  }

  function listBody() {
    if (state.mode === 'edit') {
      return { connection: state.connection };
    }
    const body = { provider: state.provider, base_url: baseUrl(), ca_file: fields.ca.value.trim(),
                   key: heldKey };
    if (state.provider === 'other') {
      body.format = format();
    }
    return body;
  }

  async function listModels() {
    const body = listBody();
    // Signed without the key itself, so nothing but heldKey and the request keeps it.
    const signature = JSON.stringify(Object.assign({}, body, { key: 'epoch ' + keyEpoch }));
    if (state.listed === signature) {
      return;   // listed once for these values; Back and Continue do not ask again
    }
    state.listed = signature;
    const list = inCard('model', '[data-models]');
    list.replaceChildren();
    status('model', 'Asking for the models it lists…');
    busy(true);
    const mine = state;
    const result = await post('/connections/models', body);
    if (state !== mine) {
      return;
    }
    busy(false);
    if (state.listed !== signature) {
      return;
    }
    if (result.status !== 200 || !result.data || !Array.isArray(result.data.models)) {
      state.listed = null;    // not listed: entering this step again asks again
      status('model', '');
      say('model', sentence(problem(result)) + ' You can type the model name instead.',
          result.data && result.data.hint ? result.data.hint : '');
      fields.model.focus();
      return;
    }
    const data = result.data;
    status('model', data.models.length ? '' : 'It listed no models. Type the model name.');
    if (!fields.model.value && typeof data.suggested === 'string') {
      fields.model.value = data.suggested;
    }
    for (const name of data.models) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'rz-model';
      button.dataset.model = name;
      const label = text('span', name, 'rz-model-name');
      button.append(label);
      if (name === data.suggested) {
        button.append(text('span', 'Suggested', 'rz-badge rz-badge-rec'));
      }
      const line = data.lines && typeof data.lines[name] === 'string' ? data.lines[name] : '';
      if (line) {
        button.append(text('span', line, 'rz-model-line'));
      }
      list.append(button);
    }
    markModel();
  }

  function markModel() {
    const chosen = fields.model.value.trim();
    for (const button of inCard('model', '[data-models]').querySelectorAll('button')) {
      button.setAttribute('aria-pressed', button.dataset.model === chosen ? 'true' : 'false');
    }
  }

  function modelDone() {
    const model = fields.model.value.trim();
    if (!model || model.length > 200) {
      say('model', 'Pick a model, or type its name (at most 200 characters).');
      fields.model.focus();
      return;
    }
    const timeout = Number(fields.timeout.value);
    if (!Number.isInteger(timeout) || timeout < 5 || timeout > 600) {
      say('model', 'The timeout is a whole number of seconds, 5 to 600.');
      return;
    }
    if (state.held && state.held.length && !state.familyTouched && model !== state.held[0].model) {
      fields.family.value = '';   // the family shown was the old model's; detect the new one's
    }
    enter('jobs');
  }

  // --- step 4: the jobs -----------------------------------------------------------

  function prepareJobs() {
    say('jobs', '');
  }

  function pill(job) {
    let words;
    if (job.overridden) {
      words = 'set on the server' + (job.model ? ' · ' + job.model : '');
    } else if (job.connection === null && job.model === null) {
      words = 'nobody';
    } else {
      words = (job.connection || 'set on the server') + ' · ' + job.model;
    }
    if (job.family_note) {
      words += ' · ' + job.family_note;
    }
    const gap = !job.overridden && job.connection === null && job.model === null;
    const item = text('li', '', 'rz-pill ' + (gap ? 'rz-gap' : 'rz-ok'));
    item.append(text('strong', job.job), document.createTextNode(' ' + words));
    return item;
  }

  async function advise() {
    const body = { provider: state.provider, model: fields.model.value.trim() };
    if (fields.family.value) {
      body.family = fields.family.value;
    }
    if (state.mode === 'edit') {
      body.editing = state.connection;
    }
    const signature = JSON.stringify(body);
    if (state.advised === signature) {
      return;   // the same model: the switches stay as they were left
    }
    state.advised = signature;
    const jobs = inCard('jobs', '[data-jobs]');
    jobs.replaceChildren();
    inCard('jobs', '[data-cover]').replaceChildren();
    status('jobs', 'Working out what it should do…');
    busy(true);
    const mine = state;
    const result = await post('/connections/recommend', body);
    if (state !== mine) {
      return;
    }
    busy(false);
    if (state.advised !== signature) {
      return;
    }
    status('jobs', '');
    if (result.status !== 200 || !result.data || !Array.isArray(result.data.cards)) {
      state.advised = null;
      say('jobs', problem(result));
      return;
    }
    say('jobs', '');
    inCard('jobs', '[data-cover]').append(...result.data.coverage.map(pill));
    const held = new Set((state.held || []).map((j) => j.role));
    state.cards = result.data.cards;
    state.on = {};
    for (const advice of state.cards) {
      // A job this connection already does stays on when editing; nothing else starts on unless advised.
      state.on[advice.role] = advice.on === true || held.has(advice.role);
      jobs.append(jobCard(advice));
    }
  }

  function jobCard(advice) {
    const box = text('div', '', 'rz-job');
    const icon = $('rz-icon-' + advice.role);
    if (icon) {
      box.append(icon.content.cloneNode(true));
    }
    const main = text('div', '', 'rz-job-main');
    const title = text('p', '', 'rz-job-title');
    const badge = BADGES[advice.badge] || ['', 'mute'];
    title.append(text('strong', advice.job), text('span', badge[0], 'rz-badge rz-badge-' + badge[1]));
    main.append(title, text('p', advice.description, 'rz-d'),
                text('p', advice.reason, 'rz-why rz-why-' + badge[1]));
    if (advice.cost) {
      main.append(text('p', advice.cost, 'rz-d'));
    }
    if (advice.policy_note) {
      const note = text('p', advice.policy_note + ' ', 'rz-why rz-why-warn');
      const link = text('a', 'Change it (opens in a new tab)');
      link.href = PAGE + '#rz-policy';
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      note.append(link);
      main.append(note);
    }
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'rz-switch';
    toggle.setAttribute('role', 'switch');
    toggle.setAttribute('aria-label', 'Use it for ' + advice.job);
    const paint = () => {
      toggle.setAttribute('aria-checked', state.on[advice.role] ? 'true' : 'false');
      box.classList.toggle('rz-on', state.on[advice.role]);
    };
    toggle.addEventListener('click', () => {
      state.on[advice.role] = !state.on[advice.role];
      paint();
    });
    paint();
    box.append(main, toggle);
    return box;
  }

  function chosenJobs() {
    const out = {};
    for (const role of ROLES) {
      if (state.on[role]) {
        const choice = { model: fields.model.value.trim(), timeout_seconds: Number(fields.timeout.value) };
        if (fields.family.value) {
          choice.family = fields.family.value;
        }
        out[role] = choice;
      }
    }
    return out;
  }

  function jobsDone() {
    if (!state.cards.length) {
      say('jobs', 'The suggestions did not load. Go back and continue again.');
      return;
    }
    if (state.mode === 'add' && !Object.keys(chosenJobs()).length) {
      say('jobs', NO_JOBS);
      return;
    }
    enter('test');
  }

  // --- step 5: test and save --------------------------------------------------------

  function uniqueName(base) {
    const taken = new Set(DATA.connections.map((c) => c.name.toLowerCase()));
    let name = base;
    for (let n = 2; taken.has(name.toLowerCase()) && n < 100; n += 1) {
      name = base + ' ' + n;
    }
    return name;
  }

  function prepareTest() {
    const adding = state.mode === 'add';
    inCard('test', '[data-field="name"]').hidden = !adding;
    if (adding && !fields.name.value.trim()) {
      fields.name.value = uniqueName(PRESETS.get(state.provider).name);
    }
    const summary = inCard('test', '[data-summary]');
    summary.replaceChildren();
    const jobs = state.mode === 'replace'
      ? state.conn.jobs.map((j) => [j.job, j.model])
      : ROLES.filter((r) => state.on[r]).map((r) => [JOB_NAMES.get(r), fields.model.value.trim()]);
    for (const [job, model] of jobs) {
      const item = text('li', '');
      item.append(text('strong', job), document.createTextNode(' ' + model));
      summary.append(item);
    }
    if (!jobs.length) {
      summary.append(text('li', state.mode === 'edit'
        ? 'No jobs: saving takes every job away from this connection.'
        : 'It does no jobs, so there is nothing to test. The new key is checked and saved.'));
    }
    status('test', '');
    say('test', '');
  }

  function test() {
    say('test', '');
    status('test', 'Testing. A slow model can take a minute or more to answer.');
    if (state.mode === 'add') {
      const jobs = chosenJobs();
      if (!Object.keys(jobs).length) {
        status('test', '');
        say('test', NO_JOBS);
        return;
      }
      change('/connections/save', { draft: { provider: state.provider, name: fields.name.value.trim(),
        format: format(), base_url: baseUrl(), ca_file: fields.ca.value.trim(), key: heldKey,
        jobs: jobs } }, 'test');
    } else if (state.mode === 'edit') {
      change('/connections/edit', { connection: state.connection, jobs: chosenJobs() }, 'test');
    } else {
      const body = { connection: state.connection, key: heldKey };
      if (baseUrl()) {
        body.base_url = baseUrl();
      }
      if (fields.ca.value.trim()) {
        body.ca_file = fields.ca.value.trim();
      }
      change('/connections/replace-key', body, 'test');
    }
  }

  function seconds(value) {
    return (typeof value === 'number' && isFinite(value) ? value : 0).toFixed(1) + ' s';
  }

  function finished(result, from) {
    const data = result.data;
    if (from === 'delete') {
      if (result.status === 200 && data && data.ok === true) {
        done(true, state.conn.name + ' is deleted', 'Its key and its jobs were removed.', '', data.audit === false);
      } else if (result.status === 503 && data && data.error) {
        done(false, state.conn.name + ' is deleted', data.error, '', data.audit === false);
      } else {
        say('delete', problem(result));
      }
      return;
    }
    if (from === 'wait') {
      const name = state.conn.name;
      if (result.status === 200 && data && data.ok === true) {
        done(true, name + ' passed', 'It answered in ' + seconds(data.seconds) + '. Tested: ' + and(data.jobs) + '.');
      } else if (result.status === 200 && data && data.ok === false) {
        done(false, name + ' did not pass', data.error, data.hint || '');
      } else {
        done(false, name + ' was not tested', problem(result));
      }
      return;
    }
    status('test', '');
    if (result.status !== 200 || !data || data.ok !== true) {
      // A failed test saves nothing; the typed values stay for Back.
      say('test', data && data.ok === false ? sentence(data.error) + ' Nothing was saved.' : problem(result),
          data && data.hint ? data.hint : '');
      return;
    }
    const does = data.jobs.length ? 'It now does ' + and(data.jobs) + '.' : 'It does no jobs now.';
    const answered = data.seconds > 0 ? 'The model answered in ' + seconds(data.seconds) + '. '
      : 'Nothing needed a new test. ';
    const title = state.mode === 'add' ? data.provider + ' is connected!'
      : state.mode === 'edit' ? data.name + ' is updated' : data.name + ' has its new key';
    if (state.mode === 'add') {
      DATA.connections.push({ id: data.connection, name: data.name, provider: state.provider, jobs: [] });
    }
    done(true, title, answered + does, '', data.audit === false);
  }

  function done(ok, title, line, hint, unaudited) {
    const shown = card('done');
    shown.querySelector('[data-icon-ok]').hidden = !ok;
    shown.querySelector('[data-icon-bad]').hidden = ok;
    shown.querySelector('[data-title]').textContent = title;
    shown.querySelector('[data-line]').textContent = line;
    const hintNode = shown.querySelector('[data-hint]');
    hintNode.textContent = hint || '';
    hintNode.hidden = !hint;
    shown.querySelector('[data-audit]').hidden = !unaudited;
    shown.querySelector('[data-do="another"]').hidden = state.mode !== 'add';
    // The key has done its job: it leaves memory now, whatever is pressed next.
    heldKey = '';
    fields.key.value = '';
    state.pending = null;
    show('done');
  }

  // --- test again ---------------------------------------------------------------------

  function testAgain() {
    inCard('wait', '[data-title]').textContent = 'Testing ' + state.conn.name;
    show('wait');
    status('wait', 'One short request for each job it does. A slow model can take a minute or more.');
    change('/connections/test', { connection: state.connection }, 'wait');
  }

  // --- wiring -------------------------------------------------------------------------

  for (const opener of document.querySelectorAll('[data-action]')) {
    opener.addEventListener('click', () => {
      const action = opener.dataset.action;
      const connId = opener.dataset.connection || null;
      if (action !== 'add' && !CONNECTIONS.has(connId)) {
        return;
      }
      begin(action, connId);
    });
  }

  const actions = {
    cancel: closeDialog,
    back: back,
    next: () => {
      if (state.card === 'key') {
        keyDone();
      } else if (state.card === 'model') {
        modelDone();
      } else if (state.card === 'jobs') {
        jobsDone();
      }
    },
    confirm: confirm,
    test: test,
    delete: () => whenConfirmed(() => {
      show('delete');
      change('/connections/delete', { connection: state.connection }, 'delete');
    }),
    another: () => begin('add', null),
    done: closeDialog,
  };

  dialog.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target || !state) {
      return;
    }
    const tile = target.closest('[data-provider]');
    if (tile) {
      choose(tile.dataset.provider);
      return;
    }
    const model = target.closest('[data-model]');
    if (model) {
      fields.model.value = model.dataset.model;
      markModel();
      return;
    }
    const button = target.closest('[data-do]');
    if (button && !button.disabled && actions[button.dataset.do]) {
      actions[button.dataset.do]();
    }
  });

  dialog.addEventListener('keydown', (event) => {
    // Enter in a box presses the card's dark button, as a form would.
    if (event.key === 'Enter' && event.target instanceof HTMLInputElement && state) {
      const primary = card(state.card).querySelector('[data-primary]');
      if (primary && !primary.disabled && !primary.hidden) {
        event.preventDefault();
        primary.click();
      }
    }
  });

  fields.search.addEventListener('input', filterTiles);
  fields.model.addEventListener('input', markModel);
  fields.family.addEventListener('change', () => {
    if (state) {
      state.familyTouched = true;
    }
  });

  dialog.addEventListener('cancel', (event) => {
    // Escape closes, unless a request is still running: then the popup waits for its answer.
    if (state && state.busy) {
      event.preventDefault();
    } else {
      heldKey = '';
      fields.key.value = '';
    }
  });

  fields.key.addEventListener('input', () => {
    keyEpoch += 1;
  });

  dialog.addEventListener('close', () => {
    clearAll();
    if (reloadOnClose) {
      location.assign(PAGE);
    }
  });
}());

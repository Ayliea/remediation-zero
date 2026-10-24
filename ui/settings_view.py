# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Local settings pages. Rendering never contacts a model."""
from html import escape

SECTIONS = {'model': 'Model connection', 'storage': 'Data & storage',
            'application': 'Application', 'safety': 'Safety & limits', 'updates': 'Updates'}


def render_settings(values, section, token, *, message='', key_present=False, overrides=False):
    e = lambda v: escape(str(v), quote=True)
    tabs = '<nav class="settings-tabs" aria-label="Settings sections">' + ''.join(
        f'<a href="/?view=settings&amp;section={k}" aria-current="{"page" if k == section else "false"}">{v}</a>'
        for k, v in SECTIONS.items()) + '</nav>'
    def form(contents):
        return f'<form method="post" action="/settings"><input type="hidden" name="token" value="{e(token)}"><input type="hidden" name="section" value="{section}">{contents}<div class="row"><button type="submit">Save preferences</button><a href="/?view=settings&amp;section={section}">Cancel</a></div></form>'
    connection = values['roles']['proposer'] or {'endpoint': '', 'model': ''}
    if section == 'model':
        body = '<h2>Your model, your choice</h2><p>Use a local or hosted OpenAI-compatible chat-completions endpoint. Saving makes no model calls.</p>'
        body += form(f'<label>Endpoint URL<input name="endpoint" type="url" maxlength="2048" value="{e(connection["endpoint"])}" placeholder="http://localhost:11434/v1/chat/completions"></label><p class="muted">Use the full chat-completions URL. Hosted endpoints require HTTPS. Leave both fields blank to disconnect.</p><label>Model name<input name="model" maxlength="200" value="{e(connection["model"])}"></label>')
        body += f'<h3>API key</h3><p>Environment key: {"present" if key_present else "not set"}. Keys are never displayed or saved here. Set RZ_MODEL_API_KEY before starting the app.</p><p>Connection status: Not tested. Saving does not verify availability.</p>'
        if overrides:
            body += '<p class="notice">RZ_MODEL_ENDPOINT or RZ_MODEL is set in this process. Environment values override saved preferences for command-line runs.</p>'
        body += '<details><summary>Run an optional sample check</summary><p>From your installation folder, run <code>python3 -m scripts.local suggest-demo</code>. This sends the bundled synthetic example to your endpoint and may incur provider charges. On Windows, use <code>py -3.12</code>. Use the same database and environment as the dashboard. No check runs when you open this page.</p><p>Existing cycles replay saved results. Changing the endpoint or model requires a new cycle; do not delete history to bypass limits.</p></details>'
    elif section == 'application':
        options = ''.join(f'<option value="{v}" {"selected" if values["mode"] == v else ""}>{label}</option>' for v, label in [('demo','Demo examples'),('saved','Saved records')])
        body = '<h2>Make it yours</h2><p>These preferences apply the next time you start the installed launcher. Command-line flags take priority.</p>'
        body += form(f'<label>Open by default<select name="mode">{options}</select></label><label class="check"><input name="open_browser" type="checkbox" value="yes" {"checked" if values["open_browser"] else ""}> Open browser on startup</label><label>Dashboard port<input name="port" type="number" min="1024" max="65535" required value="{values["port"]}"></label><p>Restart required. The current dashboard stays on its existing port.</p>')
        body += '<h3>Local access</h3><p>Host: 127.0.0.1 (fixed). No sign-in is provided. Do not expose this preview through a public proxy. It stops when you stop the launcher.</p><p>Recorded times are displayed in UTC.</p>'
    elif section == 'storage':
        body = '<h2>Your data stays with you</h2><p>Storage: SQLite. Database location is selected with the <code>--database</code> command-line option; the installed launcher uses <code>remediation-zero.sqlite3</code> in its installation folder.</p><p>Backup status: Not tracked.</p><details><summary>Back up your workspace</summary><ol><li>Stop the launcher and any command-line model runs.</li><li>Copy the database and its matching .settings.json file to a private backup folder.</li><li>Restart the launcher.</li></ol><p>Environment API keys are not included. Keep backups private: suggestions and evidence may contain sensitive information.</p></details><details><summary>Restore a backup</summary><p>Stop all app processes first. Preserve the current database and settings before replacing them with a matching backup. Restart after restoring. Restoring older data may lose request history; do not use it to reset retry limits.</p></details><h3>What is stored</h3><p>Suggestions, evidence, request history, and recorded timestamps. Preferences are stored separately as JSON. API keys are read from the environment.</p>'
    elif section == 'safety':
        body = '<h2>Clear boundaries</h2><p>This preview does not change infrastructure. Local model suggestions are unreviewed; an independent reviewer is not implemented in the local edition. Calls happen only through an explicit command.</p><dl><dt>Requests per model stage</dt><dd>4 attempts maximum, recorded durably</dd><dt>Output token limit</dt><dd>2,048 tokens per request</dd><dt>Input size</dt><dd>32 KiB</dd><dt>Response size</dt><dd>64 KiB</dd><dt>Socket timeout</dt><dd>60 seconds per blocking operation, not a total run deadline</dd></dl><details><summary>Recovery and cost details</summary><p>Completed requests are replayed, rejection evidence is retained, and exhausted requests cannot be retried by refreshing. A changed model configuration cannot replay an existing cycle.</p><p>These limits are fixed. There is no global spending cap. A local gateway may forward requests to a paid hosted provider.</p></details>'
    else:
        body = '<h2>Keep your workspace intact</h2><dl><dt>Edition</dt><dd>Local preview</dd><dt>Version</dt><dd>Development build</dd><dt>Update check</dt><dd>Unavailable — no automatic check runs</dd></dl><details><summary>Install a newer preview</summary><ol><li>Stop the app and back up your database and preferences.</li><li>Install the new build into a separate directory.</li><li>Keep the original installation until you have verified the new version.</li></ol><p>There is no automatic upgrade or database migration workflow. Do not overwrite your existing installation.</p></details><details><summary>Destination already exists</summary><p>Use its start-remediation-zero.py launcher, or choose a new directory with the installer’s --directory option. Nothing was overwritten.</p></details><details><summary>Port already in use</summary><p>Stop the previous launcher or start with --port 8082.</p></details><p>Installer signatures are not available. Checksums detect corruption; they do not establish publisher authenticity.</p>'
    return tabs + (f'<p role="status" class="notice">{e(message)}</p>' if message else '') + '<section class="card settings-card">' + body + '</section>'

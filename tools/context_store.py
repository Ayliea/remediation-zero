# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Writing the owner's business context: facts on assets, and custom labels.

The `context` stage's docstore may write the asset documents and the context collections
and nothing else (tools.local_layout). Callers check `manage_context` and write the audit
row (Accounts.record_context_change); this module only keeps the data consistent. Every
write of several assets is one batch, so a request changes all of them or none.

Business time comes from SimClock: each stored fact carries a Provenance stamped here.
Standard library only.
"""
import hashlib
import secrets
from typing import Any, Iterable, Optional

from tools import context
from tools.clock import SimClock
from tools.context_import import MAX_PENDING_ROWS, ROW_TTL_SECONDS, ColumnMapping, Preview

LABELS = "context_labels"
SUGGESTIONS = "context_suggestions"
MAPPINGS = "context_mappings"
ASSETS = "assets"


class ContextWriter:
    def __init__(self, docs: Any, clock: SimClock) -> None:
        self._docs = docs
        self._clock = clock

    def _prov(self, source: str, account: str) -> context.Provenance:
        stamp = self._clock.now()
        return context.Provenance(source, account, stamp.real_ts, stamp.sim_ts)

    def _assets(self, asset_ids: Iterable[str]) -> list[tuple[Any, dict]]:
        found = []
        for asset_id in dict.fromkeys(asset_ids):
            ref = self._docs.collection(ASSETS).document(asset_id)
            snapshot = ref.get()
            if not snapshot.exists:
                raise KeyError(f"unknown asset: {asset_id}")
            found.append((ref, snapshot.to_dict() or {}))
        return found

    def labels(self) -> dict[str, dict]:
        """Custom labels by id: name, effect, who created them and when."""
        return {s.id: s.to_dict() or {} for s in self._docs.collection(LABELS).stream()}

    def custom_labels(self) -> dict[str, str]:
        """Label id -> effect, the shape tools.context.effective_facts takes."""
        return {label_id: row.get("effect") for label_id, row in self.labels().items()}

    def set_facts(self, asset_ids: list[str], changes: dict, *, source: str, account: str) -> list[str]:
        """Set facts on each asset; the ids whose effective facts changed."""
        prov, custom = self._prov(source, account), self.custom_labels()
        batch, changed = self._docs.batch(), []
        for ref, row in self._assets(asset_ids):
            fields, summary = context.apply_facts(row, changes, prov, custom)
            if fields:
                batch.update(ref, fields)
            if summary:
                changed.append(ref.id)
        batch.commit()
        return changed

    def add_label(self, name: str, effect: str, *, account: str) -> str:
        """A new custom label's id. Names are unique ignoring case."""
        name = context.validate_label_name(name)
        if effect not in context.EFFECTS:
            raise ValueError(f"unknown label effect {effect!r}")
        if any((row.get("name") or "").lower() == name.lower() for row in self.labels().values()):
            raise ValueError("A label with that name already exists.")
        prov = self._prov("direct", account)
        label_id = f"lbl-{secrets.token_hex(6)}"
        self._docs.collection(LABELS).document(label_id).create(
            {"label_id": label_id, "name": name, "effect": effect, "created_by": account,
             "real_ts": prov.real_ts, "sim_ts": prov.sim_ts})
        return label_id

    def _relabel(self, rows: list[tuple[Any, dict]], new_labels: dict, before: dict,
                 after: dict, account: str) -> list[str]:
        """Write each asset's new label list; mark those whose effective facts changed."""
        prov = self._prov("direct", account)
        batch, changed = self._docs.batch(), []
        for ref, row in rows:
            asset_id = ref.id
            labels = new_labels[asset_id]
            fields: dict = {"context_labels": labels}
            summary = context.change_summary(context.effective_facts(row, before),
                                             context.effective_facts({**row, "context_labels": labels}, after))
            if summary:
                fields.update(context.changed_marker(prov, summary))
                changed.append(asset_id)
            batch.update(ref, fields)
        batch.commit()
        return changed

    def _label(self, label_id: str) -> dict:
        snapshot = self._docs.collection(LABELS).document(label_id).get()
        if not snapshot.exists:
            raise KeyError(f"unknown label: {label_id}")
        return snapshot.to_dict() or {}

    def tag(self, asset_ids: list[str], label_id: str, *, account: str) -> list[str]:
        """Add a custom label to each asset; the ids that did not already carry it."""
        self._label(label_id)
        custom = self.custom_labels()
        rows = [(r, d) for r, d in self._assets(asset_ids) if label_id not in (d.get("context_labels") or [])]
        self._relabel(rows, {r.id: [*(d.get("context_labels") or []), label_id]
                             for r, d in rows}, custom, custom, account)
        return [r.id for r, _ in rows]

    def untag(self, asset_ids: list[str], label_id: str, *, account: str) -> list[str]:
        """Take a custom label off each asset; the ids that carried it."""
        custom = self.custom_labels()
        rows = [(r, d) for r, d in self._assets(asset_ids) if label_id in (d.get("context_labels") or [])]
        self._relabel(rows, {r.id: [x for x in d["context_labels"] if x != label_id]
                             for r, d in rows}, custom, custom, account)
        return [r.id for r, _ in rows]

    def remove_label(self, label_id: str, *, account: str) -> list[str]:
        """Delete a custom label and take it off every asset; the ids whose effective facts changed."""
        self._label(label_id)
        before = self.custom_labels()
        after = {k: v for k, v in before.items() if k != label_id}
        rows = [(self._docs.collection(ASSETS).document(s.id), s.to_dict() or {})
                for s in self._docs.collection(ASSETS).stream()]
        rows = [(r, d) for r, d in rows if label_id in (d.get("context_labels") or [])]
        changed = self._relabel(rows, {r.id: [x for x in d["context_labels"] if x != label_id]
                                       for r, d in rows}, before, after, account)
        self._docs.collection(LABELS).document(label_id).delete()
        return changed

    def pending_rows(self, now_sim_ts: float) -> list[dict]:
        """Unmatched spreadsheet rows that have not expired."""
        return [row for row in (s.to_dict() or {} for s in self._docs.collection(SUGGESTIONS).stream())
                if row.get("kind") == "row" and row.get("expires_sim_ts", 0) > now_sim_ts]

    def apply_upload(self, preview: Preview, mapping: ColumnMapping, *, account: str) -> int:
        """Apply a preview's changes, keep its unmatched rows as suggestions and remember the
        mapping, in one batch; the number of assets whose effective facts changed. ValueError,
        and nothing written, when the rows would take pending suggestions over MAX_PENDING_ROWS."""
        prov, custom = self._prov("spreadsheet", account), self.custom_labels()
        pending = {row["key"] for row in self.pending_rows(prov.sim_ts)}
        if len(pending | {key for key, _ in preview.unmatched}) > MAX_PENDING_ROWS:
            raise ValueError(f"At most {MAX_PENDING_ROWS} rows can wait for a host the scanner has not "
                             "reported. Remove rows for hosts you no longer have and upload again.")
        batch, changed = self._docs.batch(), 0
        for ref, row in self._assets(preview.changes):
            fields, summary = context.apply_facts(row, preview.changes[ref.id], prov, custom)
            if fields:
                batch.update(ref, fields)
            changed += bool(summary)
        for key, facts in preview.unmatched:
            doc_id = "row-" + hashlib.sha256(key.encode()).hexdigest()[:24]
            batch.set(self._docs.collection(SUGGESTIONS).document(doc_id),
                      {"kind": "row", "key": key, "facts": dict(facts), "created_by": account,
                       "real_ts": prov.real_ts, "sim_ts": prov.sim_ts,
                       "expires_sim_ts": prov.sim_ts + ROW_TTL_SECONDS})
        batch.set(self._docs.collection(MAPPINGS).document("default"), mapping.to_dict())
        batch.commit()
        return changed

    def saved_mapping(self) -> Optional[ColumnMapping]:
        """The column mapping the last upload used, if any."""
        row = self._docs.collection(MAPPINGS).document("default").get().to_dict()
        return ColumnMapping(row["host_column"], dict(row["fact_columns"])) if row else None

    def asset_facts(self, asset_id: str) -> Optional[dict]:
        """The effective facts of one asset, or None when there is no such asset."""
        snapshot = self._docs.collection(ASSETS).document(asset_id).get()
        if not snapshot.exists:
            return None
        return context.effective_facts(snapshot.to_dict() or {}, self.custom_labels())

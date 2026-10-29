# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Business context: what the owner has said about a host, and where each fact came from.

Four facts describe a host to triage: criticality, internet_facing, environment and
sensitive_data. Each is set, or not known (`None`). A fact set on the host itself, by the
questions, a spreadsheet, an approved rule suggestion or a direct edit, wins; a custom
label's effect fills only a fact that is not known. Seeded synthetic assets carry the first
three as top-level fields, which count as set.

A change is a change to the *effective* facts. Re-saving a value, or setting one a label
already implies, records its provenance but does not mark the host changed, so it does not
re-rank anything.

No clock is read here: callers pass a `Provenance` stamped by SimClock. Standard library only.
"""
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping

FACTS = ("criticality", "internet_facing", "environment", "sensitive_data")
FACT_NAMES = {"criticality": "Criticality", "internet_facing": "Internet-facing",
              "environment": "Environment", "sensitive_data": "Sensitive data"}
_VALUES = {"criticality": {"high", "medium", "low"}, "environment": {"production", "development"},
           "internet_facing": {True, False}, "sensitive_data": {True, False}}
#: The labels every workspace has, each a statement about one fact. The last two let the
#: owner lower urgency deliberately rather than by leaving a label off.
BUILTIN_LABELS = {"crown_jewels": ("criticality", "high"),
                  "internet_facing": ("internet_facing", True),
                  "production": ("environment", "production"),
                  "sensitive_data": ("sensitive_data", True),
                  "development": ("environment", "development"),
                  "not_internet_facing": ("internet_facing", False)}
#: What a custom label may do: act as one of two built-in labels, or only group hosts.
EFFECTS = ("crown_jewels", "sensitive_data", "grouping")
SOURCES = ("questions", "spreadsheet", "rule", "direct")
_LABEL_NAME = re.compile(r"[A-Za-z0-9 ._-]{1,40}")
LABEL_NAME_RULE = "Label names are up to 40 letters, digits, spaces, - _ or ."


@dataclass(frozen=True)
class Provenance:
    """Who set a fact, how, and when (wall clock and SimClock)."""
    source: str
    account: str
    real_ts: float
    sim_ts: float

    def __post_init__(self) -> None:
        if self.source not in SOURCES:
            raise ValueError(f"unknown context source {self.source!r}")


def validate_label_name(name: str) -> str:
    """The name, stripped; ValueError unless it keeps to LABEL_NAME_RULE."""
    stripped = name.strip() if isinstance(name, str) else ""
    if not _LABEL_NAME.fullmatch(stripped) or not stripped.strip():
        raise ValueError(LABEL_NAME_RULE)
    return stripped


def _set_facts(asset: Mapping[str, Any]) -> dict:
    facts = {f: asset.get(f) for f in ("criticality", "internet_facing", "environment")
             if asset.get(f) is not None}
    facts.update({f: v for f, v in (asset.get("context_facts") or {}).items() if v is not None})
    return facts


def effective_facts(asset: Mapping[str, Any], custom_labels: Mapping[str, str]) -> dict:
    """Each fact's value for triage, `None` when not known. `custom_labels`: label id -> effect."""
    facts = dict.fromkeys(FACTS)
    for label in asset.get("context_labels") or ():
        effect = custom_labels.get(label)
        if effect in ("crown_jewels", "sensitive_data"):
            fact, value = BUILTIN_LABELS[effect]
            facts[fact] = value
    facts.update(_set_facts(asset))
    return facts


def _show(value: Any) -> str:
    return "not known" if value is None else "yes" if value is True else "no" if value is False else str(value)


def change_summary(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    """One line per fact whose effective value differs, e.g. 'Environment: production → development'."""
    return [f"{FACT_NAMES[f]}: {_show(before.get(f))} → {_show(after.get(f))}"
            for f in FACTS if before.get(f) != after.get(f)]


def _check(fact: str, value: Any) -> None:
    if fact not in _VALUES:
        raise ValueError(f"unknown context fact {fact!r}")
    if value is not None and (value not in _VALUES[fact] or type(value) is not type(next(iter(_VALUES[fact])))):
        raise ValueError(f"{FACT_NAMES[fact]} cannot be {value!r}")


def apply_facts(asset: Mapping[str, Any], changes: Mapping[str, Any], prov: Provenance,
                custom_labels: Mapping[str, str]) -> tuple[dict, list[str]]:
    """(fields to write on the asset document, summary lines). `changes`: fact -> value or None.

    ({}, []) when nothing stored would change. When stored facts change but the effective ones
    do not, the facts and provenance are returned without the changed-marker fields.
    """
    for fact, value in changes.items():
        _check(fact, value)
    stored = dict(asset.get("context_facts") or {})
    current = _set_facts(asset)
    if all(current.get(f) == v for f, v in changes.items()):
        return {}, []
    provenance = dict(asset.get("context_provenance") or {})
    for fact, value in changes.items():
        stored[fact] = value
        provenance[fact] = asdict(prov)
    before = effective_facts(asset, custom_labels)
    after = effective_facts({**asset, "context_facts": stored,
                             **{f: None for f in changes if f in asset}}, custom_labels)
    fields: dict = {"context_facts": stored, "context_provenance": provenance}
    # A top-level seeded field is superseded by the stored fact, so clear it.
    fields.update({f: None for f in changes if asset.get(f) is not None})
    summary = change_summary(before, after)
    if summary:
        fields.update(changed_marker(prov, summary))
    return fields, summary


def changed_marker(prov: Provenance, summary: list[str]) -> dict:
    """The fields that mark a host's effective context as changed, for re-ranking."""
    return {"context_changed_real_ts": prov.real_ts, "context_changed_sim_ts": prov.sim_ts,
            "context_last_change": {"by": prov.account, "summary": list(summary),
                                    "real_ts": prov.real_ts, "sim_ts": prov.sim_ts}}


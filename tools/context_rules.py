# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Rules that suggest business context. A rule never applies itself.

A rule names hosts by IP range (CIDR) or host-name suffix and the facts it would set. When the
scanner reports hosts a rule covers, each one is a suggestion the owner approves or denies.
Spreadsheet rows that matched no host wait as suggestions too, until a scan reports a host
that matches them, for 90 days.

Suggestions are worked out when they are read, from the hosts, the rules, the stored
decisions and the waiting rows; only decisions and rows are stored (tools.context_store).
A host is not suggested what it already has, nor anything for a rule it was denied under.
A fact set on the host after a row was stored wins over that row.

Standard library only. No clock is read here.
"""
import ipaddress
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from tools import context
from tools.context_import import match_host, normalise_host

KINDS = ("cidr", "suffix")


def validate_rule(kind: str, pattern: str, facts: Mapping[str, Any]) -> tuple[str, str, dict]:
    """(kind, normalised pattern, facts); ValueError in plain words for a rule that cannot work."""
    if kind not in KINDS:
        raise ValueError("A rule matches an IP range or the end of a host name.")
    if not facts:
        raise ValueError("A rule must set at least one fact.")
    for fact, value in facts.items():
        context.check_fact(fact, value)
    if kind == "cidr":
        try:
            pattern = str(ipaddress.ip_network(pattern.strip(), strict=False))
        except ValueError:
            raise ValueError("That is not an IP range, such as 192.0.2.0/24.") from None
    else:
        pattern = normalise_host(pattern).removeprefix("*").lstrip(".")
        if not pattern or len(pattern) > 253 or not all(c.isalnum() or c in ".-_" for c in pattern):
            raise ValueError("That is not the end of a host name, such as files.example.com.")
    return kind, pattern, dict(facts)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    kind: str
    pattern: str
    facts: dict

    def covers(self, host: Mapping[str, Any]) -> bool:
        if self.kind == "cidr":
            address = host.get("ip") or host.get("ip_address")
            try:
                return address is not None and ipaddress.ip_address(address.strip()) in ipaddress.ip_network(self.pattern)
            except ValueError:
                return False
        name = normalise_host(host.get("hostname") or "")
        return name == self.pattern or name.endswith("." + self.pattern)


@dataclass(frozen=True)
class Suggestion:
    source_id: str      # a rule id, or a waiting row's id
    asset_id: str
    facts: dict


def _wanted(host: Mapping[str, Any], facts: Mapping[str, Any], custom: Mapping[str, str],
            since: Optional[float] = None) -> dict:
    """The facts a host does not already have; with `since`, also dropping any fact set after it."""
    current = context.effective_facts(host, custom)
    provenance = host.get("context_provenance") or {}
    return {f: v for f, v in facts.items() if current.get(f) != v
            and not (since is not None and (provenance.get(f) or {}).get("sim_ts", 0) > since)}


def suggestions(hosts: list, rules: list, decided: Mapping[tuple, str], rows: list,
                custom: Mapping[str, str]) -> list:
    """Every pending suggestion, rules first in rule order, then rows. `decided`: (rule id,
    asset id) -> "approved" | "denied". `rows`: unexpired waiting rows (id, key, facts, sim_ts)."""
    found = []
    for rule in rules:
        for host in hosts:
            if (rule.rule_id, host["asset_id"]) in decided or not rule.covers(host):
                continue
            if facts := _wanted(host, rule.facts, custom):
                found.append(Suggestion(rule.rule_id, host["asset_id"], facts))
    by_id = {h["asset_id"]: h for h in hosts}
    for row in rows:
        asset_id, how = match_host(hosts, row["key"])
        if how == "matched" and (facts := _wanted(by_id[asset_id], row["facts"], custom, row["sim_ts"])):
            found.append(Suggestion(row["id"], asset_id, facts))
    return found

# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Business context from a spreadsheet: read a CSV, match its rows to hosts, preview the changes.

Any CSV a spreadsheet or asset tool exports: a UTF-8 byte-order mark is dropped, and the
delimiter is whichever of comma, semicolon or tab the header line uses most. `.xlsx` is not
read: that would need a dependency the standard-library edition does not take.

Rows are matched to hosts the scanner reported, never used to create one. A host key matches
a full host name (ignoring case and one trailing dot), a short name only when exactly one host
has it, or an IP only when exactly one host has it. A row that matches several hosts, a value
that cannot be read, or several rows that disagree about one host are problems: shown in the
preview and not applied. Rows that match no host are kept by the writer as suggestions, which
surface when a later scan reports the host.

Nothing is written here. Standard library only.
"""
import csv
import hashlib
import io
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from tools.context import FACT_NAMES, FACTS

MAX_CSV_BYTES = 5 * 1024 * 1024
MAX_CSV_ROWS = 10_000
MAX_PENDING_ROWS = 5_000
ROW_TTL_SECONDS = 90 * 86400
_DELIMITERS = (",", ";", "\t")
_YES = {"yes", "y", "true", "1", "x"}
_NO = {"no", "n", "false", "0"}
_READ = {
    "criticality": {"high": "high", "medium": "medium", "low": "low"},
    "environment": {"production": "production", "prod": "production", "development": "development",
                    "dev": "development", "test": "development", "testing": "development"},
}


@dataclass(frozen=True)
class ColumnMapping:
    """Which column holds the host name or IP, and which column holds each fact."""
    host_column: str
    fact_columns: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        unknown = set(self.fact_columns) - set(FACTS)
        if unknown:
            raise ValueError(f"unknown context facts: {sorted(unknown)}")

    def to_dict(self) -> dict:
        return {"host_column": self.host_column, "fact_columns": dict(self.fact_columns)}


@dataclass
class Preview:
    changes: dict = field(default_factory=dict)      # asset id -> {fact: value}
    problems: list = field(default_factory=list)     # plain sentences, in row order
    unmatched: list = field(default_factory=list)    # (host key, {fact: value})


def normalise_host(name: str) -> str:
    """Lower case, one trailing dot dropped, surrounding space stripped."""
    name = name.strip().lower()
    return name[:-1] if name.endswith(".") else name


def row_id(key: str) -> str:
    """The stored id of a waiting row, from its normalised host key."""
    return "row-" + hashlib.sha256(key.encode()).hexdigest()[:24]


def _ip(host: Mapping[str, Any]) -> Optional[str]:
    return host.get("ip") or host.get("ip_address")


def match_host(hosts: list, key: str) -> tuple[Optional[str], str]:
    """(asset id, "matched") or (None, "ambiguous" | "unmatched")."""
    key = normalise_host(key)
    for found in ([h for h in hosts if normalise_host(h.get("hostname") or "") == key],
                  [h for h in hosts if "." not in key
                   and normalise_host(h.get("hostname") or "").split(".")[0] == key],
                  [h for h in hosts if (_ip(h) or "").strip() == key]):
        if len(found) == 1:
            return found[0]["asset_id"], "matched"
        if found:
            return None, "ambiguous"
    return None, "unmatched"


def read_csv(data: bytes) -> tuple[list[str], list[list[str]]]:
    """(header, rows). ValueError in plain words for a file that cannot be used."""
    if len(data) > MAX_CSV_BYTES:
        raise ValueError("The file is over 5 MB. Split it and upload each part.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("The file is not UTF-8 text. Save it as \"CSV UTF-8\" and try again.") from None
    if not text.strip():
        raise ValueError("The file is empty.")
    first = text.splitlines()[0]
    delimiter = max(_DELIMITERS, key=first.count)
    lines = [row for row in csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
             if any(cell.strip() for cell in row)]
    if len(lines) - 1 > MAX_CSV_ROWS:
        raise ValueError("The file has more than 10,000 rows. Split it and upload each part.")
    return [cell.strip() for cell in lines[0]], [[cell.strip() for cell in row] for row in lines[1:]]


def _value(fact: str, cell: str) -> Any:
    """The fact value a cell says; None for blank; ValueError for anything unreadable."""
    word = cell.strip().lower()
    if not word:
        return None
    if fact in _READ:
        if word in _READ[fact]:
            return _READ[fact][word]
    elif word in _YES:
        return True
    elif word in _NO:
        return False
    raise ValueError(f"{FACT_NAMES[fact]} cannot be {cell.strip()}")


def preview(header: list, rows: list, mapping: ColumnMapping, hosts: list) -> Preview:
    """What applying `rows` would change. Raises ValueError when the mapping names a missing column."""
    for column in (mapping.host_column, *mapping.fact_columns.values()):
        if column not in header:
            raise ValueError(f"The file has no column called {column}.")
    index = {fact: header.index(column) for fact, column in mapping.fact_columns.items()}
    host_at = header.index(mapping.host_column)
    names = {h["asset_id"]: h.get("hostname") or _ip(h) or h["asset_id"] for h in hosts}
    problems: list[tuple[int, str]] = []
    seen: dict[str, list[tuple[int, dict]]] = {}
    unmatched: dict[str, dict] = {}
    for number, row in enumerate(rows, start=2):
        key = row[host_at] if host_at < len(row) else ""
        if not key.strip():
            problems.append((number, f"Row {number} has no host."))
            continue
        try:
            facts = {fact: v for fact, i in index.items()
                     if (v := _value(fact, row[i] if i < len(row) else "")) is not None}
        except ValueError as error:
            problems.append((number, f"Row {number}: {error}."))
            continue
        asset_id, how = match_host(hosts, key)
        if how == "ambiguous":
            problems.append((number, f"Row {number}: {key.strip()} matches more than one host."))
        elif how == "unmatched":
            if facts:
                unmatched[normalise_host(key)] = facts
        elif facts:
            seen.setdefault(asset_id, []).append((number, facts))
    result = Preview()
    for asset_id, found in seen.items():
        merged: dict = {}
        if all(merged.setdefault(f, v) == v for _, facts in found for f, v in facts.items()):
            result.changes[asset_id] = merged
        else:
            numbers = [n for n, _ in found]
            listed = ", ".join(map(str, numbers[:-1])) + f" and {numbers[-1]}"
            problems.append((numbers[0], f"Rows {listed} disagree about {names[asset_id]}; neither was used."
                             if len(numbers) == 2 else
                             f"Rows {listed} disagree about {names[asset_id]}; none was used."))
    result.problems = [text for _, text in sorted(problems, key=lambda p: p[0])]
    result.unmatched = list(unmatched.items())
    return result

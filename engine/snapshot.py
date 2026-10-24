# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Everything the local dashboard needs, in one pass over the neutral store.

The same keys and the same collection limits as the cloud console's
`ui.app.snapshot()`, plus `failed_runs`. Read only: nothing here writes.

Two local additions ride on existing keys rather than new ones:
- each decision row shown carries `person_approval` when a person approved
  it (`approvals/<decision_id>`). This is a view of two records side by side;
  the stored decision is not changed.
- `counts` covers the collections this store holds. The local idempotency
  journal is not a document collection, so it has no count here.

Standard library only: nothing here imports FastAPI or a cloud SDK.
"""
from tools.docstore import DESCENDING, DocStore, FieldFilter

COUNTED = ("findings", "assets", "owners", "decisions", "tickets",
           "human_queue", "sla_clocks", "idempotency")


def snapshot(docs: DocStore) -> dict:
    def rows(name, limit=60, newest_by=None):
        query = docs.collection(name)
        if newest_by:
            query = query.order_by(newest_by, direction=DESCENDING)
        return [d.to_dict() for d in query.limit(limit).stream()]

    def newest_value(name, field):
        found = list(docs.collection(name).order_by(field, direction=DESCENDING)
                     .limit(1).stream())
        return (found[0].to_dict().get(field, 0) or 0) if found else 0

    human_queue = rows("human_queue")
    sla = rows("sla_clocks")
    decisions = rows("decisions", newest_by="real_ts")
    tickets = rows("tickets")
    exceptions = rows("exceptions")
    cycles = rows("cycles", newest_by="started_real_ts")  # Ruling 42: cycles have no real_ts
    scans = rows("scans", limit=20, newest_by="real_ts")
    reports = rows("reports", limit=10, newest_by="real_ts")
    failed_runs = rows("failed_runs", newest_by="real_ts")

    approvals = docs.collection("approvals")
    for row in decisions:
        decision_id = f"{row.get('finding_id')}-c{int(row.get('cycle') or 0):03d}"
        found = approvals.document(decision_id).get()
        if found.exists:
            approval = found.to_dict()
            row["person_approval"] = {key: approval.get(key)
                                      for key in ("approved_by", "real_ts", "sim_ts")}

    sim_now = max(
        0.0,
        newest_value("tickets", "last_contact_sim_ts"),
        newest_value("sla_clocks", "started_sim_ts"),
        newest_value("decisions", "sim_ts"),
        newest_value("exceptions", "accepted_sim_ts"),
        newest_value("cycles", "finished_sim_ts"),
        newest_value("reports", "sim_ts"),
    )

    counts = {}
    for name in COUNTED:
        try:
            query = docs.collection(name)
        except KeyError:
            continue  # not a document collection in this edition
        counts[name] = int(query.count().get()[0][0].value)

    resolved_total = int(docs.collection("findings")
                         .where(filter=FieldFilter("status", "==", "resolved"))
                         .count().get()[0][0].value)

    return {
        "resolved_total": resolved_total,
        "scans": scans,
        "latest_scan": scans[0] if scans else {},
        "human_queue": human_queue,
        "sla": sla,
        "decisions": decisions,
        "tickets": tickets,
        "exceptions": exceptions,
        "cycles": cycles,
        "reports": reports,
        "counts": counts,
        "sim_now": sim_now,
        "failed_runs": failed_runs,
    }

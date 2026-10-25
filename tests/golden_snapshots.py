# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Fixed synthetic snapshots (no scanner_state) whose rendering is pinned in
fixtures/dashboard_cloud_golden.json, generated from the base commit c5e2f98."""

SNAPSHOTS = {
    "full": {
        "counts": {"assets": 3, "findings": 2}, "resolved_total": 1,
        "scans": [{"scan_id": "scan-1", "real_ts": 1793145600.0, "sim_ts": 1793145600.0, "covered": ["a1"]}],
        "human_queue": [{"finding_id": "RZ-0002", "reason": "reviewer unavailable"}],
        "decisions": [
            {"finding_id": "RZ-0001", "outcome": "ratified", "proposed_severity": "high", "cycle": 2,
             "rationale": "Synthetic rationale <b>escaped</b>.", "cited_evidence": ["Synthetic evidence."],
             "proposed_remediation": "Update the example component.", "real_ts": 1793145600.0,
             "sim_ts": 1793145600.0, "screening": {"screened": True, "blocked": False}},
            {"finding_id": "RZ-0002", "outcome": "unavailable", "proposed_severity": "medium", "cycle": 2,
             "note": "The review could not finish.", "screening": {"screened": False, "blocked": True}}],
        "failed_runs": [{"finding_id": "RZ-0003", "cycle": 2, "error_class": "TimeoutError",
                         "real_ts": 1793145600.0, "sim_ts": 1793145600.0}],
    },
    "empty": {"counts": {}, "scans": [], "decisions": [], "human_queue": []},
}

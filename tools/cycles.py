# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Cycle records.

The cycle summary is the one write in a cycle that is not keyed on a finding,
so the idempotency guard does not cover it. That gap was not theoretical: a
re-run of cycle 1 adjudicated nothing, summarised itself as {"skipped": 4}, and
overwrote the record of what the cycle had actually done.

The summary is derived state. The decisions are the source of truth, which is
why the lost summary could be rebuilt from them afterwards. This module keeps
the first run's outcomes authoritative and records later runs alongside rather
than on top.
"""

from typing import Any, Mapping, Optional


def merge_cycle_record(
    prior: Optional[Mapping[str, Any]], fresh: Mapping[str, Any]
) -> dict[str, Any]:
    """Combine an existing cycle record with a new run of the same cycle.

    First run wins on `outcomes`. A later run contributes its timestamps and a
    rerun count, so the fact that it happened is visible without it destroying
    what the cycle originally did.
    """
    if not prior:
        return {**fresh, "reruns": 0}

    merged = dict(prior)
    merged["reruns"] = int(prior.get("reruns", 0)) + 1
    merged["last_run_real_ts"] = fresh.get("finished_real_ts")
    merged["last_run_outcomes"] = fresh.get("outcomes", {})
    return merged

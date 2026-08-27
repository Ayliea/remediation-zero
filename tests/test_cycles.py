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

"""The cycle summary is derived state and must survive a re-run."""

from tools.cycles import merge_cycle_record

FIRST = {
    "cycle_id": "cycle-001",
    "outcomes": {"ratified": 2, "human_queue": 2},
    "finished_real_ts": 1000.0,
}
RERUN = {
    "cycle_id": "cycle-001",
    "outcomes": {"skipped": 4},
    "finished_real_ts": 2000.0,
}


def test_a_first_run_is_recorded_as_is():
    assert merge_cycle_record(None, FIRST)["outcomes"] == {"ratified": 2, "human_queue": 2}
    assert merge_cycle_record(None, FIRST)["reruns"] == 0


def test_a_rerun_does_not_overwrite_what_the_cycle_actually_did():
    """This is a regression test for a bug that really happened: a re-run
    adjudicated nothing, summarised itself as skipped, and destroyed the
    record of the original outcomes."""
    merged = merge_cycle_record(FIRST, RERUN)

    assert merged["outcomes"] == {"ratified": 2, "human_queue": 2}
    assert merged["last_run_outcomes"] == {"skipped": 4}
    assert merged["reruns"] == 1


def test_reruns_accumulate():
    once = merge_cycle_record(FIRST, RERUN)
    twice = merge_cycle_record(once, RERUN)

    assert twice["reruns"] == 2
    assert twice["outcomes"] == {"ratified": 2, "human_queue": 2}

#!/usr/bin/env bash
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

# Run the chase agent over every open SLA clock.
#
#   SIM_CLOCK_MODE=sim ./scripts/chase.sh --cycle 4 --advance-days 8
#
# --advance-days moves simulated time only. real_ts is wall clock on every
# write and is never adjusted to match. SIM_CLOCK_MODE=sim is required for it:
# advance() refuses in real mode rather than fabricating elapsed time, so the
# command above fails without it. That refusal is the point, not an obstacle.

set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/python scripts/chase.py "$@"

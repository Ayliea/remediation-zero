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

# Update the deployed agent in place. Safe to repeat.
#
# GUARD, HARD CONSTRAINT 10: this script must never delete or recreate the
# deployed agent resource. A long-running session carrying days of real elapsed
# time is tied to it, that elapsed time is the strongest proof point in the
# demo, and it cannot be regenerated before the deadline.
#
# Required behaviour once implemented:
#   - Read AGENT_RESOURCE_NAME from the environment. Refuse to run if unset.
#   - If the resource exists, update it in place.
#   - If a code path would delete or recreate it, refuse and print the existing
#     resource name and creation timestamp instead. Exit non-zero.
set -euo pipefail

echo "deploy-agent.sh: not implemented yet." >&2
exit 1

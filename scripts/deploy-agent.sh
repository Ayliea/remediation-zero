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

# Deploy or update the orchestrator on Agent Runtime. Safe to run repeatedly.
#
# HARD CONSTRAINT 10. This script never deletes or recreates the deployed agent
# resource. A long-running session carrying days of real elapsed time is tied to
# it, that elapsed time is the strongest proof point in the demo, and it cannot
# be regenerated before the deadline.
#
# The specific footgun this guards against: `adk deploy agent_engine` creates a
# brand new instance when --agent_engine_id is omitted. Omitting it, or passing
# a typo, does not error. It silently builds a second engine and orphans the one
# holding the session. So the ID is mandatory here, and creating a new engine
# requires opting in explicitly with --create.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  set -a; source .env; set +a
fi

CREATE=0
for arg in "$@"; do
  case "$arg" in
    --create) CREATE=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

require () {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: $name is not set. Copy .env.example to .env and fill it in." >&2
    exit 1
  fi
}

require GOOGLE_CLOUD_PROJECT
require AGENT_ENGINE_LOCATION

RESOURCE_NAME="projects/${GOOGLE_CLOUD_PROJECT}/locations/${AGENT_ENGINE_LOCATION}/reasoningEngines/${AGENT_ENGINE_ID:-}"

# ---------------------------------------------------------------------------
# Guard: without an ID, a deploy silently creates a second engine.
# ---------------------------------------------------------------------------
if [[ -z "${AGENT_ENGINE_ID:-}" ]]; then
  if [[ "$CREATE" -ne 1 ]]; then
    cat >&2 <<'MSG'
REFUSING TO DEPLOY.

AGENT_ENGINE_ID is not set. Deploying without it does not fail: it creates a
new Agent Engine instance and leaves the existing one, along with the session
whose elapsed time is the demo's proof, orphaned and unreferenced.

If an engine already exists, put its ID in .env as AGENT_ENGINE_ID.
List existing engines with:

  gcloud alpha agent-engines list --project=PROJECT --location=LOCATION

Only if no engine exists yet, create the first one deliberately:

  ./scripts/deploy-agent.sh --create

then record the printed ID in .env before deploying again.
MSG
    exit 1
  fi

  echo "Creating the first Agent Engine instance (--create was passed)."
  # adk deploy prints "Deploy failed: ..." and still exits 0, so its exit code
  # cannot be trusted. Capture the output and inspect it.
  # Same staging on the create path. An engine created without it imports
  # cleanly on this machine and fails on its first query in the cloud.
  if ! out=$(.venv/bin/adk deploy agent_engine \
      --project="${GOOGLE_CLOUD_PROJECT}" \
      --region="${AGENT_ENGINE_LOCATION}" \
      --display_name="remediation-zero-orchestrator" \
      --extra_packages=tools \
      --extra_packages=prompts \
      --extra_packages=agents/triage \
      --extra_packages=agents/reviewer \
      --extra_packages=data \
      agents/orchestrator 2>&1) || grep -qi "deploy failed" <<<"$out"; then
    echo "$out"
    echo >&2
    echo "DEPLOY FAILED. No resource ID was recorded." >&2
    exit 1
  fi
  echo "$out"
  echo
  echo "Record the printed resource ID in .env as AGENT_ENGINE_ID before"
  echo "running this script again. Subsequent runs update that ID in place."
  exit 0
fi

# ---------------------------------------------------------------------------
# Guard: a typo'd ID must not fall through into creating a second engine.
# ---------------------------------------------------------------------------
# Checked over REST rather than `gcloud alpha agent-engines describe`, because
# the alpha component is not installed by default and gcloud tries to install it
# interactively, which would make this guard refuse a perfectly valid deploy.
echo "Verifying the target resource exists before deploying..."
TOKEN="$(gcloud auth application-default print-access-token 2>/dev/null)"
if [[ -z "$TOKEN" ]]; then
  echo "ERROR: no application-default credentials. Run:" >&2
  echo "  gcloud auth application-default login --no-launch-browser" >&2
  exit 1
fi
HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${TOKEN}" \
  "https://${AGENT_ENGINE_LOCATION}-aiplatform.googleapis.com/v1/${RESOURCE_NAME}" 2>/dev/null || echo 000)"
if [[ "$HTTP_CODE" != "200" ]]; then
  cat >&2 <<MSG
REFUSING TO DEPLOY.

AGENT_ENGINE_ID is set to '${AGENT_ENGINE_ID}', but no such Agent Engine exists
in project '${GOOGLE_CLOUD_PROJECT}' at '${AGENT_ENGINE_LOCATION}' (HTTP ${HTTP_CODE}).

This is treated as an error rather than as a request to create one, because the
most likely cause is a typo, and creating a new engine here would orphan the
existing session. Check the ID against:

  gcloud alpha agent-engines list --project=${GOOGLE_CLOUD_PROJECT} --location=${AGENT_ENGINE_LOCATION}
MSG
  exit 1
fi

echo "Updating in place: ${RESOURCE_NAME}"
if ! out=$(.venv/bin/adk deploy agent_engine \
    --project="${GOOGLE_CLOUD_PROJECT}" \
    --region="${AGENT_ENGINE_LOCATION}" \
    --agent_engine_id="${AGENT_ENGINE_ID}" \
    --display_name="remediation-zero-orchestrator" \
    --extra_packages=tools \
    --extra_packages=prompts \
    --extra_packages=agents/triage \
    --extra_packages=agents/reviewer \
    --extra_packages=data \
    agents/orchestrator 2>&1) || grep -qi "deploy failed" <<<"$out"; then
  echo "$out"
  echo >&2
  echo "DEPLOY FAILED. The existing resource was not modified." >&2
  exit 1
fi
echo "$out"

# Prove the claim in the banner below rather than asserting it.
AFTER_CODE="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${TOKEN}" \
  "https://${AGENT_ENGINE_LOCATION}-aiplatform.googleapis.com/v1/${RESOURCE_NAME}" 2>/dev/null || echo 000)"
if [[ "$AFTER_CODE" != "200" ]]; then
  echo "ERROR: the resource is not reachable after deploy (HTTP ${AFTER_CODE})." >&2
  exit 1
fi

echo
echo "=========================================================="
echo "resource name : ${RESOURCE_NAME}"
echo "deployed at   : $(date -u +%Y-%m-%dT%H:%M:%SZ) (real wall clock, UTC)"
echo "updated in place. no resource was deleted or recreated."
echo "=========================================================="

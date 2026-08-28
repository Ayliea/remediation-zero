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

# Publish the orchestrator to Agent Registry so it is discoverable by name.
#
# The catalogue entry is what makes an agent findable by a department that did
# not build it: a stable id, a version, the skills it offers, and the endpoint
# that serves them. Without it the fleet exists but nobody outside this
# repository can learn that it does.
#
# Safe to repeat. An existing entry is updated rather than duplicated, because
# a catalogue with two entries for one agent is worse than no catalogue.
#
#   ./scripts/register-agent.sh          # show what would be published
#   ./scripts/register-agent.sh --apply  # publish or update

set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then set -a; source .env; set +a; fi

PROJECT="${GOOGLE_CLOUD_PROJECT:?set in .env}"
LOCATION="${AGENT_ENGINE_LOCATION:-us-central1}"
ENGINE_ID="${AGENT_ENGINE_ID:?set in .env}"
BASE="https://agentregistry.googleapis.com/v1/projects/${PROJECT}/locations/${LOCATION}"
API="${BASE}/services"
SERVICE_ID="remediation-zero-orchestrator"
VERSION="$(git rev-parse --short HEAD)"

TOKEN="$(gcloud auth print-access-token)"

# The catalogue entry is a Service carrying an A2A agent card. `agents` in this
# API is read-only — get, list and search only — so an entry is published by
# registering the Service that serves it, and the registry derives the Agent
# from the card.
#
# The skills advertised are the ones the deployed agent actually exposes as
# tools. A catalogue that promises capabilities the agent does not have is a
# directory of intentions, which is the failure this whole project is built
# against.
CARD="$(cat <<JSON
{
  "protocolVersion": "0.3.0",
  "name": "Remediation Zero — Orchestrator",
  "description": "Owns the vulnerability remediation lifecycle for a one-person security team. Triage proposes a severity, an SLA and a remediation path citing CISA KEV, NVD and EPSS; an adversarial reviewer on a different model family ratifies or rejects it with a stated reason before anything becomes state. This agent reasons and recalls and holds no credential that can write: an Agent Engine runs as a single service account, so the agents that write run in the ADK Workflow graph and scheduled Cloud Run workers, each under its own identity.",
  "url": "https://${LOCATION}-aiplatform.googleapis.com/v1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines/${ENGINE_ID}",
  "version": "${VERSION}",
  "provider": {
    "organization": "Remediation Zero",
    "url": "https://github.com/Ayliea/remediation-zero"
  },
  "capabilities": { "streaming": true },
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": [
    {
      "id": "assess_finding",
      "name": "Assess a vulnerability finding",
      "description": "Read one finding with its asset and CISA KEV, NVD and EPSS enrichment, obtain a triage proposal, and have an adversarial reviewer on a different model family ratify or reject it with a stated reason. Returns the proposal and the verdict. Persists nothing.",
      "tags": ["security", "vulnerability-management", "triage", "adversarial-review"],
      "examples": ["Assess finding RZ-0101 end to end and report the verdict."]
    },
    {
      "id": "recall_fleet_history",
      "name": "Recall past remediation cycles",
      "description": "Recall what the fleet decided in earlier cycles, including cycles run on a daily schedule by worker processes that have since exited. Reads Agent Platform Memory Bank.",
      "tags": ["security", "memory", "audit"],
      "examples": ["What has this fleet been doing in past cycles?"]
    },
    {
      "id": "lookup_finding",
      "name": "Look up a finding",
      "description": "Read one finding with its asset and its CISA KEV, NVD and EPSS enrichment, rendered the way the fleet renders it. Read-only.",
      "tags": ["security", "vulnerability-management"],
      "examples": ["Look up RZ-0216."]
    }
  ]
}
JSON
)"

BODY="$(python3 -c "
import json, sys
card = json.loads(sys.stdin.read())
print(json.dumps({
    'displayName': 'Remediation Zero — Orchestrator',
    'description': card['description'][:900],
    'agentSpec': {'type': 'A2A_AGENT_CARD', 'content': card},
}))
" <<<"${CARD}")"

echo
echo "Agent Registry — ${PROJECT} / ${LOCATION}"
echo "  service : ${SERVICE_ID}"
echo "  version : ${VERSION} (the commit the deployed engine was built from)"
echo "  skills  : assess_finding, recall_fleet_history, lookup_finding"
echo

EXISTING="$(curl -sS -H "Authorization: Bearer ${TOKEN}" "${API}" \
  | python3 -c "
import json,sys
want = sys.argv[1]
for s in json.load(sys.stdin).get('services', []):
    if s.get('name','').endswith('/' + want):
        print(s['name']); break
" "${SERVICE_ID}")"

if [[ "${1:-}" != "--apply" ]]; then
  if [[ -n "${EXISTING}" ]]; then
    echo "Already registered as ${EXISTING}."
    echo "Re-run with --apply to update it in place."
  else
    echo "Not registered. Re-run with --apply to publish."
  fi
  exit 0
fi

if [[ -n "${EXISTING}" ]]; then
  echo "Updating ${EXISTING}..."
  # updateMask is required. Without it this PATCH returns a perfectly healthy
  # long-running operation and changes nothing -- the registry entry sat on a
  # version eleven commits old while every run reported success. Name every
  # mutable field BODY sets, or the ones left out silently keep their old
  # values.
  RESPONSE="$(curl -sS -X PATCH \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
    -d "${BODY}" \
    "https://agentregistry.googleapis.com/v1/${EXISTING}?updateMask=displayName,description,agentSpec")"
else
  echo "Publishing a new catalogue entry..."
  RESPONSE="$(curl -sS -X POST \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
    -d "${BODY}" "${API}?serviceId=${SERVICE_ID}")"
fi

echo "${RESPONSE}" | python3 -c "
import json,sys
d=json.load(sys.stdin)
if 'error' in d:
    print('FAILED:', json.dumps(d['error'])[:400]); raise SystemExit(1)
print()
name = d.get('name') or d.get('response',{}).get('name','?')
print('  service    :', name)
print('  agent      :', d.get('registryResource') or d.get('response',{}).get('registryResource','(pending)'))
"

# Registration returns a long-running operation, so the entry is not in the
# catalogue when the call returns. Prove discoverability by searching for it
# the way a department that did not build it would, rather than asserting it.
#
# Match on the version just published, not merely on the name. An earlier
# version of this loop broke on any entry whose displayName said "Remediation
# Zero", which meant a stale catalogue entry from eleven commits back satisfied
# it in two seconds. That check could not fail for the reason it claimed to
# test: had the update silently not landed, it would still have reported
# "discoverable". Requiring the version makes the assertion able to fail.
echo "Waiting for the catalogue to reflect ${VERSION}..."
FOUND=""
STALE=""
for _ in $(seq 1 30); do
  MATCH="$(curl -sS -X POST -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" -d '{"searchString":"vulnerability remediation"}' \
    "${BASE}/agents:search" | RZ_WANT="${VERSION}" python3 -c "
import json, os, sys
want = os.environ['RZ_WANT']
for a in json.load(sys.stdin).get('agents', []):
    if 'Remediation Zero' not in a.get('displayName', ''):
        continue
    got = str(a.get('version', '?'))
    row = (a['name'] + '|' + got + '|' +
           ','.join(x['id'] for x in a.get('skills', [])))
    # Prefix says whether this is the version we just published or an older
    # one the catalogue has not yet replaced.
    print(('OK|' if got == want else 'STALE|') + row)
    break
")"
  case "${MATCH}" in
    OK\|*)    FOUND="${MATCH#OK|}"; break ;;
    STALE\|*) STALE="${MATCH#STALE|}" ;;
  esac
  sleep 5
done

echo
if [[ -z "${FOUND}" ]]; then
  if [[ -n "${STALE}" ]]; then
    IFS='|' read -r _SN _SV _SK <<<"${STALE}"
    echo "FOUND, BUT STALE. The catalogue still serves ${_SV}, not ${VERSION}." >&2
    echo "The entry is discoverable, but it is not the one just published." >&2
    echo "Either the update did not land, or the catalogue is still lagging." >&2
  else
    echo "PUBLISHED, BUT NOT FOUND BY SEARCH." >&2
    echo "The catalogue can lag behind the operation. Re-run to check again." >&2
  fi
  exit 1
fi
IFS='|' read -r RNAME RVERSION RSKILLS <<<"${FOUND}"
echo "=========================================================="
echo "Discoverable by search, not merely published."
echo "  query   : vulnerability remediation"
echo "  agent   : ${RNAME}"
echo "  version : ${RVERSION}"
echo "  skills  : ${RSKILLS}"
echo "=========================================================="

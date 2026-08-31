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

# Grant each agent identity the least privilege it can actually be given.
#
# READ THIS BEFORE RUNNING. It modifies project IAM.
#
# What Firestore can and cannot enforce, verified rather than assumed:
# roles/datastore.user resolves to datastore.entities.create/update/delete,
# which are database-scoped. Firestore Native has no collection-scoped IAM
# permission, and Security Rules, which are collection-aware, are bypassed
# entirely by server SDKs authenticating as a service account. So collection
# level separation cannot be enforced by IAM here, and claiming otherwise
# would be claiming a control that does not exist.
#
# What is enforceable is a per-database boundary, so the one claim the demo
# makes is made real: the reporting agent holds read-only access to the
# operational database and write access only to the reports database. It is
# structurally unable to write a ticket, and scripts/verify-controls.sh proves
# it by attempting the write and showing the denial.
#
# The other agents each get their own identity, so there is no shared
# credential, with collection separation enforced in code. That distinction is
# stated in the README rather than blurred.

set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then set -a; source .env; set +a; fi

PROJECT="${GOOGLE_CLOUD_PROJECT:?set in .env}"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')"
OPERATIONAL="projects/${PROJECT}/databases/(default)"
REPORTS="projects/${PROJECT}/databases/reports"

sa () { echo "serviceAccount:rz-$1@${PROJECT}.iam.gserviceaccount.com"; }

echo "Creating the seven agent service accounts when absent..."
for agent in orchestrator triage reviewer ownership chase exception reporting; do
  address="rz-${agent}@${PROJECT}.iam.gserviceaccount.com"
  if gcloud iam service-accounts describe "${address}" \
      --project="${PROJECT}" > /dev/null 2>&1; then
    echo "  rz-${agent}: already exists"
  else
    gcloud iam service-accounts create "rz-${agent}" \
      --display-name="Remediation Zero ${agent}" \
      --project="${PROJECT}" --quiet > /dev/null
    echo "  rz-${agent}: created"
  fi
done

has_vertex_access () {
  local member policy
  member="$(sa "$1")"
  if ! policy="$(gcloud projects get-iam-policy "${PROJECT}" \
    --flatten='bindings[].members' \
    --filter="bindings.role=roles/aiplatform.user AND bindings.members=${member}" \
    --format='value(bindings.members)')"; then
    return 2
  fi
  grep -Fqx "${member}" <<< "${policy}"
}

echo "Granting model access only to identities whose code calls a model..."
for agent in orchestrator triage reviewer reporting; do
  gcloud projects add-iam-policy-binding "${PROJECT}" \
    --member="$(sa "${agent}")" --role="roles/aiplatform.user" \
    --condition=None --quiet > /dev/null
  echo "  rz-${agent}: roles/aiplatform.user"
done

# This script is also a reconciler. Earlier deployments granted Vertex access
# to every named identity; merely narrowing the add loop would leave those
# stale privileges effective forever.
for agent in ownership chase exception; do
  gcloud projects remove-iam-policy-binding "${PROJECT}" \
    --member="$(sa "${agent}")" --role="roles/aiplatform.user" \
    --condition=None --quiet > /dev/null 2>&1 || :
  if has_vertex_access "${agent}"; then
    echo "ERROR: rz-${agent} still has roles/aiplatform.user" >&2
    exit 1
  else
    verify_status=$?
    if [[ ${verify_status} -ne 1 ]]; then
      echo "ERROR: could not verify Vertex access for rz-${agent}" >&2
      exit 1
    fi
  fi
  echo "  rz-${agent}: Vertex access verified absent (deterministic worker)"
done

echo
echo "Granting operational database write to the agents that own state..."
for agent in orchestrator triage reviewer ownership chase exception; do
  gcloud projects add-iam-policy-binding "${PROJECT}" \
    --member="$(sa "${agent}")" --role="roles/datastore.user" \
    --condition=None --quiet > /dev/null
  echo "  rz-${agent}: roles/datastore.user"
done

echo
echo "Reporting is different, and this is the control:"
gcloud projects add-iam-policy-binding "${PROJECT}" \
  --member="$(sa reporting)" --role="roles/datastore.viewer" \
  --condition=None --quiet > /dev/null
echo "  rz-reporting: roles/datastore.viewer   (read everything, write nothing)"

gcloud projects add-iam-policy-binding "${PROJECT}" \
  --member="$(sa reporting)" --role="roles/datastore.user" \
  --condition="expression=resource.name.startsWith('${REPORTS}'),title=reports-database-only,description=Reporting writes only to the reports database" \
  --quiet > /dev/null
echo "  rz-reporting: roles/datastore.user     (conditioned to the reports database only)"

echo
echo "The deployed Agent Engine reads findings, and only reads them:"
gcloud projects add-iam-policy-binding "${PROJECT}" \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
  --role="roles/datastore.viewer" \
  --condition=None --quiet > /dev/null
echo "  reasoning engine agent: roles/datastore.viewer   (read only, never datastore.user)"
gcloud projects add-iam-policy-binding "${PROJECT}" \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
  --role="roles/modelarmor.user" \
  --condition=None --quiet > /dev/null
echo "  reasoning engine agent: roles/modelarmor.user   (screen untrusted text)"
echo
echo "  The deployed agent reads a finding, and the scanner comment on that"
echo "  finding came from outside the system. Constraint 12 says it passes"
echo "  Model Armor before any reasoning context sees it, so the identity that"
echo "  does the reading must be able to screen."
echo
echo "  An Agent Engine runs as one service account, so everything attached to"
echo "  the deployed orchestrator shares this identity. It is therefore given"
echo "  read and nothing else: the agents that write run in the Workflow graph"
echo "  and the Cloud Run workers, each as itself. Granting datastore.user here"
echo "  would make the reporting-denial control untrue of the deployment."

echo
echo "The tracker credential is granted on the secret, not on the project:"
gcloud secrets add-iam-policy-binding rz-github-token \
  --project="${PROJECT}" \
  --member="$(sa chase)" \
  --role="roles/secretmanager.secretAccessor" \
  --quiet > /dev/null 2>&1 || echo "  (create the secret first: see the README)"
echo "  rz-chase: roles/secretmanager.secretAccessor on rz-github-token only"
echo
echo "  Chase delivers to the tracker and the exception sweep does not, so only"
echo "  chase can read the token. The boundary is on the secret rather than on"
echo "  the exception agent choosing not to ask, and exception-secret-probe"
echo "  proves it by running as rz-exception and being refused."

echo
echo "Allowing the operator to impersonate rz-reporting, so the denial can be"
echo "demonstrated rather than described..."
OPERATOR="$(gcloud config get-value account 2>/dev/null)"
gcloud iam service-accounts add-iam-policy-binding \
  "rz-reporting@${PROJECT}.iam.gserviceaccount.com" \
  --member="user:${OPERATOR}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project="${PROJECT}" --quiet > /dev/null
echo "  ${OPERATOR}: tokenCreator on rz-reporting"

echo
echo "Done. Verify with: ./scripts/verify-controls.sh"

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
OPERATIONAL="projects/${PROJECT}/databases/(default)"
REPORTS="projects/${PROJECT}/databases/reports"

sa () { echo "serviceAccount:rz-$1@${PROJECT}.iam.gserviceaccount.com"; }

echo "Granting model access to every agent identity..."
for agent in orchestrator triage reviewer ownership chase exception reporting; do
  gcloud projects add-iam-policy-binding "${PROJECT}" \
    --member="$(sa "${agent}")" --role="roles/aiplatform.user" \
    --condition=None --quiet > /dev/null
  echo "  rz-${agent}: roles/aiplatform.user"
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

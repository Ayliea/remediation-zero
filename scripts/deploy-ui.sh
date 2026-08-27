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

# Deploy the console to Cloud Run. Safe to repeat.
#
# The console runs under console-reader, a service account holding
# roles/datastore.viewer and nothing else. That is what makes the claim in the
# page footer true rather than decorative: the interface a stranger can reach
# is structurally unable to change the record it displays.
#
# Minimum instances 0 and maximum 3. There are no credits, so idle cost has to
# be zero and the ceiling has to be explicit.

set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then set -a; source .env; set +a; fi

: "${GOOGLE_CLOUD_PROJECT:?set in .env}"
REGION="${AGENT_ENGINE_LOCATION:-us-central1}"
SERVICE="remediation-zero-console"
SA="console-reader@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"

echo "Deploying ${SERVICE} to ${REGION}..."
gcloud run deploy "${SERVICE}" \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --region="${REGION}" \
  --source=. \
  --service-account="${SA}" \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=3 \
  --cpu=1 \
  --memory=512Mi \
  --timeout=60 \
  --set-env-vars="SESSION_CREATED_REAL_TS=${SESSION_CREATED_REAL_TS:-0},ORCHESTRATOR_SESSION_ID=${ORCHESTRATOR_SESSION_ID:-unknown}" \
  --quiet

URL="$(gcloud run services describe "${SERVICE}" \
  --project="${GOOGLE_CLOUD_PROJECT}" --region="${REGION}" \
  --format='value(status.url)')"

echo
echo "=========================================================="
echo "console      : ${URL}"
echo "service acct : ${SA} (roles/datastore.viewer only)"
echo "instances    : min 0, max 3"
echo "deployed at  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=========================================================="

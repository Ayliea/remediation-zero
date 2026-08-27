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

# Enable the Google Cloud APIs this project depends on. Idempotent: enabling an
# already-enabled API is a no-op, so this is safe to re-run.

set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then set -a; source .env; set +a; fi

PROJECT="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
if [[ -z "$PROJECT" || "$PROJECT" == "(unset)" ]]; then
  echo "ERROR: no project. Set GOOGLE_CLOUD_PROJECT in .env or run gcloud config set project." >&2
  exit 1
fi

APIS=(
  aiplatform.googleapis.com          # Vertex AI / Agent Platform / Agent Runtime
  run.googleapis.com                 # Cloud Run, for the console UI
  firestore.googleapis.com           # working state
  pubsub.googleapis.com              # events and dead-letter queue
  cloudscheduler.googleapis.com      # cycle tick
  cloudtrace.googleapis.com          # telemetry
  logging.googleapis.com             # structured logs
  modelarmor.googleapis.com          # guardrails on untrusted ingress
  cloudbuild.googleapis.com          # required by adk deploy
  artifactregistry.googleapis.com    # deploy artefacts
  storage.googleapis.com             # staging
  iam.googleapis.com                 # per-agent service accounts
  cloudresourcemanager.googleapis.com
)

echo "Enabling ${#APIS[@]} APIs on ${PROJECT}. This takes a couple of minutes."
gcloud services enable "${APIS[@]}" --project="${PROJECT}"

echo
echo "Enabled:"
gcloud services list --enabled --project="${PROJECT}" --format='value(config.name)' | sort

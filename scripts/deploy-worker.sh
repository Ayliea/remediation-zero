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

# Deploy the scheduled worker. Safe to repeat.
#
# One image, two services. WORKER_AGENT selects the agent and each service runs
# under that agent's own identity, so neither holds the other's access. A
# single service running both agents would need one credential with both
# agents' permissions, which is the shared credential the architecture does not
# have.
#
# Neither service is public. The only thing that can invoke them is the push
# subscription, authenticated as the agent, and Terraform grants that.
#
# Run this before `terraform apply`: the subscriptions read the service URLs.

set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then set -a; source .env; set +a; fi

PROJECT="${GOOGLE_CLOUD_PROJECT:?set in .env}"
REGION="${AGENT_ENGINE_LOCATION:-us-central1}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/cloud-run-source-deploy/rz-worker:$(git rev-parse --short HEAD)"

# Refuse a deploy that would silently take delivery away. This script reads the
# tracker from the deploy-time shell, so running it from a terminal that never
# exported GITHUB_TICKET_REPO produces a healthy-looking deploy whose only
# visible symptom is `delivery_disabled` in a log nobody is reading. That
# happened on 2026-08-28: the workers were redeployed to pick up a fix and came
# back unable to file a ticket, and the deploy reported success throughout.
#
# Losing a capability is not the same as never having had one. If the running
# service can deliver and this invocation cannot, that is a regression and the
# operator has to say so out loud.
if [[ -z "${GITHUB_TICKET_REPO:-}" ]]; then
  LIVE_REPO="$(gcloud run services describe "rz-worker-chase" \
    --project="${PROJECT}" --region="${REGION}" \
    --format='value(spec.template.spec.containers[0].env.filter("name":"GITHUB_TICKET_REPO").extract("value"))' \
    2>/dev/null | tr -d "[]\"' ")"
  if [[ -n "${LIVE_REPO}" ]]; then
    echo "REFUSING: rz-worker-chase currently delivers to ${LIVE_REPO}," >&2
    echo "and GITHUB_TICKET_REPO is not set in this shell. Deploying now would" >&2
    echo "leave the worker unable to file a ticket, and would report success." >&2
    echo >&2
    echo "  export GITHUB_TICKET_REPO=\"${LIVE_REPO}\"" >&2
    echo >&2
    echo "Or pass DROP_DELIVERY=1 to remove it deliberately." >&2
    [[ "${DROP_DELIVERY:-}" == "1" ]] || exit 1
    echo "DROP_DELIVERY=1 set; removing tracker delivery deliberately." >&2
  fi
fi

echo "Building ${IMAGE}..."
gcloud builds submit \
  --project="${PROJECT}" \
  --config=cloudbuild.worker.yaml \
  --substitutions="_IMAGE=${IMAGE}" \
  --quiet

# Only chase delivers to the tracker, so only chase is given the token. The
# grant is on the secret rather than the project, so rz-exception is not merely
# un-configured — it cannot read the credential at all. An exception sweep that
# could file a ticket would be a capability nobody asked it to have.
GITHUB_REPO="${GITHUB_TICKET_REPO:-}"
for agent in chase exception; do
  SERVICE="rz-worker-${agent}"
  SA="rz-${agent}@${PROJECT}.iam.gserviceaccount.com"

  EXTRA_ENV=""
  SECRETS=()
  if [[ "${agent}" == "chase" && -n "${GITHUB_REPO}" ]]; then
    EXTRA_ENV=",GITHUB_TICKET_REPO=${GITHUB_REPO}"
    SECRETS=(--set-secrets="GITHUB_TOKEN=rz-github-token:latest")
    echo
    echo "  ${SERVICE} will deliver to ${GITHUB_REPO}"
    echo "  token comes from Secret Manager at request time; it is never in the"
    echo "  image, never in the deploy command, and never in an env var this"
    echo "  script can print."
  fi

  echo
  echo "Deploying ${SERVICE} as ${SA}..."
  gcloud run deploy "${SERVICE}" \
    --project="${PROJECT}" \
    --region="${REGION}" \
    --image="${IMAGE}" \
    --service-account="${SA}" \
    --no-allow-unauthenticated \
    --min-instances=0 \
    --max-instances=2 \
    --cpu=1 \
    --memory=512Mi \
    --timeout=300 \
    --set-env-vars="WORKER_AGENT=${agent},SIM_CLOCK_MODE=${SIM_CLOCK_MODE:-real},GOOGLE_CLOUD_PROJECT=${PROJECT}${EXTRA_ENV}" \
    "${SECRETS[@]}" \
    --quiet
done

# Same guard as the console deploy. A pinned service accepts new revisions and
# serves none of them, reporting success the whole way.
for agent in chase exception; do
  SERVICE="rz-worker-${agent}"
  SERVING="$(gcloud run services describe "${SERVICE}" \
    --project="${PROJECT}" --region="${REGION}" \
    --format='value(status.traffic[0].revisionName)')"
  LATEST="$(gcloud run services describe "${SERVICE}" \
    --project="${PROJECT}" --region="${REGION}" \
    --format='value(status.latestReadyRevisionName)')"
  if [[ "${SERVING}" != "${LATEST}" ]]; then
    echo >&2
    echo "ERROR: ${SERVICE} is serving ${SERVING}, not ${LATEST}." >&2
    echo "Release it with: gcloud run services update-traffic ${SERVICE} \\" >&2
    echo "  --region=${REGION} --project=${PROJECT} --to-latest" >&2
    exit 1
  fi
done

echo
echo "=========================================================="
for agent in chase exception; do
  URL="$(gcloud run services describe "rz-worker-${agent}" \
    --project="${PROJECT}" --region="${REGION}" --format='value(status.url)')"
  printf 'rz-worker-%-10s %s\n' "${agent}" "${URL}"
  printf '%-21s runs as rz-%s, min 0 / max 2, not public\n' "" "${agent}"
done
echo "deployed at  : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo
echo "Next: terraform -chdir=infra apply"
echo "=========================================================="

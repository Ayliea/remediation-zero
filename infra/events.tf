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

# One topic, two subscribers.
#
# The fan-out is not decoration. Chase and the exception sweep are separate
# agents with separate service accounts, and constraint 7 says no agent shares
# a credential with another. A single worker running both would need one
# identity holding both agents' access, so the tick fans out instead and each
# subscriber runs as itself.

locals {
  agents = toset(["chase", "exception"])

  # Dead-lettering is performed by the Pub/Sub service agent, not by the
  # publisher or the subscriber, so this is the principal that needs the
  # bindings further down.
  pubsub_agent = "serviceAccount:service-${var.project_number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_pubsub_topic" "tick" {
  name    = "remediation-tick"
  project = var.project_id

  labels = {
    component = "events"
  }
}

# Where a tick goes when the fleet could not process it.
#
# This exists so that "findings are never silently dropped" is a property of
# the infrastructure rather than a sentence in a README. A message that fails
# every delivery attempt lands here and stays here: nothing drains it on a
# schedule, because the point is that a person finds it.
resource "google_pubsub_topic" "dead_letter" {
  name    = "remediation-tick-dead"
  project = var.project_id

  labels = {
    component = "events"
    role      = "dead-letter"
  }
}

# The dead-letter subscription retains; it has no push endpoint on purpose.
# A dead-letter queue wired to a consumer that quietly retries is not a
# dead-letter queue, it is a slower retry loop.
resource "google_pubsub_subscription" "dead_letter_hold" {
  name    = "remediation-tick-dead-hold"
  project = var.project_id
  topic   = google_pubsub_topic.dead_letter.id

  # Long enough that a failure over a weekend is still there on Monday, which
  # is the realistic discovery time for a one-person security team.
  message_retention_duration = "604800s" # 7 days
  retain_acked_messages      = true
  expiration_policy {
    ttl = "" # never expire
  }

  labels = {
    component = "events"
    role      = "dead-letter"
  }
}

resource "google_pubsub_subscription" "agent_tick" {
  for_each = local.agents

  name    = "${each.key}-tick"
  project = var.project_id
  topic   = google_pubsub_topic.tick.id

  ack_deadline_seconds = 120

  push_config {
    # The path matters. The worker serves POST /tick and nothing at /, so a
    # push to the bare service URL is a 404 on every delivery — which looks
    # exactly like a working subscription until you notice the tick never ran.
    push_endpoint = "${data.google_cloud_run_service.worker[each.key].status[0].url}/tick"

    # The push is authenticated as the agent's own identity, and the worker it
    # reaches runs as that same identity. Transport and execution do not drift
    # apart.
    oidc_token {
      service_account_email = "rz-${each.key}@${var.project_id}.iam.gserviceaccount.com"

      # The audience stays the bare service URL: it is what Cloud Run validates
      # the token against, and it is not the same thing as the request path.
      audience = data.google_cloud_run_service.worker[each.key].status[0].url
    }
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = var.max_delivery_attempts
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  labels = {
    component = "events"
    agent     = each.key
  }
}

# Dead-lettering fails silently without both of these, and it fails in the
# worst possible way: the subscription keeps retrying forever and nothing ever
# arrives in the dead-letter topic, so the queue looks empty because it is
# never written to rather than because nothing failed.
resource "google_pubsub_topic_iam_member" "dead_letter_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.dead_letter.name
  role    = "roles/pubsub.publisher"
  member  = local.pubsub_agent
}

resource "google_pubsub_subscription_iam_member" "dead_letter_subscriber" {
  for_each = local.agents

  project      = var.project_id
  subscription = google_pubsub_subscription.agent_tick[each.key].name
  role         = "roles/pubsub.subscriber"
  member       = local.pubsub_agent
}

# Pub/Sub mints the OIDC token it pushes with, so it must be able to sign as
# the agent identity named in the push config.
resource "google_service_account_iam_member" "pubsub_can_mint_oidc" {
  for_each = local.agents

  service_account_id = "projects/${var.project_id}/serviceAccounts/rz-${each.key}@${var.project_id}.iam.gserviceaccount.com"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.pubsub_agent
}

# The push identity must be allowed to invoke the worker it pushes to. The
# workers are deliberately not public: the only thing that can start a cycle
# is the scheduler, through Pub/Sub, as the agent itself.
resource "google_cloud_run_service_iam_member" "push_can_invoke" {
  for_each = local.agents

  project  = var.project_id
  location = var.region
  service  = data.google_cloud_run_service.worker[each.key].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:rz-${each.key}@${var.project_id}.iam.gserviceaccount.com"
}

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

# The thing that makes the fleet autonomous rather than operated.
#
# The cycle number is derived from the date rather than incremented, because
# the scheduler has no memory and an idempotency key needs one. Two ticks on
# the same day derive the same cycle, so a manual re-run or a Pub/Sub
# redelivery is absorbed by the same guard that protects every other write.
resource "google_cloud_scheduler_job" "tick" {
  name        = "remediation-tick"
  project     = var.project_id
  region      = var.region
  description = "Daily chase and exception sweep. Costs no model calls."
  schedule    = var.tick_schedule
  time_zone   = "Etc/UTC"

  # No attempt_deadline here. Cloud Scheduler only honours it for HTTP targets,
  # so on a Pub/Sub target the API accepts the field, discards it, and every
  # subsequent plan reports the same one-line change forever. A configuration
  # that never converges is worse than a missing setting: it teaches whoever
  # runs plan next to skim past a diff instead of reading it.
  #
  # Delivery timing is the subscription's job anyway — ack_deadline_seconds and
  # the retry policy in events.tf are where it actually takes effect.

  retry_config {
    retry_count = 3
  }

  pubsub_target {
    topic_name = google_pubsub_topic.tick.id

    # Deliberately carries no cycle number. Cloud Scheduler cannot template the
    # date into a payload and keeps no counter, so any literal here would be
    # the same integer every day — and since the cycle is half the idempotency
    # key, the guard would correctly skip every tick after the first. The
    # schedule would quietly stop doing anything on day two while still
    # reporting success, which is invisible from the scheduler console.
    #
    # The worker derives the cycle from the day instead. Publishing this same
    # payload by hand runs the same tick; adding a "cycle" field to it
    # reproduces any specific past run.
    data = base64encode(jsonencode({
      advance_days = var.tick_advance_days
    }))
  }
}

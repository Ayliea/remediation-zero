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

output "tick_topic" {
  description = "Publish here by hand to run a cycle without waiting for the schedule."
  value       = google_pubsub_topic.tick.id
}

output "dead_letter_topic" {
  description = "Where a tick goes when the fleet could not process it."
  value       = google_pubsub_topic.dead_letter.id
}

output "dead_letter_subscription" {
  description = "Pull from here to see what failed. Nothing drains it automatically."
  value       = google_pubsub_subscription.dead_letter_hold.name
}

output "schedule" {
  description = "When the fleet runs itself."
  value       = "${google_cloud_scheduler_job.tick.schedule} ${google_cloud_scheduler_job.tick.time_zone}"
}

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

variable "project_id" {
  description = "Google Cloud project."
  type        = string
  default     = "remediation-zero"
}

variable "project_number" {
  description = "Needed to name the Pub/Sub service agent, which dead-lettering requires."
  type        = string
  default     = "978104855285"
}

variable "region" {
  description = "Where the workers and the scheduler live. Not the model location."
  type        = string
  default     = "us-central1"
}

variable "tick_schedule" {
  description = "Cron for the daily tick, in UTC."
  type        = string
  default     = "0 9 * * *"
}

variable "tick_advance_days" {
  description = <<-EOT
    Simulated days each tick moves the clock forward. Zero in real mode, where
    advance() refuses to move at all; the worker answers 400 rather than
    fabricating elapsed time, and the message dead-letters rather than
    disappearing. Set this only alongside SIM_CLOCK_MODE=sim on the workers.
  EOT
  type        = number
  default     = 0
}

variable "max_delivery_attempts" {
  description = <<-EOT
    Deliveries before a message is dead-lettered. Five is the Pub/Sub minimum
    and is deliberate: a tick that has failed five times is not going to
    succeed on the sixth, and every further retry is another attempt to write
    state the fleet has already failed to write.
  EOT
  type        = number
  default     = 5
}

variable "console_url" {
  description = "The read-only console. Kept warm so a cold start never greets a visitor."
  type        = string
  default     = "https://remediation-zero-console-978104855285.us-central1.run.app"
}

variable "console_warm_schedule" {
  description = <<-EOT
    How often to ping the console so Cloud Run keeps an instance alive. Five
    minutes is chosen against Cloud Run's idle-instance retention rather than
    against a cost ceiling: the ping itself is free in every practical sense.
  EOT
  type        = string
  default     = "*/5 * * * *"
}

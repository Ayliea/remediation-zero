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

# What this configuration deliberately does not manage.
#
# Terraform owns the event plumbing and nothing else. The Agent Engine, its
# long-running session, the Firestore databases, the per-agent service accounts
# and the Cloud Run services are all read here as data rather than declared as
# resources.
#
# That boundary is a safety property, not an oversight. The Agent Engine holds
# a session with days of real elapsed wall-clock time on it, which is the one
# thing in this project that cannot be regenerated before the deadline. A
# resource Terraform does not manage is a resource `terraform destroy` cannot
# take, and importing it to make the configuration look complete would trade
# that guarantee for tidiness.
#
# The service accounts are created by scripts/grant-iam.sh, which is the script
# a reader should read to understand the identity model.

data "google_cloud_run_service" "worker" {
  for_each = local.agents

  name     = "rz-worker-${each.key}"
  project  = var.project_id
  location = var.region
}

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

"""The scheduled worker.

Cloud Scheduler publishes one tick a day to a single topic. Two push
subscriptions fan it out to two instances of this service, one running as
rz-chase and one as rz-exception, so the per-agent identity boundary survives
the move from a command line to a schedule.
"""

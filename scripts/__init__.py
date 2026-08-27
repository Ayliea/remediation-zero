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

"""Shared setup for the command-line drivers.

The agents themselves live in `agents/` and their capabilities in `tools/`.
This package holds the things that only matter when a human is running a
command and reading the output.
"""

import logging

#: SDK loggers that log every request at INFO, burying the structured cycle
#: log that is the actual observability surface.
_NOISY = ("httpx", "google_genai", "google.auth", "urllib3")

#: The google-genai SDK warns once per process that automatic function calling
#: is better used through Chat.send_message. The fleet calls generate_content
#: deliberately: each triage and review is a single stateless turn, not a
#: conversation, so there is no chat session to carry. The advice does not
#: apply, and the line lands in the middle of the structured log where it reads
#: like a fault.
#:
#: Dropped by exact message rather than by raising the logger to ERROR, because
#: silencing every warning this SDK might ever raise to hide one known-benign
#: line is how a real warning goes unnoticed on the day it matters.
_AFC_NOTICE = "Direct use of automatic function calling (AFC)"


class _DropAFCNotice(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not record.getMessage().startswith(_AFC_NOTICE)


def quiet_sdk_logging(*extra: str) -> None:
    """Leave the structured fleet log as the only thing on stdout.

    Extra logger names are quieted alongside the defaults; the graph driver
    passes "google.adk", which narrates every node it enters.
    """
    for name in (*_NOISY, *extra):
        logging.getLogger(name).setLevel(logging.WARNING)
    logging.getLogger("google_genai.models").addFilter(_DropAFCNotice())

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

"""The idempotency key is the control that stops a resumed agent from opening
a second ticket, sending a fourth nudge as its first, or escalating twice.

It is demonstrated on camera, so it cannot be discovered broken late.
"""

from tools.idempotency import KEY_SCHEME, derive_key, derive_record


def test_same_inputs_always_derive_the_same_key():
    """A resumed agent recomputes the key from scratch and must land on the
    same value, or the resume opens a duplicate."""
    first = derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=7)
    second = derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=7)

    assert first == second


def test_distinct_actions_never_collide_across_field_boundaries():
    """Concatenating fields without a boundary lets one field's tail merge into
    the next field's head. Here 'nudge' + cycle 12 and 'nudge1' + cycle 2 both
    flatten to 'nudge12', which would make a cycle-12 nudge silently reuse the
    key of a different action and be suppressed as a duplicate."""
    twelfth_nudge = derive_key(finding_id="CVE-2024-1234", action="nudge", cycle=12)
    second_nudge1 = derive_key(finding_id="CVE-2024-1234", action="nudge1", cycle=2)

    assert twelfth_nudge != second_nudge1


def test_key_does_not_leak_the_finding_id():
    """The key is opaque. Finding identifiers are not carried in document
    names, where they would appear in console URLs, logs and error messages
    that were never scoped to hold them."""
    key = derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=7)

    assert "CVE-2024-1234" not in key
    assert "ticket" not in key


def test_key_is_fixed_width_regardless_of_input_length():
    """A key is a document name. Fixed width keeps it a safe one whatever the
    finding identifier turns out to look like."""
    short = derive_key(finding_id="A", action="ticket", cycle=1)
    long = derive_key(finding_id="CVE-2024-1234" * 40, action="ticket", cycle=1)

    assert len(short) == len(long) == 64


def test_record_carries_the_components_so_an_opaque_key_stays_traceable():
    """Opacity must not cost the analyst the ability to answer 'what is this?'.
    Every writer persists the components alongside the key, so a single
    finding's journey is still queryable end to end without a rainbow table."""
    record = derive_record(finding_id="CVE-2024-1234", action="ticket", cycle=7)

    assert record.key == derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=7)
    assert record.finding_id == "CVE-2024-1234"
    assert record.action == "ticket"
    assert record.cycle == 7


def test_record_names_the_scheme_that_produced_the_key():
    """Keys outlive the code that made them. A stored scheme version is how a
    later change is recognised as a change rather than as a silent collision."""
    record = derive_record(finding_id="CVE-2024-1234", action="ticket", cycle=7)

    assert record.scheme == KEY_SCHEME

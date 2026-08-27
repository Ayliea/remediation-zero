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

import pytest

from tools.idempotency import (
    KEY_SCHEME,
    IdempotencyGuard,
    InMemoryIdempotencyStore,
    derive_key,
    derive_record,
)


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


# --- normalisation: what is deliberately folded -----------------------------

def test_finding_id_case_does_not_split_the_key():
    """CVE identifiers are conventionally uppercase and a lowercase one means
    the same vulnerability. Splitting on case opens two tickets for one CVE."""
    upper = derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=7)
    lower = derive_key(finding_id="cve-2024-1234", action="ticket", cycle=7)

    assert upper == lower


def test_action_case_does_not_split_the_key():
    """Actions are a vocabulary this system generates, so no action is
    case-significant. An inconsistent literal at one call site must not mint a
    second key and send a duplicate."""
    assert derive_key(finding_id="CVE-2024-1234", action="nudge", cycle=3) == derive_key(
        finding_id="CVE-2024-1234", action="Nudge", cycle=3
    )


def test_surrounding_whitespace_is_stripped():
    """Trailing whitespace off a CSV column or a copied identifier is an
    artefact of transport, not a different finding."""
    clean = derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=7)
    padded = derive_key(finding_id="  CVE-2024-1234\n", action=" ticket ", cycle=7)

    assert clean == padded


# --- normalisation: what is deliberately NOT folded -------------------------

def test_internal_whitespace_still_separates_keys():
    """Guard on a decision, not a discovered behaviour. Collapsing internal
    whitespace is unjustified until real findings show it is needed, and the
    cost of folding something meaningful is a silently suppressed action."""
    assert derive_key(finding_id="CVE-2024-1234", action="risk accept", cycle=1) != derive_key(
        finding_id="CVE-2024-1234", action="riskaccept", cycle=1
    )


def test_unicode_lookalikes_still_separate_keys():
    """NFKC folding is not applied. finding_id originates in the trusted seed
    script rather than scanner free text, so there is no homoglyph pressure
    here, and folding without evidence risks merging distinct identifiers."""
    ascii_id = derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=1)
    # Fullwidth C, V, E (U+FF23, U+FF36, U+FF25). NFKC would fold these to
    # ASCII; we do not apply NFKC, so they must stay distinct.
    fullwidth = derive_key(
        finding_id="\uff23\uff36\uff25-2024-1234", action="ticket", cycle=1
    )
    assert ascii_id != fullwidth  # sanity: the inputs really do differ

    assert ascii_id != fullwidth


# --- normalisation: what is rejected ----------------------------------------

def test_empty_finding_id_is_rejected():
    """A key derived from nothing is still a valid-looking key. It would
    deduplicate every finding against every other."""
    with pytest.raises(ValueError, match="finding_id"):
        derive_key(finding_id="", action="ticket", cycle=1)


def test_whitespace_only_action_is_rejected():
    """Rejected after stripping, not before: '   ' is empty for this purpose."""
    with pytest.raises(ValueError, match="action"):
        derive_key(finding_id="CVE-2024-1234", action="   ", cycle=1)


def test_negative_cycle_is_rejected():
    """Cycle numbers count upward from zero. A negative one is a bug upstream
    and must not be laundered into a plausible key."""
    with pytest.raises(ValueError, match="cycle"):
        derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=-1)


def test_record_stores_the_normalised_components_not_the_raw_ones():
    """The record explains the key. If it stored the raw input, the components
    would not reproduce the key they are filed under."""
    record = derive_record(finding_id="  cve-2024-1234 ", action=" Ticket ", cycle=7)

    assert record.finding_id == "CVE-2024-1234"
    assert record.action == "ticket"
    assert record.key == derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=7)


# --- the guard that actually suppresses the second effect -------------------

def test_a_repeated_call_produces_no_second_effect():
    """The whole point. A resumed agent recomputes the same key and the ticket
    is opened once, not twice."""
    guard = IdempotencyGuard(InMemoryIdempotencyStore())
    opened = []

    @guard.protects(action="ticket")
    def open_ticket(*, finding_id, cycle):
        opened.append((finding_id, cycle))
        return f"TICKET-{len(opened)}"

    open_ticket(finding_id="CVE-2024-1234", cycle=7)
    open_ticket(finding_id="CVE-2024-1234", cycle=7)

    assert opened == [("CVE-2024-1234", 7)]


def test_a_repeated_call_returns_the_first_result():
    """The caller cannot tell it was suppressed, which is what makes resume
    transparent to everything upstream."""
    guard = IdempotencyGuard(InMemoryIdempotencyStore())
    counter = []

    @guard.protects(action="ticket")
    def open_ticket(*, finding_id, cycle):
        counter.append(1)
        return f"TICKET-{len(counter)}"

    first = open_ticket(finding_id="CVE-2024-1234", cycle=7)
    second = open_ticket(finding_id="CVE-2024-1234", cycle=7)

    assert first == second == "TICKET-1"


def test_a_later_cycle_is_a_new_effect():
    """Suppression is scoped to the cycle. Week three's nudge is not week
    two's nudge, and must still send."""
    guard = IdempotencyGuard(InMemoryIdempotencyStore())
    sent = []

    @guard.protects(action="nudge")
    def nudge(*, finding_id, cycle):
        sent.append(cycle)

    nudge(finding_id="CVE-2024-1234", cycle=2)
    nudge(finding_id="CVE-2024-1234", cycle=2)
    nudge(finding_id="CVE-2024-1234", cycle=3)

    assert sent == [2, 3]


def test_a_failed_call_is_not_recorded_and_can_be_retried():
    """A transient failure must not permanently suppress the action. Recording
    on entry rather than on success would make one network blip mean a nudge
    that can never be sent again."""
    guard = IdempotencyGuard(InMemoryIdempotencyStore())
    attempts = []

    @guard.protects(action="escalate")
    def escalate(*, finding_id, cycle):
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionError("ticketing system unreachable")
        return "ESCALATED"

    with pytest.raises(ConnectionError):
        escalate(finding_id="CVE-2024-1234", cycle=1)

    assert escalate(finding_id="CVE-2024-1234", cycle=1) == "ESCALATED"
    assert len(attempts) == 2


def test_the_store_keeps_the_record_not_just_the_key():
    """So the suppression itself is explicable after the fact."""
    store = InMemoryIdempotencyStore()
    guard = IdempotencyGuard(store)

    @guard.protects(action="ticket")
    def open_ticket(*, finding_id, cycle):
        return "TICKET-1"

    open_ticket(finding_id="cve-2024-1234", cycle=7)

    record = store.get(derive_key(finding_id="CVE-2024-1234", action="ticket", cycle=7))
    assert record.finding_id == "CVE-2024-1234"
    assert record.action == "ticket"
    assert record.cycle == 7

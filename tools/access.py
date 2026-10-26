# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Who may do what in the local edition: the one permission table.

Every handler and command asks `allowed`. An action that is not in the table
raises `KeyError` rather than answering, so a misspelt or new action is denied
loudly instead of quietly allowed. A role that is not `owner` or `tech`
(including None, for nobody signed in) is allowed nothing. Standard library
only.
"""

ACTIONS = frozenset({'view', 'settings', 'upload', 'approve', 'accept_risk',
                     'manage_accounts', 'view_audit'})

# The spec's table: an owner may do everything; a tech works the findings and
# configures the install, but cannot accept a risk, manage accounts or read
# the account audit trail.
_TABLE = {
    'owner': ACTIONS,
    'tech': frozenset({'view', 'settings', 'upload', 'approve'}),
}


def allowed(role: str | None, action: str) -> bool:
    if action not in ACTIONS:
        raise KeyError(action)
    return action in _TABLE.get(role, frozenset())


def may_invite(inviter_role: str | None, invitee_role: str, owner_exists: bool) -> bool:
    """An owner may invite either role. A tech may invite only an owner, and
    only while no owner has joined: the installing MSP's bootstrap case."""
    if invitee_role not in _TABLE:
        return False
    if inviter_role == 'owner':
        return True
    if inviter_role == 'tech':
        return invitee_role == 'owner' and not owner_exists
    return False

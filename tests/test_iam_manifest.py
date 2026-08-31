# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""The deployment manifest must match the model boundary described publicly."""

from pathlib import Path


SOURCE = (
    Path(__file__).resolve().parents[1] / "scripts" / "grant-iam.sh"
).read_text(encoding="utf-8")


def test_only_model_callers_are_in_the_vertex_grant_loop():
    grant_loop = SOURCE.split(
        "Granting model access only to identities whose code calls a model"
    )[1].split("done", 1)[0]

    for agent in ("orchestrator", "triage", "reviewer", "reporting"):
        assert agent in grant_loop
    for deterministic in ("ownership", "chase", "exception"):
        assert deterministic not in grant_loop


def test_stale_vertex_grants_are_explicitly_removed():
    removal = SOURCE.split("Earlier deployments granted Vertex access")[1]
    assert "remove-iam-policy-binding" in removal
    for deterministic in ("ownership", "chase", "exception"):
        assert deterministic in removal


def test_fresh_setup_creates_every_agent_identity():
    creation = SOURCE.split("Creating the seven agent service accounts")[1]
    creation = creation.split("has_vertex_access", 1)[0]
    assert "service-accounts create" in creation
    for agent in (
        "orchestrator", "triage", "reviewer", "ownership", "chase",
        "exception", "reporting",
    ):
        assert agent in creation


def test_vertex_revocation_is_verified_before_claiming_absence():
    removal = SOURCE.split("Earlier deployments granted Vertex access")[1]
    assert "has_vertex_access" in removal
    assert "exit 1" in removal
    assert "verified absent" in removal
    assert "could not verify Vertex access" in removal

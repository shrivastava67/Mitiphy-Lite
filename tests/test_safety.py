"""AUP + consent gates."""

from __future__ import annotations

from pathlib import Path

from mitiphy.safety.aup import AUPGate
from mitiphy.safety.consent import ConsentGate


def test_aup_unaccepted_by_default(tmp_path: Path) -> None:
    gate = AUPGate(tmp_path / "aup.json", revision="rev-1")
    assert gate.is_accepted() is False


def test_aup_acceptance_persists(tmp_path: Path) -> None:
    gate = AUPGate(tmp_path / "aup.json", revision="rev-1")
    h = gate.record_acceptance("AUP TEXT")
    assert len(h) == 64
    assert AUPGate(tmp_path / "aup.json", revision="rev-1").is_accepted() is True


def test_aup_revision_change_invalidates(tmp_path: Path) -> None:
    AUPGate(tmp_path / "aup.json", revision="rev-1").record_acceptance("A")
    assert AUPGate(tmp_path / "aup.json", revision="rev-2").is_accepted() is False


def test_consent_granted_only_on_yes() -> None:
    gate = ConsentGate(prompter=lambda _q: "YES")
    decision = gate.require("alice", "person")
    assert decision.granted is True
    assert decision.answer_hash != ""


def test_consent_denied_on_no() -> None:
    gate = ConsentGate(prompter=lambda _q: "no")
    decision = gate.require("alice", "person")
    assert decision.granted is False


def test_consent_hash_is_stable() -> None:
    g1 = ConsentGate(prompter=lambda _q: "YES")
    g2 = ConsentGate(prompter=lambda _q: "YES")
    assert g1.require("a", "person").answer_hash == g2.require("a", "person").answer_hash

"""Person-target consent prompt.

When Target.is_person, the orchestrator must call ConsentGate.require()
before running collectors. The answer (and its hash) goes into the audit chain.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class ConsentDecision:
    granted: bool
    answer_hash: str
    answer_text: str


class ConsentGate:
    """Decoupled prompt so tests and the web UI can inject answers."""

    def __init__(self, prompter: Callable[[str], str] | None = None) -> None:
        self._prompter = prompter or self._default_prompter

    @staticmethod
    def _default_prompter(question: str) -> str:
        try:
            return input(question)
        except EOFError:
            return ""

    @staticmethod
    def _hash_answer(answer: str) -> str:
        return hashlib.sha256(answer.strip().encode("utf-8")).hexdigest()

    def require(self, target_value: str, target_type: str) -> ConsentDecision:
        """Prompt the user; return a ConsentDecision."""
        prompt = (
            f"\nTarget {target_value!r} appears to be a {target_type}.\n"
            f"Confirm you have a lawful basis (own consent / written authorization /\n"
            f"defensive investigation of your own asset) by typing YES:\n> "
        )
        answer = self._prompter(prompt)
        granted = answer.strip().upper() == "YES"
        return ConsentDecision(
            granted=granted,
            answer_hash=self._hash_answer(answer),
            answer_text=("yes" if granted else "no"),
        )

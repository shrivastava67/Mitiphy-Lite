"""AUP acceptance gate.

First-run flow:
  1. User runs `mitiphy` for any command other than `aup` / `help` / `--version`.
  2. AUPGate.is_accepted() returns False.
  3. CLI prints AUP and prompts for acceptance, or refuses with --no-aup.
  4. On accept, write aup_accepted.json with revision + timestamp + hash;
     append same to audit chain.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


class AUPGate:
    def __init__(self, acceptance_file: Path, revision: str) -> None:
        self.acceptance_file = Path(acceptance_file)
        self.revision = revision

    def is_accepted(self) -> bool:
        if not self.acceptance_file.exists():
            return False
        try:
            data = json.loads(self.acceptance_file.read_text(encoding="utf-8"))
            return data.get("revision") == self.revision
        except Exception:
            return False

    def record_acceptance(self, aup_text: str) -> str:
        """Record acceptance to disk and return the revision hash."""
        rev_hash = hashlib.sha256(
            (self.revision + "\n" + aup_text).encode("utf-8")
        ).hexdigest()
        payload = {
            "revision": self.revision,
            "revision_hash": rev_hash,
            "accepted_at": time.time(),
        }
        self.acceptance_file.parent.mkdir(parents=True, exist_ok=True)
        self.acceptance_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return rev_hash

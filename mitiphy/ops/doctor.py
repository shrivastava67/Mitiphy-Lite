"""mitiphy doctor — self-check."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from ..audit.chain import AuditChain
from ..core.config import get_settings
from ..core.plugin import CollectorRegistry
from ..llm.base import NoLLMProvider, get_provider
from ..safety.aup import AUPGate
from ..safety.quota import QuotaManager


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class DoctorReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


def run_doctor() -> DoctorReport:
    s = get_settings()
    s.ensure_dirs()
    report = DoctorReport()

    # State directory writable.
    test_file = s.state_dir / ".doctor_probe"
    try:
        test_file.write_text("ok")
        test_file.unlink()
        report.checks.append(CheckResult("state_dir_writable", True, str(s.state_dir)))
    except Exception as exc:
        report.checks.append(CheckResult("state_dir_writable", False, repr(exc)))

    # Audit chain reachable + verifies.
    try:
        chain = AuditChain(s.audit_db)
        chain.ensure_genesis(installer_version="doctor")
        ok, count, bad = chain.verify()
        report.checks.append(
            CheckResult(
                "audit_chain_verifies",
                ok,
                f"rows={count}" + (f" bad_at={bad}" if bad else ""),
            )
        )
    except Exception as exc:
        report.checks.append(CheckResult("audit_chain_verifies", False, repr(exc)))

    # Quota DB usable.
    try:
        q = QuotaManager(s.quota_db)
        q.usage_report()
        report.checks.append(CheckResult("quota_db_ok", True))
    except Exception as exc:
        report.checks.append(CheckResult("quota_db_ok", False, repr(exc)))

    # AUP file present (may not be accepted — that's a warning not a fail).
    aup = AUPGate(s.aup_acceptance_file, s.aup_revision)
    report.checks.append(
        CheckResult(
            "aup_accepted",
            aup.is_accepted(),
            s.aup_revision if aup.is_accepted() else "not accepted yet — run `mitiphy aup --accept`",
        )
    )

    # Plugin discovery.
    try:
        reg = CollectorRegistry.discover(s.plugins_dir)
        report.checks.append(
            CheckResult(
                "plugins_discovered",
                len(reg.collectors) > 0,
                f"{len(reg.collectors)} collectors",
            )
        )
    except Exception as exc:
        report.checks.append(CheckResult("plugins_discovered", False, repr(exc)))

    # LLM provider.
    provider = get_provider()
    report.checks.append(
        CheckResult(
            "llm_provider",
            True,
            f"{provider.name}"
            + (" (headless — install mitiphy[llm] to enable)" if isinstance(provider, NoLLMProvider) else ""),
        )
    )

    # Network reachability — DNS lookup against a few public hosts.
    hosts = ["api.first.org", "crt.sh", "archive.org", "api.osv.dev"]
    net_ok = False
    detail_parts = []
    for h in hosts:
        try:
            socket.gethostbyname(h)
            detail_parts.append(f"{h}=ok")
            net_ok = True
        except OSError:
            detail_parts.append(f"{h}=fail")
    report.checks.append(
        CheckResult("network_reachable", net_ok, ", ".join(detail_parts))
    )

    # Telemetry must be off.
    report.checks.append(
        CheckResult(
            "telemetry_disabled",
            not s.enable_telemetry,
            "telemetry must remain off (CI enforces)",
        )
    )

    return report

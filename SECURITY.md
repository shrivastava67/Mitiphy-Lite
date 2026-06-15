# Security Policy

## Supported versions

Mitiphy follows semantic versioning. Security fixes are produced for the most recent **minor** release on the current major.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Older versions may receive critical fixes at the maintainers' discretion.

## Reporting a vulnerability

**Please do not file a public GitHub issue for security problems.**

Use **GitHub's private vulnerability reporting** for this repository:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill out the form with:
   - A clear description of the issue.
   - Steps to reproduce (PoC welcome).
   - Affected version(s) / commit hashes.
   - Suggested fix or workaround, if you have one.

If you cannot use GitHub's vulnerability reporting, contact the maintainers via the email listed in the repository's GitHub profile.

## What to expect

| Stage | Target time |
|-------|-------------|
| Acknowledgement of report | within **72 hours** |
| Triage + initial assessment | within **7 days** |
| Patch release (high/critical) | within **30 days** of confirmation |
| CVE assignment (where applicable) | with the patch release |

## Scope

In scope:

- Mitiphy core (`mitiphy/` Python package).
- Installer scripts (`install.sh`, `install.ps1`).
- Bundled report templates.
- Default collector adapters.
- Audit-chain tamper-evidence guarantees.
- Egress-allowlist guarantees (no telemetry).

Out of scope:

- Issues in the user's locally installed third-party plugins.
- Issues in optional extras (llama.cpp, WeasyPrint, KuzuDB, LanceDB) — please report upstream.
- Theoretical attacks requiring host root access.
- Reports requiring active recon against systems the reporter is not authorized to test.

## Safe-harbor

Security researchers acting in good faith and respecting this policy will not be subject to legal action by the Mitiphy maintainers. Please:

- Do not access or modify data that is not your own.
- Do not exfiltrate user data.
- Give us reasonable time to fix issues before public disclosure.
- Test only against systems you own or have authorization to test.

Thank you for helping keep Mitiphy and its users safe.

# Mitiphy Acceptable Use Policy (AUP)

Mitiphy is a defensive OSINT and threat-intelligence tool. By using Mitiphy, you agree to operate within the law and within ethical norms for security research.

## What you may use Mitiphy for

- Investigating identifiers (emails, domains, IPs, hashes, etc.) that **you own** or have **explicit written authorization** to investigate.
- Defensive threat-intelligence work: triaging indicators of compromise, mapping observed adversary behavior to MITRE ATT&CK, scoring vulnerability exposure for systems under your control.
- Authorized penetration tests and red-team engagements where the target is enumerated in a signed scope document.
- CTF challenges, security training, and educational use against intentionally vulnerable targets.
- Academic and journalistic research conducted under your institution's ethics policy.

## What you may NOT use Mitiphy for

- Active reconnaissance, scanning, probing, or enumeration of any system you do not own or have written authorization to test. Active recon is **disabled by default** in the Lite profile and remains gated by a signed `authorized_targets.yml` in higher profiles.
- Targeted surveillance of private individuals without their informed consent.
- Stalking, harassment, doxxing, or facilitating violence against any person.
- Circumventing access controls or terms of service of third-party platforms.
- Generating reports intended to defame, intimidate, extort, or otherwise harm a person or organization.
- Any activity prohibited by the laws of your jurisdiction or the jurisdiction in which the target resides.

## Person targets

When Mitiphy detects that a target appears to identify a natural person (for example, a `person` or `username` type), it will prompt for an explicit acknowledgement that you have a lawful basis for the investigation. The acknowledgement is hashed and stored in the tamper-evident audit chain. You should be prepared to produce the underlying authorization on request.

## API quotas and free-tier compliance

Mitiphy enforces per-API quota caps so that operations refuse to proceed rather than leak into paid tiers or violate the rate limits of free services it depends on. You are responsible for honoring the terms of service of any third-party API you configure.

## Telemetry

Mitiphy emits zero outbound telemetry. No usage data is sent to any third party by default. The continuous integration pipeline asserts the absence of outbound calls to non-allowlisted hosts.

## Acceptance

The first time you run `mitiphy`, you will be asked to acknowledge this AUP. Your acknowledgement is recorded in `~/.mitiphy/audit.sqlite` together with the AUP revision hash. Re-running with `mitiphy --accept-aup` re-records the acknowledgement.

## Reporting abuse

If you become aware that Mitiphy is being used in violation of this policy, please open a confidential report at the project's security advisory tracker on GitHub.

---

AUP revision: 2026-06-06 (v1)

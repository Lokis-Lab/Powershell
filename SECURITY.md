# Security policy

We take security reports seriously. This document describes how to report vulnerabilities responsibly and what you can expect from maintainers.

## Supported versions

Security fixes are intended for **actively maintained** branches, tags, or release lines. Which versions are supported may vary by component in this repository—check the README, changelog, or release notes for the specific package or subproject you are using.

If documentation is unclear, open a **non-sensitive** question (for example, a discussion or issue asking which branch or release to use for production), or ask through your usual support channel. Do **not** include exploit details in public posts.

## How to report a vulnerability

**Do not** open a public issue, pull request, or discussion that describes an exploitable security flaw before it is fixed and users can protect themselves.

### Preferred channels

Use **one** of the following, depending on what this project has enabled:

1. **GitHub** — If private vulnerability reporting is enabled for this repository: open the repository on GitHub, go to **Security**, then **Report a vulnerability** (or **Advisories** → **Report a vulnerability**). That keeps the report private between you and maintainers.
2. **Email** — If maintainers publish a security contact (for example in this file, the README, or the organization’s website), use that address and put a clear subject line such as `Security: [short summary]`.

Maintainers should **replace this paragraph** with concrete instructions (exact link or email) so reporters are not left guessing.

### What to include

The more precise and reproducible your report, the faster it can be validated and fixed. Include when you can:

- **Description** — What the issue is and why it matters (confidentiality, integrity, availability, privilege boundary, supply chain, etc.).
- **Affected scope** — Components, versions, branches, configuration, or deployment context.
- **Reproduction** — Minimal steps, proof-of-concept, or test case. Redact secrets and personal data.
- **Impact** — Who can exploit it, what they could do, and any mitigations you are aware of.
- **Discovery** — Whether the issue was found by you, by automation, or disclosed elsewhere (with links if already public elsewhere).

If you wish to be credited in release notes or an advisory, say how you would like your name or handle to appear.

## What we will do

- **Acknowledge** receipt when possible, so you know the report was seen.
- **Investigate** in good faith and keep you informed of material status changes (triaged, accepted, declined, fixed).
- **Coordinate disclosure** — We aim to release a fix and guidance before technical details are published broadly. We may request a short embargo period so users can upgrade.
- **Credit** — We appreciate responsible reporting and will credit reporters when they want recognition, unless we are legally constrained not to.

Timelines depend on severity, complexity, and maintainer availability. Critical issues affecting confidentiality or remote code execution are prioritized.

## Safe harbor

We support **good-faith** security research that follows this policy:

- Do not access, modify, or exfiltrate data that is not yours, except minimally needed to demonstrate the issue.
- Do not degrade service for others (no denial-of-service attacks against production).
- Do not attempt physical or social engineering, or third-party services, unless explicitly in scope for a bug bounty program published by this project.
- Stop testing and report promptly when you find a serious issue.

If you are unsure whether something is in scope, ask through the private reporting channel before testing aggressively.

## Out of scope (examples)

Reports may be declined or deprioritized when they concern, for example:

- Issues in dependencies or platforms that are already fixed upstream in a version this project could adopt
- Theoretical problems without a plausible exploit path
- Missing security headers or best practices with no demonstrated impact for this project
- Content spoofing or UI issues that do not cross a trust boundary
- Secrets that are already public, sample data, or test credentials committed intentionally in fixtures

Maintainers may still appreciate a heads-up for borderline cases; use judgment and the private channel when impact is unclear.

## After a fix

We may publish a **security advisory** (for example through GitHub Security Advisories) with severity, affected versions, patches, and upgrade instructions. You can help by verifying the fix and respecting agreed disclosure timing.

---

Thank you for helping keep users and this project safe.

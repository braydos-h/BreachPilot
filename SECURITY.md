# Security Policy

BreachPilot is a lab-only offensive security tool. Use it only against
networks and systems you own or have explicit written authorization to
assess, on a throwaway operator box.

## Supported versions

| Version | Supported |
|---|---|
| `0.68.x` (`main`) | Yes — security fixes land here |
| Older betas (e.g. `v0.49.x` prereleases) | No — upgrade to `main` |

The published prerelease trail may lag the source during the reliability
milestone (see `todo/08-p1-release-069-beta.md`); when in doubt, test
against the latest `main` and say which commit you used.

## Reporting a vulnerability

**Do not open a public issue.** BreachPilot is offensive by design, so
please report privately:

- Preferred: open a **private** GitHub Security Advisory for this repo
  (`Security` tab → `Advisories` → `New draft advisory`). Only the
  maintainers see it until disclosure is coordinated.
- If private advisories are unavailable, contact the maintainer through
  the profile-listed channel on <https://github.com/braydos-h> and ask for
  a private channel before sharing details.

Include: affected commit/version, what you did (lab target only — never
test against systems you are not authorized to assess), what you expected,
what happened, and the smallest reproduction (config excerpt redacted,
relevant log lines). Reports with a reproduction get triaged first.

## Disclosure expectations

- We will acknowledge receipt within a few days and keep you updated as a
  fix progresses. This is a solo-maintainer project, so complex issues can
  take longer; we will say so rather than go silent.
- We will coordinate the disclosure timeline with you before publishing
  details: fix on `main`, brief advisory notes, credit if you want it
  (or anonymity if you prefer).
- While a report is being handled, please do not disclose it publicly,
  and please do not probe other operators' systems with it.

## Scope notes

- In scope: BreachPilot's own code — scope/allowlist enforcement, sandbox
  containment, audit behavior, credential handling, WebUI auth, packaging,
  and dependency supply chain.
- Out of scope: vulnerabilities in the **targets** you test with it, and
  any testing performed against systems you do not own or lack explicit
  written authorization to assess.
- Safe harbor: good-faith research against your own lab systems, following
  this policy, will not be treated adversely. Do not exfiltrate data that
  is not yours, do not disrupt shared services, and stop if you reach
  anything out of scope.

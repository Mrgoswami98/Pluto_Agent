# Changelog

All notable changes to Pluto Advance are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Not yet done
- Windows installer has **not** been built (needs a Windows host or CI runner)
- Windows desktop automation is **not** functionally tested (needs a real desktop)
- Claude API integration is tested against mocks only (needs a real API key)

See `docs/STATUS.md` for the itemised status.

---

## [0.5.0] - 2026-10-02

First working build of the Pluto Advance agent.

### Added

**Security foundations**
- `PathGuard` filesystem sandbox: symlink-aware resolution, traversal rejection
  for not-yet-existing targets, protected-location blocklist, executable-write
  refusal, NTFS alternate-data-stream rejection, default deny
- Secret redaction for Anthropic, OpenAI, GitHub, AWS, Google, Slack and Stripe
  keys, JWTs, bearer headers, private key blocks, inline URL credentials and
  Luhn-validated card numbers
- `CredentialStore` backed by the OS vault (Windows Credential Manager), with
  environment and 0600-file fallbacks
- Centralised `PermissionEngine`: four autonomy modes, risk tiers, scoped and
  expiring approvals, and an always-confirm list that holds in every mode
- Global Emergency Stop that overrides approvals and signals running work
- Untrusted-content handling with framing, detection and containment

**Data**
- SQLite schema with versioned, transactional migrations
- Repositories for tasks, steps, approvals, audit, memory, preferences,
  schedules and tool invocations, all redacting before write
- Append-only audit trail with retention pruning and JSONL export
- Unique index preventing duplicate scheduled runs after a restart

**Intelligence**
- Claude API client with exponential backoff, retry-after support, token
  accounting and cancellable waits
- Planner that recomputes risk from the tool registry rather than trusting the
  model's declared risk
- Task orchestrator with dependency ordering, bounded retries, budgets and a
  verification gate: a step is complete only when successful AND verified

**Tools**
- Nine filesystem tools, each verifying its own effect (content read back,
  SHA-256 digests compared, moves confirmed on both sides)
- Four spreadsheet tools for Excel and CSV analysis, filtering and export
- Five Playwright browser tools with a domain allow-list and credential-field
  refusal
- Five Windows UI Automation tools with protected-window refusal

**Interface**
- PySide6 desktop application: chat, tasks, approvals, activity, permissions,
  memory and settings, with light and dark themes
- Emergency Stop reachable from every view
- Progress that counts only verified completions

**Project**
- 530+ automated tests, all executed
- GitHub Actions workflows for tests and for a Windows build
- PyInstaller spec and Inno Setup script

### Fixed during development

Bugs found by the test suite, each of which would have shipped broken:

- Playwright's sync API is thread-affine, but tools run in a worker pool for
  timeout enforcement — every browser call failed. The session now owns a
  dedicated browser thread and marshals operations onto it.
- In-memory and file SQLite connections had different isolation settings, so
  transactions nested and every task save during execution silently failed.
- Steps were validated against the task state machine, which has no
  PENDING to RUNNING edge; steps now have their own transition map.
- Qt unwraps str-subclass enums to plain strings, which broke the memory view
  and silently made the autonomy-mode selector a no-op.
- The approval card rendered tool arguments without redaction.
- Security refusals raised inside a tool were not written to the audit trail.
- The exfiltration detection pattern could never match ".env" because of an
  impossible word boundary.
- Windows path lists (`C:\A;C:\B`) split incorrectly on non-Windows hosts.
- `pydantic-settings` JSON-decoded env list values before validators ran.
- Security checks in the Windows tools ran after the platform check, so a
  policy violation reported the wrong reason.

[Unreleased]: https://github.com/OWNER/pluto-advance/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/OWNER/pluto-advance/releases/tag/v0.5.0

# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting (Security → Report a vulnerability) on this repository. Include what you did, what happened, what you expected, and the version from `pluto --status`.

---

## What Pluto Advance actually protects against

These are implemented and covered by automated tests. Each claim here corresponds to tests you can run.

### Filesystem sandbox (`src/pluto/security/paths.py`)

- Default deny: with no approved folders, **every** path is refused.
- Traversal (`../`) is rejected, **including against files that do not exist yet** — the naive implementation resolves only existing paths and misses this.
- Symlinks are resolved before the check, so a link inside the sandbox pointing outside it is refused.
- A sibling directory sharing a prefix (`/work` vs `/work-evil`) is not treated as inside.
- Protected system locations (`/etc/shadow`, `System32`, `.ssh`, credential stores) are refused even if explicitly granted.
- Executable file types (`.exe`, `.bat`, `.ps1`, `.dll`, …) cannot be written without an explicit override.
- NTFS alternate data streams (`notes.txt:hidden`) are rejected.

### Permission engine (`src/pluto/security/permissions.py`)

Every tool call passes through one `check()`. There is no bypass path.

- **Always-confirm actions** — sending email or messages, publishing, purchasing, payments, submitting forms, deleting or overwriting files, changing permissions, installing software, system configuration, sharing externally, running commands — require explicit human confirmation in **every** autonomy mode including Supervised. A test asserts this for all of them, in all four modes.
- A tool that declares a *lower* risk than its action warrants does not bypass this: the always-confirm list is keyed on the action, not the claimed risk.
- An approval is scoped to **one action kind at one risk level** and **expires**. It cannot be replayed for a different action or a higher risk.
- Emergency Stop overrides everything, including a valid approval.
- Disabled tools are refused before execution and are not offered to the model.

### Credential handling (`src/pluto/security/secrets.py`)

- The API key lives in the **OS credential vault** (Windows Credential Manager through `keyring`). It is deliberately *not* part of the settings model, so it cannot appear in a config dump, a diagnostics export or a crash report.
- The development file fallback is `0600` and off by default.
- Redaction runs before anything reaches the database or the logs: Anthropic/OpenAI/GitHub/AWS/Google/Slack/Stripe keys, JWTs, bearer headers, private key blocks, inline URL credentials, Luhn-validated card numbers, and values of sensitive field names.
- Redaction is applied again at the point of display in the approval UI, because an in-memory approval has not passed through the repository.

### Untrusted content (`src/pluto/security/untrusted.py`)

Web pages, files, spreadsheet cells and tool output are data, never instructions.

**The honest hierarchy:**

1. **Framing** — content is wrapped in a labelled envelope stating it must not be obeyed.
2. **Detection** — injection patterns are flagged and surfaced to the user. Invisible Unicode is stripped first, so a zero-width space inside a keyword does not defeat the scan.
3. **Containment** — *this is the actual guarantee.* Nothing the model concludes after reading untrusted content can bypass the permission engine, because permission checks happen at execution time against the tool's declared risk and the always-confirm list.

Detection is pattern matching and **will miss novel attacks**. The test suite therefore includes tests that assume detection fails entirely and verify a fully-convinced model still cannot delete a file or send an email without approval. Design to layer 3, not to layer 2.

### Browser (`src/pluto/automation/browser.py`)

- Domain allow-list, default deny. Matching is exact-host or `.domain` suffix, so `evil-example.com` and `example.com.attacker.net` are refused.
- `javascript:`, `data:`, `file:`, `vbscript:` and `about:` URLs rejected at validation.
- Password, PIN, CVV and card fields are **never** filled.
- Form snapshots record field names and types, never values.
- Cookies, tokens and storage are never read.
- CAPTCHA/2FA pauses for the human; Pluto does not attempt to solve or bypass them.
- A click that navigates off the allow-list goes back and reports failure.
- Browser runs **visible** by default.

### Windows automation (`src/pluto/automation/windows.py`)

- Application allow-list, default deny.
- UAC prompts, Windows Security, Defender, BitLocker, the registry editor, credential manager and admin consoles are refused **even when the user has approved that application**.
- Protected processes (`consent.exe`, `lsass.exe`, `cmd.exe`, `powershell.exe`, …) are refused.
- **There is no arbitrary shell or code-execution tool anywhere in the codebase**, and a test asserts no such tool name exists.
- Screenshots are off by default and the destination is sandboxed.

---

## Known limitations and residual risk

Passing a test suite is not the same as being secure. These are real and documented rather than hidden.

### 1. Prompt injection cannot be fully prevented
Detection is heuristic. A novel phrasing will get through the scanner. The mitigation is containment, not detection — but containment only limits damage to what the **current permissions allow**. A user who grants broad folder access and runs in Supervised mode has a correspondingly larger blast radius. Grant narrowly.

### 2. Approved actions are genuinely performed
Approving a deletion deletes the file. Pluto verifies and audits; it does not undo. There is no trash-can or rollback layer.

### 3. Emergency Stop cannot recall what already left
It cancels pending work and signals running work to stop at its next checkpoint. **An HTTP request already sent, a form already submitted, or an email already dispatched cannot be recalled.** The UI states this explicitly when the button is pressed rather than implying a clean stop.

### 4. Cancellation is cooperative
A tool is asked to stop at its next checkpoint. A tool blocked in a non-interruptible native call will finish that call first. Timeouts bound this, but the stop is not instantaneous.

### 5. The model can be wrong
Pluto verifies that an action *occurred*, not that it was *wise*. A correctly-executed wrong plan is still wrong. This is why the default mode is Assisted.

### 6. Secret redaction is pattern-based
Novel credential formats will not match. It reduces exposure; it does not eliminate it. Do not treat the logs as guaranteed secret-free.

### 7. Local data is not encrypted at rest
The SQLite database and logs rely on the OS account and filesystem permissions. Anyone with access to the Windows account can read task history. Use BitLocker if that matters.

### 8. Dependency supply chain
Pluto depends on Anthropic's SDK, Playwright, PySide6, pandas and others. Their vulnerabilities are inherited. Keep them updated.

### 9. Not independently audited
No third-party security review has been performed.

---

## Supported versions

| Version | Supported |
|---|---|
| 0.5.x | ✅ |
| < 0.5 | ❌ |

Pre-1.0 software. Treat it as such.

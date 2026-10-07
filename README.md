# Pluto Advance 0.5

**Your Intelligent Digital Operator** — a permission-controlled autonomous agent for Windows 10/11.

Pluto understands a request, plans it, asks before anything consequential, executes it, **verifies the result**, and reports what actually happened — including what it could not do.

---

## Status: honest summary

This is a working codebase with a real test suite, not a demo. What is proven and what is not:

| Area | Status | Evidence |
|---|---|---|
| Core engine, permissions, sandbox | ✅ **Tested** | 530+ automated tests, all executed |
| File & spreadsheet tools | ✅ **Tested** | Real files, real Excel/CSV, verified output |
| Browser automation | ✅ **Tested** | Real headless Chromium, not mocks |
| Desktop GUI | ✅ **Tested** | Real Qt widgets on the offscreen platform |
| Claude API integration | ⚠️ **Mocked only** | Needs a real key — see [docs/STATUS.md](docs/STATUS.md) |
| Windows desktop automation | ❌ **NOT TESTED** | Written, but needs a real Windows desktop |
| Windows installer (`.exe`) | ❌ **NOT BUILT** | Needs a Windows build host — see below |

The full, itemised status is in **[docs/STATUS.md](docs/STATUS.md)**. Nothing in this README claims a capability the test suite does not demonstrate.

---

## What it does

- **Plans before acting.** A request becomes a validated, dependency-ordered plan you can inspect.
- **Asks before anything consequential.** Sending, publishing, buying, submitting, deleting, overwriting, installing and changing system settings *always* require your explicit confirmation — in every autonomy mode, however the request is phrased.
- **Verifies instead of assuming.** A step is only "done" when Pluto has evidence: the file read back and compared, SHA-256 digests matched, row counts re-counted. A step that ran without proof is reported as *partial*, not complete.
- **Speaks your language.** English, Hindi and Hinglish, matching however you write.
- **Stops when you say stop.** A global Emergency Stop is reachable from every screen.

### The four autonomy modes

| Mode | What Pluto may do |
|---|---|
| **Observe** | Look and propose. Changes nothing. |
| **Assisted** | Asks before every meaningful action. *(default)* |
| **Workflow** | Runs approved workflows, pausing at checkpoints. |
| **Supervised** | Completes low and medium-risk multi-step work on its own. |

High-impact actions require confirmation in **all four**. That is not configurable.

---

## Requirements

- Windows 10 or 11 (the core engine also runs on Linux and macOS; desktop automation does not)
- Python 3.11–3.13
- A Claude API key from [console.anthropic.com](https://console.anthropic.com/)

## Install from source

```bash
git clone <your-repo-url>
cd pluto-advance

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS

pip install -e ".[gui,browser,windows,dev]"
playwright install chromium     # only if you want browser automation
```

Verify the install without opening a window:

```bash
pluto --check
```

Expected output on a healthy install:

```
  [PASS] Database: schema v2 at ...\PlutoAdvance\pluto.db
  [PASS] Tools registered: 23 of 23 enabled
  [PASS] Credential storage: WinVaultKeyring
  [INFO] API key: not set — add one in Settings on first run
Core application starts correctly.
```

Then start it:

```bash
pluto
```

## Configure the API key

Open **Settings → API** and paste your key. It is stored in the **Windows Credential Manager** via `keyring` — never in a file, never in the database, never in the settings model.

Pluto will never ask you to put a key into a chat message, a source file, or a repository.

For development, `ANTHROPIC_API_KEY` in the environment or a local `.env` also works. Copy `.env.example` to `.env` to start. **`.env` is gitignored and must stay that way.**

## Grant permissions

Nothing is granted by default. In **Permissions**:

- **Folders** — Pluto refuses every path outside these, including paths reached through `..` or symlinks.
- **Websites** — the browser opens only these domains. Subdomains are included; look-alikes such as `evil-example.com` are not.
- **Tools** — turn any individual tool off entirely.

---

## Architecture

```
src/pluto/
├── core/          Config, models, state machines, exceptions, app wiring
├── security/      PathGuard sandbox · secret redaction · permission engine
│                  · untrusted-content handling
├── data/          SQLite schema, migrations, repositories
├── ai/            Claude client · planner · prompts
├── agent/         Task orchestrator
├── tools/         Registry · file tools · spreadsheet tools
├── automation/    Playwright browser · Windows UI Automation
└── ui/            PySide6 interface (7 views, theme, widgets)
```

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the security model is in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

### The one rule worth knowing

Every tool call passes through `PermissionEngine.check()`. There is no second path. A tool that under-declares its own risk, or a plan that claims deleting a file is harmless, does not get further — the engine checks the tool's real declared risk and the always-confirm list independently of anything the model said.

This is what makes prompt injection containable rather than merely detectable. Detection reports; **containment is the guarantee**, and the test suite proves it holds even assuming detection fails completely.

---

## Testing

```bash
pytest                       # the whole suite
pytest -m "not slow"         # quick pass
pytest --cov=src/pluto       # with coverage
```

Markers: `integration` (needs real services), `e2e` (needs a real Windows desktop), `windows`, `gui`, `slow`.

Tests that need a real Claude key or a real Windows desktop are **skipped by default and reported as skipped** — they are never counted as passes.

---

## Building the Windows installer

The installer **must be built on Windows**. See [docs/BUILD.md](docs/BUILD.md).

```powershell
pip install -e ".[gui,browser,windows,build]"
pyinstaller packaging/windows/pluto.spec --clean --noconfirm
iscc packaging\windows\installer.iss
```

Output: `packaging/windows/Output/Pluto-Advance-0.5-Setup.exe`

A GitHub Actions workflow (`.github/workflows/windows-build.yml`) does this on a `windows-latest` runner, which is the supported way to produce a genuine installer.

**No installer has been built in this repository yet.** When one exists it will be attached to a GitHub Release. A file named like an installer that was not produced by a successful build is not an installer.

---

## Security

- API keys in the OS credential vault, never on disk in plaintext
- Secrets redacted before anything reaches the database or the logs
- Path traversal, symlink escape, and alternate-data-stream writes refused
- No arbitrary shell or code-execution tool exists in the codebase at all
- Full audit trail, including refusals, exportable and prunable

Known limitations are documented honestly in [SECURITY.md](SECURITY.md). Passing a test suite is not the same as being secure, and this project does not claim otherwise.

Report vulnerabilities per [SECURITY.md](SECURITY.md) — please do not open a public issue.

## Licence

MIT — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: new tools need a declared risk level, input validation, a real `verify()` and tests, and no change may weaken the permission engine.

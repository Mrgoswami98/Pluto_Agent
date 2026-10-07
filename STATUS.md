# Build and Test Status

**Version:** 0.5.0
**Build environment:** Ubuntu 24.04 (Linux), Python 3.13.15
**Target platform:** Windows 10/11

This document exists because the specification requires any requirement that
cannot be completed to be marked **BLOCKED** or **NOT TESTED** with the exact
next step. Nothing here is aspirational.

---

## Summary

| | Count |
|---|---|
| ✅ Verified by executed tests | 530+ tests across 11 modules |
| ⚠️ Implemented, tested against mocks | Claude API integration |
| ❌ NOT TESTED — needs Windows | Desktop automation |
| ❌ NOT BUILT — needs Windows | Installer executable |

**The single blocking fact:** this was built in a Linux container. Windows
desktop automation and the Windows installer cannot be produced or verified
here. Everything else is genuinely tested, including browser automation against
a real Chromium and the GUI against a real Qt application.

---

## ✅ Verified — tests written and executed

Run `pytest` to reproduce any of these.

### Security foundations
| Capability | Evidence |
|---|---|
| Path sandbox | 53 tests: traversal, symlink escape, sibling-prefix, NUL bytes, ADS, executable writes, protected locations, default-deny |
| Secret redaction | 44 tests: 7 key formats, JWTs, bearer headers, URL credentials, Luhn-checked cards; verified absent from DB *and* logs |
| Credential storage | OS vault with env and 0600-file fallbacks; file permissions asserted |
| Permission engine | 79 tests: all 4 autonomy modes × all 13 always-confirm actions |
| Approval scoping | Cannot be replayed for a different action or a higher risk; expiry revokes |
| Emergency Stop | Overrides valid approvals; observable by running workers |
| Prompt injection | 39 tests including containment proven *independently of detection* |

### Data layer
| Capability | Evidence |
|---|---|
| Versioned migrations | Applied transactionally; a newer DB is refused, not corrupted |
| Foreign keys | Enforced — an orphan approval is rejected |
| Transaction rollback | Verified on disk |
| State machines | Illegal task/step transitions rejected |
| Redaction before write | Asserted against raw SQL reads |
| Duplicate-run protection | Unique partial index on `idempotency_key` |

### Tools
| Capability | Evidence |
|---|---|
| 9 file tools | Real files; writes read back and compared, copies digest-matched, moves confirmed both sides |
| 4 spreadsheet tools | Real `.xlsx`/`.csv`; grouped aggregates checked against known values |
| 5 browser tools | **Real headless Chromium**, not mocks |
| Verification gate | A successful-but-unverified step leaves the task PARTIAL |

### Browser automation — genuinely tested
| Capability | Evidence |
|---|---|
| Domain allow-list | `evil-example.com` refused when `example.com` approved |
| Scheme rejection | `javascript:`, `data:`, `file:` rejected at validation |
| Credential refusal | Password fields refused; test asserts nothing was typed |
| No value leakage | Form snapshot asserted not to contain a filled value |
| Injection in pages | Flagged and wrapped, not followed |
| Submit gating | Always-confirm even in Supervised mode |

### Agent
| Capability | Evidence |
|---|---|
| Planner risk correction | Plan claiming a delete is `read_only` corrected to `high` |
| Dependency ordering | Execution order asserted |
| Bounded retries | Exact attempt counts asserted |
| High-risk never retried | `calls == 1` after failure |
| Cancellation | Mid-run cancel verified |
| Budgets | Step and time limits enforced |

### Interface
| Capability | Evidence |
|---|---|
| All 7 views | Built and navigated on real Qt (offscreen) |
| Progress honesty | Unverified step asserted *not* to count as progress |
| Emergency Stop reachable | From every view |
| No secrets in diagnostics | Asserted |
| Approval card redaction | Asserted |

### Application
Verified by running `pluto --check`:
```
[PASS] Database: schema v2
[PASS] Tools registered: 18 of 23 enabled
[PASS] Credential storage: environment-only
[INFO] API key: not set
[INFO] Windows automation: unavailable on linux (expected off Windows)
Core application starts correctly.
```

---

## ⚠️ Implemented, tested against mocks only

### Claude API integration
**Status:** All code paths exercised with a mocked SDK — retry/backoff,
rate-limit handling, auth failure (asserted not retried), response
normalisation, tool-call parsing, cancellation.

**NOT verified:** behaviour against the live API — real latency, real streaming,
real tool-use round trips, real token accounting, real rate-limit headers.

**Why:** no Claude API key is available in this environment, and the spec
forbids asking you to paste one into source or a repository.

**Exact next step:**
```bash
# On any machine, with your own key:
export ANTHROPIC_API_KEY="sk-ant-..."     # or set it in Settings → API
pluto --check                              # should report API key configured
pytest -m integration                      # opt-in live tests
```
Then in the GUI: open Settings → API → **Test connection**. A green result
confirms the live path.

---

## ❌ NOT TESTED — requires a real Windows desktop

### Windows desktop automation
**Status:** Fully implemented in `src/pluto/automation/windows.py` against
pywinauto and UI Automation. The **policy layer is tested** (protected windows,
protected processes, application allow-list, credential-field refusal) because
it is platform-independent, and the **refusal path off Windows is tested**.

**NOT verified:** that clicking a real button in a real Windows application
works. `pywinauto` and `comtypes` do not exist on Linux and cannot be
meaningfully exercised here.

**Exact next step:**
```powershell
# On Windows 10 or 11:
pip install -e ".[gui,browser,windows,dev]"
pytest -m windows -v          # the Windows-marked tests
pytest tests/e2e -v           # end-to-end desktop tests
```
Start with Notepad as the approved application; it is the least risky target.
Confirm that `windows.list_windows` returns real windows and that
`windows.click` operates a real control before trusting it with anything else.

---

## ❌ NOT BUILT — requires a Windows build host

### `Pluto-Advance-0.5-Setup.exe`
**Status:** **This installer does not exist.** No file by that name has been
produced, and none has been faked.

All build inputs are complete and committed:
- `packaging/windows/pluto.spec` — PyInstaller one-folder spec with the hidden
  imports that static analysis misses
- `packaging/windows/version_info.txt` — Windows version resource
- `packaging/windows/installer.iss` — Inno Setup script, per-user install,
  user data in `%LOCALAPPDATA%`, uninstall that offers to remove data
- `packaging/windows/before-install.txt` — pre-install disclosure
- `assets/pluto.ico` — multi-resolution icon (16→256px), generated and verified
- `.github/workflows/windows-build.yml` — CI that builds it on `windows-latest`

**Why not built here:** PyInstaller produces an executable for the platform it
runs on. On Linux it produces an ELF binary, not a Windows `.exe`. Inno Setup
is a Windows-only compiler. Cross-compiling is not supported, and renaming a
Linux binary to `.exe` would be a lie.

**Exact next step — option A (recommended, no Windows machine needed):**
```bash
git tag v0.5.0 && git push origin v0.5.0
```
The `windows-build` workflow runs on a GitHub-hosted `windows-latest` runner:
it runs the tests, runs `pluto --check`, builds the executable, **smoke-tests
the frozen `.exe` itself**, builds the installer, publishes the SHA-256, and
creates a **draft** release. Nothing is published without your action.

**Exact next step — option B (on your own Windows machine):**
```powershell
pip install -e ".[gui,browser,windows,build]"
pytest                                           # must pass first
pyinstaller packaging/windows/pluto.spec --clean --noconfirm
.\packaging\windows\dist\PlutoAdvance\PlutoAdvance.exe --check
choco install innosetup -y
iscc packaging\windows\installer.iss
# → packaging\windows\Output\Pluto-Advance-0.5-Setup.exe
```

### Installer behaviour (install, settings persistence, uninstall)
**Status: NOT TESTED**, because no installer exists to test.

**Exact next step** once an installer is built — verify on a clean Windows VM:
1. Install; confirm shortcuts appear
2. Launch; confirm first-run prompts for the API key
3. Add the key; close and reopen; confirm it persisted (Credential Manager)
4. Grant a folder; run a task; confirm `%LOCALAPPDATA%\PlutoAdvance\pluto.db`
   and `logs\pluto.jsonl` are written there, **not** into the install directory
5. Uninstall; confirm the program is removed and the data prompt appears
6. Confirm `%LOCALAPPDATA%\PlutoAdvance` is retained when you answer No

---

## ❌ NOT DONE — requires your authorisation

### GitHub repository and release
**Status:** The repository is prepared locally with full commit history. Nothing
has been pushed.

**Why:** the spec says not to push, publish a release, or change visibility
without explicit authorisation. The `GH_TOKEN` in this environment is also
invalid, so a push would fail regardless.

**Exact next step:**
```bash
gh auth login                                    # or set a valid GH_TOKEN
gh repo create pluto-advance --private --source=. --remote=origin
git push -u origin main
```
Keep it **private** until you have reviewed the code yourself. Replace `OWNER`
in `pyproject.toml` and `CHANGELOG.md` with your GitHub username.

### Code signing
**Status: NOT DONE.** No certificate is available.

Without one, Windows SmartScreen warns on first run and some antivirus products
flag an unsigned PyInstaller bundle. Reputation builds over time, slowly.

**Exact next step:** obtain an OV or EV code-signing certificate, then add a
signing step to the workflow after the PyInstaller build and before Inno Setup.

---

## Definition of done — spec §18, item by item

| Requirement | Status |
|---|---|
| Application starts on the target environment | ✅ on Linux; ❌ **NOT TESTED** on Windows |
| Chat uses the configured Claude API | ⚠️ code complete, mocked only |
| Task planned, approved, executed, verified | ✅ end-to-end test |
| File and spreadsheet tools work with test data | ✅ |
| Browser automation works in a test workflow | ✅ real Chromium |
| Windows automation has real tests on Windows | ❌ **NOT TESTED** |
| Permissions and emergency cancellation enforced | ✅ |
| Errors and partial results visible | ✅ |
| Tests actually run, results documented | ✅ 530+, this document |
| Secrets excluded from the repository | ✅ enforced by a test that scans git |
| Installer built and tested on Windows | ❌ **NOT BUILT** |
| Installation and API instructions complete | ✅ README + docs/BUILD.md |
| GitHub release preparation truthful | ✅ this document |

**Honest overall assessment:** the engine, the security model and the two
automation surfaces that *can* be verified here are genuinely built and
genuinely tested. The Windows-specific deliverables are complete as code and
build configuration but unproven as artefacts. Treat the Windows automation as
unproven until you have run it on a real desktop.

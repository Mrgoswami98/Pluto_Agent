# Building Pluto Advance

## Requirements

| Target | Needs |
|---|---|
| Run from source | Python 3.11–3.13, any OS (desktop automation is Windows-only) |
| Windows executable | **Windows**, PyInstaller |
| Windows installer | **Windows**, Inno Setup 6 |

PyInstaller freezes for the platform it runs on. There is no supported
cross-compilation: building on Linux yields an ELF binary, not a `.exe`.
This is why the installer must be built on Windows or on a Windows CI runner.

---

## Option A — GitHub Actions (recommended)

No Windows machine needed. The workflow runs the tests, verifies the
application starts, builds the executable, smoke-tests the **frozen** `.exe`,
builds the installer and publishes a SHA-256.

```bash
git tag v0.5.0
git push origin v0.5.0
```

Or trigger it manually from the Actions tab (`Windows build` →
`Run workflow`).

The result is a **draft** release with the installer attached. Review it, then
publish when you are ready. CI never publishes on its own.

---

## Option B — build locally on Windows

### 1. Set up

```powershell
git clone <repo>
cd pluto-advance
python -m venv venv
venv\Scripts\activate
pip install -e ".[gui,browser,windows,build,dev]"
playwright install chromium
```

### 2. Test before building

Never package a build whose tests did not pass.

```powershell
pytest -v
pluto --check
```

### 3. Build the executable

```powershell
pyinstaller packaging/windows/pluto.spec --clean --noconfirm
```

Output: `packaging\windows\dist\PlutoAdvance\PlutoAdvance.exe`

### 4. Smoke-test the frozen build

This step matters. A PyInstaller bundle can be missing a hidden import and
still look fine until a user runs it.

```powershell
.\packaging\windows\dist\PlutoAdvance\PlutoAdvance.exe --check
```

Expect exit code 0 and a passing database and tools check. If it fails with
`ModuleNotFoundError`, add the module to `hidden_imports` in
`packaging/windows/pluto.spec` and rebuild.

### 5. Build the installer

```powershell
choco install innosetup -y        # or download from jrsoftware.org
iscc packaging\windows\installer.iss
```

Output: `packaging\windows\Output\Pluto-Advance-0.5-Setup.exe`

### 6. Verify the installer on a clean machine

Use a VM or a fresh user account — not your development machine, where
dependencies are already present.

- [ ] Installs without administrator rights (per-user install)
- [ ] Shortcuts created as selected
- [ ] First run prompts for the API key
- [ ] Key persists across a restart (stored in Credential Manager)
- [ ] `%LOCALAPPDATA%\PlutoAdvance\pluto.db` is created
- [ ] Logs appear in `%LOCALAPPDATA%\PlutoAdvance\logs\`
- [ ] **Nothing is written into the installation directory**
- [ ] Uninstall removes the program
- [ ] Uninstall asks about user data, and keeps it when you answer No

---

## Code signing

Builds are unsigned. Windows SmartScreen will warn on first run, and some
antivirus products are suspicious of unsigned PyInstaller bundles.

With a certificate, sign after the PyInstaller step and before Inno Setup:

```powershell
signtool sign /f cert.pfx /p $env:CERT_PASSWORD /tr http://timestamp.digicert.com `
  /td sha256 /fd sha256 packaging\windows\dist\PlutoAdvance\PlutoAdvance.exe

iscc packaging\windows\installer.iss

signtool sign /f cert.pfx /p $env:CERT_PASSWORD /tr http://timestamp.digicert.com `
  /td sha256 /fd sha256 packaging\windows\Output\Pluto-Advance-0.5-Setup.exe
```

Keep the certificate out of the repository. Use GitHub encrypted secrets in CI.

---

## Troubleshooting

**`ModuleNotFoundError` from the frozen build**
Add the module to `hidden_imports` in `pluto.spec`. Lazily-imported and
entry-point-resolved modules (`keyring` backends, `openpyxl` writers) are the
usual culprits — several are already listed there.

**Antivirus flags the build**
Expected for unsigned PyInstaller output. UPX is already disabled in the spec
because it makes this worse. Signing is the real fix.

**Installer is very large**
Normal: PySide6 and pandas are big. Excluding `tkinter`, `matplotlib` and
`scipy` in the spec already trims it. Chromium is *not* bundled — Playwright
downloads it on demand.

**Qt fails to start in CI**
Set `QT_QPA_PLATFORM=offscreen`. The workflows already do.

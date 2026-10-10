# Install Sentinel Local: Windows, Linux, and macOS

Choose a native desktop beta executable for the simplest start, or a reviewed source checkout for development. Core monitoring needs no AI account. Windows/Linux x64 beta packages are available from the [v0.5.1 beta release](https://github.com/dibyapp/sentinel-local/releases/tag/v0.5.1-beta.1). macOS and ARM64 packages remain pending native validation. Development binaries are unsigned; signing remains a consumer-release gate.

## Windows x64 executable

1. Download `sentinel-local-0.5.1-windows-x64.exe` and its `.sha256` file from that release, keeping them in the same folder.
2. In that folder, verify the file's SHA-256:

```powershell
$expectedDigest = (Get-Content -LiteralPath 'sentinel-local-0.5.1-windows-x64.exe.sha256').Split()[0]
$actualDigest = (Get-FileHash -LiteralPath 'sentinel-local-0.5.1-windows-x64.exe' -Algorithm SHA256).Hash
if ($actualDigest -ne $expectedDigest) { throw 'Checksum mismatch: do not run this file.' }
```

3. Open the verified executable. It starts the private dashboard; no antivirus scan starts automatically. Python is bundled. Defender must already be available for Windows scanning.

A checksum verifies agreement with a downloaded reference; it does not authenticate the publisher or replace code signing. Windows may warn about this unsigned beta. Do not add antivirus exclusions, disable protection, or bypass security warnings. Use a reviewed source setup or wait for signed distributions instead.

## Linux x64 executable

On a compatible glibc-based x64 distribution, download the Linux artifact and checksum, then run in their folder:

```sh
sha256sum --check sentinel-local-0.5.1-linux-x64.sha256 &&
chmod u+x sentinel-local-0.5.1-linux-x64 &&
./sentinel-local-0.5.1-linux-x64
```

Only run the final command after checksum verification passes. The build uses an Ubuntu 24.04 baseline; older glibc and musl distributions may need source execution. WSL validation does not prove physical Linux Wi-Fi behavior. Optional OS utilities or permissions may be unavailable; the dashboard shows that limitation.

## Source: one explicit setup command

First install Python 3.11+ from [Python](https://www.python.org/downloads/) or your OS's official package manager, and Git from [Git](https://git-scm.com/downloads). Source installation is user-level; no administrator/root launch is required for basic monitoring.

```text
git clone https://github.com/dibyapp/sentinel-local.git
cd sentinel-local
python tools/setup.py --open
```

Linux/macOS use `python3` in the final command. Linux may require the distribution's Python venv package. The helper creates only the checkout's `.venv`, installs `psutil==7.2.2` from PyPI as a wheel, and verifies the selected Python/dependency versions. It does not install engines, AI tools/models, shell hooks, services, or startup tasks. Inspect the script before execution. Network failure leaves the dashboard unstarted.

Check without installing or opening anything:

```text
python tools/setup.py --check
```

Virtual environments are platform-specific. Use separate checkouts for Windows and Linux/macOS; the helper refuses an incomplete or foreign-platform `.venv`.

## Manual or offline setup

Windows:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py --open
```

Linux/macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py --open
```

For offline use, obtain the exact platform-appropriate pinned psutil wheel from a trusted package source beforehand. Supply a local wheel directory to pip with `--no-index --find-links /absolute/path/to/wheels`. No built-in dependency download occurs in offline mode. Native executables do not need pip.

## Portable Python launcher

The `.pyz` works on supported desktop Python environments with Python 3.11+ and psutil 7.2.2 already installed:

```text
python sentinel-local-0.5.1-portable.pyz --open
```

It is a source launcher, not a bundled universal binary. It cannot provide Android/iOS support or replace native permission validation.

## Next launch, AI, and scans

- Windows source: double-click `Open-Sentinel.cmd`.
- Linux/macOS source: `sh start-sentinel.sh`.
- Native executable: open it again; a verified matching instance is reused.
- AI: select an installed tool, test with fictional evidence, preview host indicators, and explicitly start review. [Provider setup](AI_REVIEW.md).
- Windows scan: select **Run quick scan** when work permits. Full scans are separately labeled Advanced.
- Linux/macOS scan: install ClamAV/current definitions through the official OS package manager and select an existing absolute folder with `--scan-root`. [Folder scan guide](guides/clamav-folder-scans.md).

No full-disk/home/Downloads scan, Wi-Fi discovery, file removal, or protection change occurs automatically. Runtime data remains private outside the checkout.

## Stop and update

A foreground source/native monitor stops with Ctrl+C in its terminal. Windows source users can use `Stop-Sentinel.ps1`; inspect its scope before running it. For a hidden native process, close the Sentinel process using the OS process manager. Closing the browser alone does not stop monitoring. No system-wide service or automatic updater is installed by these flows.

For source updates, stop the source instance you intend to update, review the new commit, run `git pull --ff-only`, rerun setup, and relaunch. For native updates, verify a new artifact before choosing to replace your copy. Do not replace an unrelated running monitor automatically. Changed profiles/interval/scan roots require a restart or a separate private `--data-dir` and explicit port.

If the default loopback port is occupied, Sentinel chooses an available one. Always open through its launcher or `--open` for the authenticated link. Never publish that link, runtime files, real screenshots, or local state as support attachments.

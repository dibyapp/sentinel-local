# Reviewed source and beta release preparation

The source tree, source archive, and native build tools are prepared for review. Source/beta publication requires explicit maintainer authorization. Nothing here pushes Git history, creates a remote repository, deploys a site, enables cloud monitoring, or publishes a release automatically.

## Privacy gate first

Keep all runtime reports, model state, network inventory, logs, tokens, real screenshots, and private build logs out of the source tree and every artifact. Legacy ignored state can remain on the owner's machine; it must never enter a release. Use an exact source allowlist rather than copying the whole project directory.

```text
python tools/release_guard.py
python tools/prepare_source.py
```

The source ZIP contains only allowlisted public files, deterministic ZIP metadata, and no `.git` history or configuration. The accompanying checksum covers the exact ZIP. If a gate fails, inspect its sanitized reason categories locally and fix the source before proceeding. Do not share failed artifacts or raw logs.

For local testing between Windows and WSL, an optional rejection-only private seed file can be written under `.local/` and supplied to either build. It contains sensitive values, must remain ignored, and is not a support attachment. Build workflows on clean CI runners never receive that owner's file or machine state.

## Build each target natively

```text
python -m pip install -r requirements-build.txt
python tools/build.py
```

Builds target the current OS/architecture; they do not cross-compile or fake unsupported artifacts. The builder inspects the executable before copying it to `dist/`, executes only its synthetic self-test, and writes a checksum plus a summary validation record. No existing monitor is restarted or replaced. No files under Downloads are scanned, moved, or deleted by packaging.

The six-target manual workflow prepares Windows/Linux/macOS x64 and ARM64 artifacts. It has read-only repository permissions and no release publishing step. Starting it sends allowlisted source to GitHub and uploads clean build artifacts there; it does not automatically publish a release.

## Gates before a public release

1. Review the exact staged diff and exact source/archive membership for private information. Do not use `git add .`; stage only the reviewed manifest entries. Review Git author identity before creating public commits. The source ZIP intentionally omits existing history.
2. Complete source tests and synthetic executable smoke checks on all native targets. Complete physical Wi-Fi/firewall/permission tests where claimed. Keep untested targets marked experimental.
3. Verify scanner detections, skipped-content reporting, definition freshness, and scan cancellation in an isolated lab. Functional tests do not establish antivirus efficacy.
4. Build from clean CI, scan final artifacts, include dependency notices, and provide SHA-256 checksums. Keep signing keys exclusively in a private signing system.
5. Sign Windows distributions and notarize macOS packages before recommending ordinary consumer installation. Do not instruct users to disable security barriers or endpoint protection for an unsigned build.
6. Prepare a release title, changelog, support matrix, known limits, and private vulnerability-reporting channel. Publish only after explicit owner authorization. A future public site also needs its own explicit deployment approval.

Native development executables open the dashboard automatically when launched without arguments; CLI options remain available. `tools/build_portable.py` also produces an allowlisted `.pyz` launcher requiring Python 3.11+ and psutil 7.2.2. Its exact members, bootstrap, privacy scan, checksum, and synthetic smoke are checked before copying. It is not a standalone universal executable. MSI/DMG/AppImage packages, signed updates, and uninstallable user services remain planned improvements. There is no automatic updater or deployment agent.

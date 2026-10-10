# Contributing to Sentinel Local

Useful contributions include clearer alerts, fewer false positives, OS-native read-only collectors, privacy regression tests, accessibility fixes, signed packaging, and reproducible validation on additional desktop platforms.

## Develop

Use Python 3.11 or newer. Create a virtual environment, install `requirements.txt`, and run:

```text
python -m unittest discover -s tests -v
python app.py --self-test
python tools/release_guard.py
```

Never commit your state directory, reports, logs, network inventory, tokens, credentials, or real screenshots. All fixtures must be fictional. Summarize failures without including personal names, command lines, SSIDs, MACs, or file locations. Add new public files individually to `release-manifest.json`; the manifest is the contribution/release allowlist.

## Changes worth accepting

Describe a concrete user problem, the resulting behavior, test coverage, and limits. Preserve unavailable states rather than treating missing data as healthy. Scanner failures, canceled scans, permission gaps, and skipped content must stay visible. Behavioral model findings must be explainable and must never automatically remove files, kill processes, or become a claim that a host is clean.

Use feature branches prefixed with `codex/` for agent-generated work. Keep changes focused. For OS adapters, test both successful and unavailable/permission-denied paths with synthetic fixtures. Native OS testing remains necessary even when mocked tests pass.

## Before opening a contribution

Run the privacy gate against the exact changed files and source archive. Share only allowlisted source and, if needed, the default redacted diagnostic summary. No genuine malware is required for routine tests. Use isolated laboratory systems for scanner efficacy work; never test destructive samples on contributors' everyday computers.

Subsequent releases, binary uploads, community announcements, and website deployment remain explicit maintainer decisions. The included workflows do not publish releases or deploy anything automatically.

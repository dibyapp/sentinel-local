# Roadmap driven by everyday security problems

| Priority | Pain point | Implemented now | Next evidence required |
| --- | --- | --- | --- |
| P0 | Private computer details accidentally enter a public contribution | External state directory, redacted summary, exact source allowlist, source/archive/compiled-code privacy scans | Maintainer review of exact staged files and final artifacts |
| P0 | Incomplete scans are mistaken for a clean computer | Errors and unknown states, Defender event matching, ClamAV exit-code handling | Independent lab validation of permission gaps, skipped content, cancellation, and engine limits |
| P0 | Cross-platform claims hide missing capabilities | OS adapters and explicit capability-driven actions | Native macOS, ARM64, and physical Linux Wi-Fi validation |
| P0 | Installation disrupts existing work | No auto-elevation, remediation, replacement, or deployment in build tools | Signed packages and intentional install/upgrade/uninstall workflows |
| P1 | Too many suspicious-but-legitimate alerts | Explainable scores, warmup, flagged-behavior holdout, separate historical/active signals | A labeled fictional/lab dataset, measured false-positive rates, contextual allow rules |
| P1 | Attackers blend into an untrusted initial baseline | Explicit learning pause, reversible baseline restart and limitation messaging | Poisoning-resistance evaluation and independent baseline-quality evidence |
| P1 | Users cannot tell which app created a connection | Executable/PID attribution in sampled TCP inventory | PID-reuse handling, signed identity/hash caching, short-lived event coverage |
| P1 | Findings become an overwhelming queue | Search/facets, expiring review and snooze, critical-state refusal, unchanged status totals | Accessibility review and measured task completion with users |
| P1 | Old observations look current | Per-source freshness, partial coverage, failed-sample gaps, exact-snapshot AI binding | Clock-change and long-running device validation |
| P1 | Monitoring creates unbounded local records | Count caps, configurable collection/advisory retention and readable summary export | Separate lifecycle controls for model profiles, scan jobs, AI journals and backup |
| P1 | Network discovery confuses a VPN, cache entry, or silent device | Verified Wi-Fi, source binding, /24 cap, explicit cache labels | Native neighbor refresh and multi-interface/mesh tests without active rescans |
| P1 | Unsigned binaries reduce user trust | Native build isolation, checksum, dependency notices, development labels | Windows signing, macOS notarization, reproducible clean CI |
| P2 | Monitoring ends when the terminal closes | Existing Windows user-startup helper and background agent | Opt-in user services for Linux/macOS and native tray notifications |
| P2 | Mobile users expect desktop prevention features | Scope is explicitly desktop | Separate mobile threat model and platform-compliant companion design |

No roadmap item implies a hidden cloud service, automatic blocking by the statistical model, credential collection, exploitation, or a new kernel antivirus driver. Changes need measured benefit and explicit limits before being marketed as protection.

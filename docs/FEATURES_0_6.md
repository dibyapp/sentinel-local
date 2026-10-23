# Sentinel Local 0.6: fifteen improvements for everyday monitoring

This release adds controls and explanations to the local desktop beta. These features do not introduce a new malware detection engine or establish detection efficacy. Existing native engines provide scanning and blocking. No action starts automatically when you change review preferences.

| # | Feature | User benefit and tested boundary |
| --- | --- | --- |
| 1 | Finding search and facets | Search titles/details and filter severity/source without changing status totals. Critical findings remain visible across review-state filters; explicit severity/search filters can narrow the display. |
| 2 | Reviewed advisory queue | Mark noncritical findings reviewed for seven days. The finding remains in status and reports. A changed finding fingerprint reopens it. |
| 3 | One-hour advisory snooze | Temporarily move a noncritical advisory out of the default open queue. Expiry reopens it; critical findings cannot be snoozed. |
| 4 | Sensor coverage and freshness | Separate process, TCP, listener, startup, firewall and threat-source availability. Show stale, unknown, fresh or unverified observations and partial firewall coverage; a failed collection never becomes a fresh result. |
| 5 | Collection health and action timing | View recent collection durations, source errors and collection failures, plus elapsed native-job time and status filters. These are observation/job timings, not scanner throughput or efficacy measurements. |
| 6 | Protection-change timeline | Record observed protection booleans and firewall transitions, including a change to unknown visibility. The first sample is a starting observation, not proof of continuous protection. |
| 7 | Searchable TCP inventory | Filter sampled connections by application/PID, address/port and public, loopback, local/reserved or unknown destination scope. Canonical address classification is performed by the server. |
| 8 | Connection-change comparison | Count opened, closed and persisting socket tuples between consecutive readable samples. Collection failures break comparison; PID reuse and short-lived traffic limit attribution. |
| 9 | Listening-service review | Inspect already-collected TCP listeners and focus on public/all-interface binds. This does not probe ports or prove reachability through a firewall. Missing listener access remains unavailable. |
| 10 | Explicit scan reminders | Choose daily, weekly or 30-day local reminders, or turn them off. They appear while the dashboard is open, survive restart, and never start scans or notifications in the background. |
| 11 | AI evidence freshness | Bind each AI result to its exact private snapshot fingerprint. Changed, failed, stale or unknown observations make an old result historical. The fingerprint is local metadata and never added to AI evidence. |
| 12 | Pause/resume baseline learning | Freeze baseline updates while continuing deterministic rules and existing model evaluation. Missing sensor data remains distinct from a manual pause. The preference survives restart. |
| 13 | Reversible baseline restart | Explicitly restart learning with one private pre-reset backup and restore it later. Neither reset nor restore declares a trusted/clean state. An active AI request blocks baseline changes. |
| 14 | Bounded local history retention | Choose 7, 30 or 90 days for Sentinel collection history and advisory alerts; existing count caps still apply. Scan jobs, AI journals, native engine records, model profiles and baseline backup are outside this retention setting. |
| 15 | Readable sharing-safe summary | Download Markdown with enum/boolean protection flags, allowlisted counts and freshness. It excludes identifiers, raw errors, addresses, paths and exact observation times, like the JSON summary. |

## Use the controls

Launch your chosen Sentinel version through its launcher. The Findings panel contains search and review-state controls. The Live activity panel contains connection filters. Scroll to **Monitoring workspace** for coverage, timelines, listening services, baseline controls, retention, reminders and the readable export.

All settings apply to that running instance's local state directory. Existing older monitors are not replaced or upgraded automatically. A browser window closing does not stop monitoring. No cloud request, native scan or Wi-Fi discovery starts from these controls.

Review and snooze keys bind to the full finding identity, source, severity and detail. This avoids silently carrying a decision onto changed evidence, but counters in changing advisory text can cause a new finding to reopen. Review decisions are workflow aids, not allowlisting or enforcement policy.

Retention is applied during successful collection or when explicitly changed; read views also prune expired workbench records in memory. Native engine history is managed separately by that engine. Older application state can already have been bounded by the pre-existing record caps, so selecting 90 days does not reconstruct lost history.

## Validation scope

Fictional tests exercise expiry, changed evidence, critical-state refusal, persistence, malformed settings, address scopes, collection failure gaps, protection transitions, missing listeners, retention scope, reminder behavior, baseline reset/restore, AI snapshot binding, export redaction, API tokens and Origin checks. Dashboard filter assertions run in Node. Packaged self-tests verify bundled assets, controls and redaction with fictional observations.

Native build and CI success do not certify malware detection, signing, every OS permission configuration, or physical Wi-Fi behavior. macOS/ARM64 and physical Linux Wi-Fi validation remain incomplete; the beta remains unsigned. No real PC report or private screenshot is test evidence for publication.

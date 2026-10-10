# Security and privacy

Sentinel Local is a security companion under development. Its statistical alerts are advisory; they are not malware verdicts. No independent antivirus efficacy certification is claimed.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/dibyapp/sentinel-local/security/advisories/new) or a private security advisory. Do not put vulnerabilities, tokens, raw snapshots, command lines, file paths, SSIDs, MAC/IP addresses, or personal screenshots in public issues. Until a private reporting channel exists, coordinate privately with the maintainer rather than creating a public exploit report. No personal contact information is embedded in this project.

Ordinary bug reports should contain the version, OS family, synthetic reproduction, and the sharing-safe summary only. The issue template explicitly asks contributors not to attach local runtime files.

## Boundaries

- Dashboard: IPv4 loopback only; random per-instance token; Host and Origin validation; restrictive CSP; no public listening mode, remote API, telemetry, analytics, or automatic external AI requests.
- AI review: local Ollama by default, fixed loopback endpoint with no proxies/redirects and verified downloaded model. Optional Codex/Claude cloud review requires explicit consent; the dashboard requires a fresh single-use provider-bound preview. Only anonymous indicators enter prompts. Tools/MCP/hooks are restricted by provider contracts; unknown CLI behavior fails closed. Vendor account policies and same-user access remain outside Sentinel's control. Gemini uses a separate restricted vendor profile and refuses existing enterprise system overrides. Custom inference wrappers are explicitly trusted by their owner; Sentinel cannot sandbox arbitrary wrappers. Compatible model servers also require consent because they may proxy cloud requests. Model output is validated and never executed. See `docs/AI_REVIEW.md`.
- Native commands: argument arrays and fixed action names; no shell interpolation, privilege escalation, policy disabling, automatic file deletion, or automatic process termination.
- POSIX scans: explicit existing folders, no symlink following or filesystem crossing. ClamAV and its definitions are optional external prerequisites; errors never count as clean scans. Exit code 1 is a detection result, not a scanner failure.
- State: stored in user-local application storage, separately from the source tree. POSIX state folders/files use 0700/0600. Same-user malware or privileged users can still access local data and the dashboard token; Sentinel is not an isolation boundary against them.
- Learning: the first baseline is not known-clean. Existing malicious activity can become baseline behavior. Frequent sampling can miss short-lived processes and sockets. Some OS permissions prevent complete visibility.
- Network discovery: only verified connected Wi-Fi, RFC1918 IPv4, at most the local /24, source-bound ICMP and nine gateway TCP connection checks. No exploit payloads, credentials, packet capture, or WAN exposure claims. Only scan networks you are authorized to assess.
- Supply chain: pinned build dependencies and pinned workflow action commits; clean allowlisted build staging; no runtime state included in source bundles or native packages. Source checks run on pushes and pull requests; native builds are manual. Both workflows have read-only repository permissions.

## Release privacy gate

`tools/release_guard.py` refuses tracked files outside `release-manifest.json`, known local identifiers, common credential signatures, unsafe archive paths, and unexpected archive entries. Native builds inspect decompressed bundled Python code, resources, libraries, and filenames before copying an executable to the output directory. The gate never prints matched secrets. A private denylist can be carried between local Windows/WSL checks, but is never part of a release.

The explicitly approved public repository URL is allowed even if its GitHub account name overlaps a local username. That exception applies only to the fixed public URL prefix; credentials, personal paths, and other occurrences remain subject to the gate.

Bundled CPython binaries have narrow exceptions for a known fictional standard-library example and the public hosted CPython compiler directory. Those exceptions never apply to source files or other personal paths. Known owner identifiers and credential patterns are still rejected in every vendor binary.

Automated scanning is a backstop, not an absolute secrecy guarantee. Inspect the exact source archive and staged diff before publishing. Never upload `.local/`, `data/`, machine reports, logs, baseline models, tokens, real screenshots, build logs, or the repository's existing Git configuration/history.

# Platform coverage and native validation

| Function | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Process inventory | CIM/PowerShell | psutil | psutil, permission dependent |
| Established TCP/listeners | Get-NetTCPConnection | psutil; unprivileged results may omit sockets | psutil; normally root required |
| Native antivirus status | Microsoft Defender | No universal native engine assumed | Gatekeeper/SIP checks; XProtect unverified |
| File scanning | Defender quick/full | Optional ClamAV selected folders | Optional ClamAV selected folders |
| Definition updates | Defender | Optional freshclam | Optional freshclam |
| Firewall status | Three Windows profiles | UFW/firewalld when readable; rules not audited | Native application firewall query |
| Wi-Fi metadata | netsh current interface | Cached NetworkManager advertisement, cipher unverified | Native query, permission/schema dependent |
| Routes/neighbors | Native PowerShell | iproute2 | route/arp |
| Startup inventory | Native startup commands | Current-user desktop autostart entries | Current-user LaunchAgents filenames |
| User autostart installer | Existing PowerShell helper | Not installed automatically | Not installed automatically |

Support means the adapter exists, not that every source is available or independently verified. macOS privacy restrictions can hide Wi-Fi metadata. Linux containers/WSL usually lack a physical Wi-Fi interface. Sentinel does not substitute a VPN or Ethernet route for verified Wi-Fi discovery.

Prepared native executable targets: Windows x64/ARM64, Linux x64/ARM64, macOS Intel/Apple Silicon. Each must be built and tested on a native runner. Linux output depends on the builder's libc baseline. A build made on Ubuntu 24.04 is not promised to run on every older Linux distribution or musl-based system. macOS compatibility depends on the builder's deployment target and installed native utilities.

Local validation covers Windows source/runtime reads and Linux source/runtime reads through Ubuntu WSL, plus x64 executable smoke checks. Physical Linux Wi-Fi, macOS hardware, and ARM64 runners remain release gates. No mobile, BSD, embedded, or universal binary support is claimed.

Before marking a platform release-ready, run source tests, the packaged synthetic self-test, read-only diagnostics, permission-denied tests, cancellation/error tests, and privacy scans. Test the GUI on that platform. Verify any optional scanner using an isolated laboratory fixture and current definitions; do not infer efficacy from a successful packaging smoke test.

# Windows Defender dashboard: monitor protection and run a quick scan

Sentinel Local combines Defender protection status, three Windows firewall profiles, recent scan state, sampled processes/TCP connections, and advisory findings in a local dashboard. Microsoft Defender handles malware detection, blocking, and quarantine.

1. [Install the Windows beta or source](../INSTALLATION.md).
2. Open the dashboard using the executable or source launcher. Read protection status and Monitor health first.
3. When other work permits, select **Run quick scan**. Sentinel uses a fixed Defender command and checks for a matching native completion event.
4. Read scan history. Completed, failed, running, and unverified outcomes have different meanings; an inactive historical detection does not establish an active infection.

Full scans are under Advanced and can take substantial time. Definition updates are separate actions. Permissions may prevent an operation; failure is retained. The product does not disable protection, add exclusions, silently elevate, or remove files in response to AI output.

A completed quick scan covers the engine's quick-scan scope rather than every file. “No current issues in available checks” is limited to observed data. [Microsoft scan command documentation](https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan), [Defender status documentation](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus).

If a connection alert is the concern, review the [connection activity explanation](connection-activity.md). High counts alone do not establish malware or data theft. AI can explain anonymous signals while the native engine remains responsible for malware scanning. [Local AI review](local-ai-security-review.md).

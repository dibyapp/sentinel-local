# Many network connections: advisory activity, false positives, and next steps

An application can legitimately open many internet connections. Browsers, AI tools, software updates, cloud synchronization, and development tooling can all do so. A count alone does not identify a malicious destination, transferred data, or an infection.

Sentinel has two different signals:

- **AI evidence count rule:** 20 or more simultaneous public TCP connections for an executable produce a review indicator. Multiple processes using the same executable are grouped. This fixed heuristic does not mean the activity differs from your own established usage.
- **Learned behavior model:** after enough successful samples, connection counts and newly observed destination-port combinations can trigger advisory deviations. Learning is not a known-clean baseline; sampling can miss activity.

The dashboard calls the AI signal **Connection activity needs review**. For example, a fictional browser with 24 TCP connections can trigger the count rule while the native antivirus reports no active threat. That combination is a request for context, not a verdict.

## What to review locally

1. Does the application match work you intentionally started? Use the process/application view.
2. Do the connections persist when that activity ends? Compare later samples; do not assume a disappearing alert proves safety.
3. Is an unsigned remote-access application something you intentionally installed? A signature helps investigate origin but is not a guarantee; an unsigned binary is not automatically malware.
4. Read native protection history if the engine reports a detection. Use the supported native scanner when you request a malware scan.

Sentinel does not automatically trust an app, block a destination, terminate processes, inspect packet contents, or remove files from this signal. Avoid pasting raw addresses, process paths, command lines, or tokens into a public issue. A fictional reproduction and sharing-safe summary are enough for ordinary reports.

Further reading: [Windows Defender dashboard](windows-defender-dashboard.md), [local AI review](local-ai-security-review.md), [privacy boundaries](../../SECURITY.md).

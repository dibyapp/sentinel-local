# Public screenshots: fictional provenance

The README images are original captures of Sentinel's dashboard served by `tools/demo.py`. They contain only fictional processes, a fictional Wi-Fi name, example network addresses, generated demo timestamps, mock provider selections, and mock structured reviews. No host collection, native scan, network discovery, credentials, or model inference is performed by the demo.

| Image | What it illustrates |
| --- | --- |
| `screenshots/overview.jpg` | Protection summary and three clear starting steps |
| `screenshots/ai-review.jpg` | Fictional connection test, advisory finding, and next step |
| `screenshots/wifi.jpg` | Fictional Wi-Fi metadata and example device entries |

Run with your selected Python environment:

```text
python tools/demo.py
```

Open the temporary authenticated loopback URL it prints. Test AI connection and Run AI review use mock results. Native action buttons are disabled by the server contract and return a clear demo error. The demo exits after 15 minutes or Ctrl+C. Its private temporary state is discarded.

Capture only the content area. Never capture the real monitor, desktop, browser profile/account chrome, environment paths, terminal, or token-bearing URL for public docs. Screenshots are JPEGs without personal metadata. Review every image visually and run the source/archive privacy gate before publication. The script's token is generated at runtime and is never committed or embedded in screenshot files.

The images illustrate workflows; they do not prove detection efficacy, performance, or native platform validation.

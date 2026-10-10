# ClamAV selected-folder scans on Linux and macOS

Sentinel supplies controls for an existing ClamAV installation. ClamAV supplies the scanning engine and definitions; Sentinel does not ship its own signature database or add real-time blocking on these platforms.

1. Install ClamAV and current definitions using your platform's official package manager and the [ClamAV documentation](https://docs.clamav.net/).
2. Select an existing absolute folder you intentionally want scanned.
3. Launch the source or supported executable with that root:

```text
python app.py --open --scan-root /opt/fictional-scan-folder
```

Replace the fictional example with your explicitly chosen folder. Repeat `--scan-root` for multiple selected folders. Scan controls appear only when the engine and roots are configured. No implicit home/whole-disk/Downloads root is supplied.

4. Select **Scan selected folders**, then read the detected-file count, scanned-file count, warnings, and coverage. ClamAV exit code 1 means detections; it is distinct from a scanner error. Skipped or unreadable content must not be treated as clean.

The adapter uses fixed arguments, no symlink following, and no filesystem crossing. Sentinel does not automatically delete detections, install definitions, elevate, or run AI commands. Selected-folder scanning is on demand; separately configured OS protections remain responsible for prevention.

macOS source support and native permissions remain experimental until actual native validation is recorded. [Installation](../INSTALLATION.md), [platform matrix](../PLATFORMS.md), [official ClamAV scanning guide](https://docs.clamav.net/manual/Usage/Scanning.html).

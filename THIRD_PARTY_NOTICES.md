# Third-party components and distribution notices

Sentinel Local's own source is MIT-licensed. Native binaries contain separately licensed components; the project's MIT license does not replace those licenses.

| Component | Purpose | License/reference |
| --- | --- | --- |
| CPython and standard library | Bundled Python runtime | [Python license](https://docs.python.org/3/license.html) |
| psutil | Portable host metadata | [BSD-3-Clause license](https://github.com/giampaolo/psutil/blob/master/LICENSE) |
| PyInstaller bootloader | Executable startup and extraction | [GPL with bootloader exception](https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt) |
| PyInstaller build hooks/tools | Build-time discovery | Licenses supplied in their distributions; not application telemetry |
| Runtime support libraries | Python vendor/distribution dependencies | Python's shipped notices and relevant library licenses |

The native builder includes the installed Python, psutil, and PyInstaller license texts inside a `licenses/` resource directory and writes a companion notices file. Python distributions may include notices for bundled support libraries such as OpenSSL, libffi, zlib, and others; retain them. For Linux distro-supplied runtime libraries, retain the distribution's copyright/license notices and review the final bundle before public distribution.

For Python 3.13 installations that omit a runtime license, the builder can use the checked-in [official CPython 3.13 license](https://github.com/python/cpython/blob/3.13/LICENSE), preserved in `licenses/Python-3.13-LICENSE.txt`. It refuses this fallback for other Python versions.

Defender is supplied by Windows and is not distributed by this project. ClamAV and its signature databases are external prerequisites and are not bundled. The dashboard ships no third-party CDN assets, fonts, analytics SDK, or cloud model.

Before publishing signed binaries, audit the final runtime-library inventory on each native builder and include any additional notices required by that inventory. This build-time inventory and license review is part of the release gate.

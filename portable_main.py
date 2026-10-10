"""Portable desktop launcher; Python and psutil remain external prerequisites."""
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import zipfile


def run():
    if sys.version_info < (3, 11):
        raise SystemExit('Sentinel needs Python 3.11 or newer.')
    if importlib.util.find_spec('psutil') is None:
        raise SystemExit('Install the dependency in your chosen Python environment: python -m pip install psutil==7.2.2')
    archive_path = Path(sys.argv[0]).resolve()
    with zipfile.ZipFile(archive_path) as archive, tempfile.TemporaryDirectory(prefix='sentinel-portable-') as temporary:
        names = archive.namelist()
        if len(names) != len(set(names)) or 'release-manifest.json' not in names:
            raise SystemExit('Portable archive has invalid members.')
        manifest = json.loads(archive.read('release-manifest.json'))['files']
        if set(names) != set(manifest) | {'__main__.py'}:
            raise SystemExit('Portable archive does not match its source allowlist.')
        root = Path(temporary).resolve()
        for info in archive.infolist():
            name = PurePosixPath(info.filename)
            if name.is_absolute() or '..' in name.parts or '\\' in info.filename or ':' in info.filename or info.file_size > 2_000_000:
                raise SystemExit('Portable archive has an unsafe member.')
            target = root.joinpath(*name.parts)
            if not target.resolve().is_relative_to(root):
                raise SystemExit('Portable archive member escaped its private staging directory.')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
        if sys.platform != 'win32': root.chmod(0o700)
        sys._MEIPASS = str(root)
        sys.path.insert(0, str(root))
        # Match the native launcher experience without claiming a bundled
        # Python runtime or bypassing any OS restrictions.
        if len(sys.argv) == 1: sys.argv.append('--open')
        from app import main
        main()


if __name__ == '__main__':
    run()

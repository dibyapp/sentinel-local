"""Create a reproducible Python launcher for supported desktop environments."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.release_guard import audit_source, local_seeds, manifest, scan_bytes
from version import __version__


def audit_portable(path, root, seeds):
    expected = set(manifest(root)) | {'__main__.py'}
    findings = []
    with zipfile.ZipFile(path) as archive:
        if len(archive.namelist()) != len(expected) or set(archive.namelist()) != expected:
            return [{'reason': 'unexpected-portable-members'}]
        for name in sorted(expected):
            contents = archive.read(name)
            if len(contents) > 2_000_000:
                findings.append({'file': name, 'reason': 'oversized-portable-member'})
            findings.extend(scan_bytes(contents, name, seeds))
        if archive.read('__main__.py') != (root / 'portable_main.py').read_bytes():
            findings.append({'reason': 'unexpected-portable-bootstrap'})
    return findings


def build(root, destination, seeds):
    if audit_source(root, seeds): raise ValueError('Source privacy gate failed; no portable artifact was produced.')
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f'sentinel-local-{__version__}-portable.pyz'
    if output.exists(): raise ValueError('Output exists; choose a new folder to preserve prior artifacts.')
    with tempfile.TemporaryDirectory(prefix='sentinel-portable-build-') as temporary:
        candidate = Path(temporary) / output.name
        with zipfile.ZipFile(candidate, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            entries = {name: (root / name).read_bytes() for name in manifest(root)}
            entries['__main__.py'] = (root / 'portable_main.py').read_bytes()
            for name, contents in sorted(entries.items()):
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3; info.external_attr = 0o100644 << 16
                archive.writestr(info, contents)
        if audit_portable(candidate, root, seeds): raise ValueError('Portable privacy gate failed; artifact was not copied.')
        result = subprocess.run([sys.executable, str(candidate), '--self-test'], capture_output=True, text=True, timeout=60,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode or not json.loads(result.stdout).get('passed'):
            raise ValueError('Portable synthetic self-test failed; artifact was not copied.')
        output.write_bytes(candidate.read_bytes())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(f'{digest}  {output.name}\n', encoding='utf-8')
    output.with_name(output.name + '.validation.json').write_text(json.dumps({'privacyGate': 'passed', 'syntheticSmoke': 'passed',
        'requires': 'Python 3.11+ and psutil 7.2.2 on a supported desktop OS', 'bundledPython': False, 'published': False}, indent=2), encoding='utf-8')
    return output


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output-dir', type=Path, default=ROOT / 'release' / 'portable')
    parser.add_argument('--seed-file', type=Path); args = parser.parse_args()
    seeds = local_seeds(ROOT)
    if args.seed_file: seeds += json.loads(args.seed_file.read_text(encoding='utf-8'))
    output = build(ROOT, args.output_dir.resolve(), seeds)
    print(json.dumps({'artifact': output.name, 'privacyGate': 'passed', 'smokeTest': 'passed', 'bundledPython': False, 'published': False}))


if __name__ == '__main__': main()

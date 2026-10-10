"""Build a deterministic allowlisted archive, with no runtime data or Git history."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.release_guard import audit_source, audit_archive, local_seeds, manifest
from version import __version__


def prepare(root, destination, seeds):
    findings = audit_source(root, seeds)
    if findings:
        raise ValueError('Privacy gate rejected source. Run release_guard.py to see sanitized finding categories.')
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f'sentinel-local-{__version__}-source.zip'
    if output.exists():
        raise ValueError('Output already exists; select a new destination to preserve previous artifacts.')
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in manifest(root):
            entry = zipfile.ZipInfo('sentinel-local/' + name, date_time=(2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = (0o100755 if name.endswith('.sh') else 0o100644) << 16
            archive.writestr(entry, (root / name).read_bytes())
    if audit_archive(output, seeds):
        raise ValueError('Privacy gate rejected the produced source archive. Do not share it.')
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    (destination / (output.name + '.sha256')).write_text(f'{checksum}  {output.name}\n', encoding='utf-8')
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'release' / 'source')
    parser.add_argument('--seed-file', type=Path)
    args = parser.parse_args()
    seeds = local_seeds(ROOT)
    if args.seed_file:
        seeds += json.loads(args.seed_file.read_text(encoding='utf-8'))
    output = prepare(ROOT, args.output_dir, seeds)
    print(json.dumps({'created': output.name, 'files': len(manifest(ROOT)), 'privacyGate': 'passed', 'published': False}))


if __name__ == '__main__':
    main()

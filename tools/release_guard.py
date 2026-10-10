"""Fail-closed source/artifact gate. Never prints matched private strings."""
import argparse
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_REPOSITORY = 'https://github.com/dibyapp/sentinel-local'
FORBIDDEN = {'data', '.local', '.git', '.venv', '__pycache__', 'build', 'dist', 'release', 'node_modules'}
FORBIDDEN_SUFFIXES = {'.lnk', '.log', '.pem', '.key', '.pfx', '.p12', '.sqlite', '.db'}
PATTERNS = [
    ('private-key', re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('credential', re.compile(rb'\b(?:sk-[A-Za-z0-9_-]{24,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,})\b')),
    ('credential-in-url', re.compile(rb'https?://[^\s/:]+:[^\s/@]+@')),
    ('personal-home-path', re.compile(rb'(?:[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s"\x27()\x00]{3,}|/home/[A-Za-z0-9_.-]{3,}/|/Users/[A-Za-z0-9_.-]{3,}/)', re.I)),
    ('literal-dashboard-token', re.compile(rb'#token=[A-Za-z0-9_-]{30,}')),
]


def manifest(root=ROOT):
    paths = json.loads((root / 'release-manifest.json').read_text(encoding='utf-8'))['files']
    if not isinstance(paths, list) or not paths or len(paths) != len(set(paths)):
        raise ValueError('Invalid release manifest')
    for value in paths:
        path = PurePosixPath(value)
        if path.is_absolute() or '..' in path.parts or any(p in FORBIDDEN or p.startswith('.env') for p in path.parts) or path.suffix in FORBIDDEN_SUFFIXES:
            raise ValueError('Manifest includes a forbidden path')
        actual = root / path
        if actual.is_symlink() or not actual.is_file():
            raise ValueError(f'Manifest entry is missing or is a symlink: {value}')
        if not actual.resolve().is_relative_to(root.resolve()):
            raise ValueError('Manifest path escaped source tree')
    return sorted(paths)


def local_seeds(root=ROOT):
    seeds = set()
    def add(value):
        if not isinstance(value, str) or len(value) < 5:
            return
        seeds.update((value, value.replace('\\', '/'), value.replace('/', '\\')))
    username = os.environ.get('USERNAME') or os.environ.get('USER')
    if username and username.lower() not in ('root', 'runner', 'ubuntu', 'public', 'user') and len(username) >= 5:
        add(username)
    if str(Path.home()) not in ('/root', '/home/runner', '/Users/runner'):
        add(str(Path.home()))
    for name in (socket.gethostname(), socket.getfqdn()):
        if name.lower() not in ('localhost', 'localhost.localdomain'):
            add(name)
    # Inspect only private runtime files locally. Their values are never copied
    # into release sources, logs, findings, or public artifacts.
    directories = [root / 'data', root / '.local' / 'host-validation']
    try:
        sys.path.insert(0, str(root))
        from privacy import state_directory
        directories.append(state_directory())
    finally:
        sys.path.pop(0)
    keys = {'SSID', 'ssid', 'LinkLayerAddress', 'mac', 'token'}
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in keys:
                    protocol_marker = key in ('LinkLayerAddress', 'mac') and isinstance(item, str) and item.replace('-', '').replace(':', '').lower() in ('000000000000', 'ffffffffffff')
                    if not protocol_marker:
                        add(item)
                        if key in ('LinkLayerAddress', 'mac') and isinstance(item, str):
                            add(item.replace('-', ':'))
                if key == 'wifiRaw' and isinstance(item, str):
                    for line in item.splitlines():
                        if line.strip().startswith('SSID') and ':' in line:
                            add(line.split(':', 1)[1].strip())
                if key in ('IPAddress', 'ip') and isinstance(item, str):
                    try:
                        address = ipaddress.ip_address(item)
                        if not address.is_loopback and not address.is_multicast and not address.is_unspecified and item != '255.255.255.255':
                            add(item)
                    except ValueError:
                        pass
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    for directory in directories:
        for filename in ('instance.json', 'initial-snapshot.json', 'latest-report.json', 'scan-report.json', 'network.json'):
            path = directory / filename
            if path.is_file():
                try:
                    walk(json.loads(path.read_text(encoding='utf-8-sig')))
                except (OSError, ValueError):
                    raise ValueError('A private seed source could not be read. Release gate refuses to continue.')
    return sorted(seeds)


def scan_bytes(payload, label, seeds, patterns=True, vendor_examples=False):
    findings = []
    lower = payload.lower()
    # The owner explicitly authorized this public repository address. Its
    # account name can overlap a local username. Mask only this fixed URL
    # prefix for identifier matching; credential/path checks still see every
    # original byte, and all other occurrences of local identifiers fail.
    for encoding in ('utf-8', 'utf-16-le'):
        lower = lower.replace(PUBLIC_REPOSITORY.encode(encoding),
                              b'approved-public-repository')
    for seed in seeds:
        for encoded in (seed.lower().encode('utf-8'), seed.lower().encode('utf-16-le')):
            if encoded in lower:
                findings.append({'file': label, 'reason': 'local-private-identifier'})
                break
    if patterns:
        for reason, pattern in PATTERNS:
            matches = list(pattern.finditer(payload))
            # CPython's frozen ntpath.splitroot docstring includes a fictional
            # home-path example. This exception is limited to the vendor
            # Python shared library. Known owner identifiers are still denied
            # above, even when they coincide with an example.
            if reason == 'personal-home-path' and vendor_examples:
                vendor_path = b'c:' + b'/users/' + b'barney'
                # Verified in Python.org's public universal2 installer,
                # distributed by actions/python-versions for setup-python.
                vendor_compiler = b'/Users/' + b'nad/build_macos_installer'
                matches = [m for m in matches
                           if m.group().replace(b'\\', b'/').lower() != vendor_path
                           and not (payload[m.start():].startswith(vendor_compiler)
                                    and payload[m.start()+len(vendor_compiler):m.start()+len(vendor_compiler)+1] in
                                    (b'', b'/', b'\x00', b' ', b'\n', b'\r', b"'"))]
            if matches:
                findings.append({'file': label, 'reason': reason})
    return findings


def audit_source(root=ROOT, seeds=()):
    findings = []
    allowed = manifest(root)
    for name in allowed:
        findings.extend(scan_bytes((root / name).read_bytes(), name, seeds))
    # When Git has an index, refuse accidental staging of anything outside
    # the allowlist, even if it is nominally ignored.
    import subprocess
    result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], capture_output=True)
    if result.returncode == 0:
        for name in result.stdout.decode('utf-8').split('\0'):
            if name and name not in allowed:
                findings.append({'file': name, 'reason': 'tracked-outside-release-allowlist'})
    return findings


def audit_archive(path, seeds=()):
    findings = []
    with zipfile.ZipFile(path) as archive:
        expected = set(json.loads(archive.read('sentinel-local/release-manifest.json'))['files'])
        for name in archive.namelist():
            part = PurePosixPath(name)
            if part.is_absolute() or '..' in part.parts or len(part.parts) < 2 or part.parts[0] != 'sentinel-local':
                findings.append({'file': name, 'reason': 'unsafe-archive-path'}); continue
            relative = '/'.join(part.parts[1:])
            if any(p in FORBIDDEN or p.startswith('.env') for p in part.parts[1:]) or part.suffix in FORBIDDEN_SUFFIXES:
                findings.append({'file': name, 'reason': 'forbidden-private-archive-member'})
            if relative not in expected:
                findings.append({'file': name, 'reason': 'archive-file-not-allowlisted'})
            findings.extend(scan_bytes(archive.read(name), name, seeds))
        actual = {'/'.join(PurePosixPath(n).parts[1:]) for n in archive.namelist()}
        if actual != expected:
            findings.append({'file': 'source-archive', 'reason': 'archive-manifest-mismatch'})
    return findings


def audit_executable(path, seeds=()):
    from PyInstaller.archive.readers import CArchiveReader
    findings = scan_bytes(path.read_bytes(), path.name, seeds)
    archive = CArchiveReader(str(path))
    for name, entry in archive.toc.items():
        findings.extend(scan_bytes(name.encode(), 'bundle-table', seeds))
        kind = entry[-1]
        if kind == 'z':
            embedded = archive.open_embedded_archive(name)
            for module in embedded.toc:
                # raw marshalled code preserves constants, strings and nested
                # co_filename paths after decompression; never execute code.
                payload = embedded.extract(module, raw=True)
                if payload is not None:
                    # Inspect decompressed bytes directly. Deserializing code
                    # from a different Python version can crash the auditor.
                    findings.extend(scan_bytes(payload, f'python:{module}', seeds))
        elif kind not in ('o', 'd'):
            payload = archive.extract(name)
            vendor_python = name.startswith('libpython') or name.startswith('python') and name.endswith('.dll')
            vendor_framework = name.startswith('Python.framework/Versions/') and PurePosixPath(name).name == 'Python'
            vendor_extension = re.fullmatch(r'python3\.\d+/lib-dynload/[A-Za-z0-9_]+\.cpython-\d+-darwin\.so', name) is not None
            findings.extend(scan_bytes(payload, f'bundle:{name}', seeds, vendor_examples=vendor_python or vendor_framework or vendor_extension))
            if name.endswith('.zip') and zipfile.is_zipfile(io.BytesIO(payload)):
                with zipfile.ZipFile(io.BytesIO(payload)) as library:
                    for member in library.namelist():
                        findings.extend(scan_bytes(library.read(member), f'library:{member}', seeds))
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--executable', type=Path)
    parser.add_argument('--seed-file', type=Path)
    parser.add_argument('--save-private-seeds', type=Path)
    args = parser.parse_args()
    seeds = local_seeds(args.root)
    if args.seed_file:
        seeds.extend(json.loads(args.seed_file.read_text(encoding='utf-8')))
    if args.save_private_seeds:
        args.save_private_seeds.parent.mkdir(parents=True, exist_ok=True)
        args.save_private_seeds.write_text(json.dumps(sorted(set(seeds))), encoding='utf-8')
        if os.name != 'nt':
            args.save_private_seeds.chmod(0o600)
    if args.archive:
        findings = audit_archive(args.archive, seeds)
    elif args.executable:
        findings = audit_executable(args.executable, seeds)
    else:
        findings = audit_source(args.root, seeds)
    result = {'passed': not findings, 'filesChecked': len(manifest(args.root)), 'findings': findings,
              'scope': 'Allowlist, known local identifiers, common credentials, archive members, and compiled Python paths. Manual release review is still required.'}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if not findings else 1)


if __name__ == '__main__':
    main()

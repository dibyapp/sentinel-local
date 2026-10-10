"""Native PyInstaller build from isolated, allowlisted source. Never publishes."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.release_guard import audit_source, audit_executable, local_seeds, manifest
from version import __version__


def python_runtime_license(staging, prefix=None, version=None):
    prefix = Path(sys.base_prefix if prefix is None else prefix)
    version = sys.version_info[:2] if version is None else version
    candidates = [prefix / 'LICENSE.txt', prefix / 'LICENSE',
                  Path('/usr/share/doc') / f'python{version[0]}.{version[1]}' / 'copyright']
    # setup-python's Linux runtime may omit LICENSE. Use an official,
    # version-specific fallback, without fetching license text during builds.
    if tuple(version) == (3, 13):
        candidates.append(staging / 'licenses' / 'Python-3.13-LICENSE.txt')
    return next((path for path in candidates if path.is_file()), None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    parser.add_argument('--seed-file', type=Path, help='Ignored local denylist carried between local Windows/WSL checks')
    args = parser.parse_args()
    seeds = local_seeds(ROOT)
    if args.seed_file:
        seeds += json.loads(args.seed_file.read_text(encoding='utf-8'))
    if audit_source(ROOT, seeds):
        raise SystemExit('Source privacy gate failed. No build produced.')
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = 'arm64' if machine in ('aarch64', 'arm64') else 'x64' if machine in ('amd64', 'x86_64') else machine
    if system not in ('windows', 'linux', 'darwin') or arch not in ('x64', 'arm64'):
        raise SystemExit('Native builds currently support Windows/Linux/macOS on x64 or arm64.')
    suffix = '.exe' if system == 'windows' else ''
    name = f'sentinel-local-{__version__}-{system}-{arch}'
    destination = args.output_dir.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / (name + suffix)
    if output.exists():
        raise SystemExit('Output already exists. Use a new output directory; previous artifacts are preserved.')
    hidden = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    with tempfile.TemporaryDirectory(prefix='sentinel-clean-build-') as temporary:
        staging = Path(temporary) / 'source'
        staging.mkdir()
        for relative in manifest(ROOT):
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        notices = staging / 'licenses'
        notices.mkdir(exist_ok=True)
        shutil.copyfile(staging / 'LICENSE', notices / 'Sentinel-MIT.txt')
        for package in ('psutil', 'PyInstaller'):
            distribution = importlib.metadata.distribution(package)
            candidates = [f for f in distribution.files or [] if f.name.upper() in ('LICENSE', 'LICENSE.TXT', 'COPYING.TXT', 'COPYING')]
            if not candidates:
                raise SystemExit('A required dependency license is missing; build stopped.')
            for index, entry in enumerate(candidates):
                shutil.copyfile(distribution.locate_file(entry), notices / f'{package}-{index}-license.txt')
        python_license = python_runtime_license(staging)
        if not python_license:
            raise SystemExit('Python runtime license was not found; build stopped before packaging.')
        shutil.copyfile(python_license, notices / 'Python-runtime-license.txt')
        # The build log stays private and is never copied into an artifact.
        command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--console', '--noupx', '--optimize', '2',
                   '--name', name, '--distpath', str(Path(temporary) / 'dist'), '--workpath', str(Path(temporary) / 'build'),
                   '--specpath', str(Path(temporary) / 'spec'), '--add-data', str(staging / 'static') + ':static',
                   '--add-data', str(staging / 'scripts') + ':scripts', '--add-data', str(staging / 'docs') + ':docs', '--add-data', str(notices) + ':licenses',
                   '--add-data', str(staging / 'THIRD_PARTY_NOTICES.md') + ':licenses',
                   '--hidden-import', 'psutil', '--hidden-import', 'selftest', 'app.py']
        if system != 'windows':
            command.append('--strip')
        else:
            command += ['--hide-console', 'hide-early']
        result = subprocess.run(command, cwd=staging, capture_output=True, text=True, errors='replace', creationflags=hidden)
        if result.returncode:
            log = ROOT / '.local' / 'build-error.log'
            log.parent.mkdir(exist_ok=True)
            log.write_text(result.stdout + result.stderr, encoding='utf-8')
            raise SystemExit('Native build failed; details are in ignored local build-error.log.')
        built = Path(temporary) / 'dist' / (name + suffix)
        findings = audit_executable(built, seeds)
        if findings:
            print(json.dumps({'privacyGate': 'failed', 'findings': findings}, indent=2))
            raise SystemExit('Compiled artifact was not copied into release output.')
        smoke = subprocess.run([str(built), '--self-test'], capture_output=True, text=True, timeout=60, creationflags=hidden)
        if smoke.returncode or not json.loads(smoke.stdout).get('passed'):
            raise SystemExit('Native executable smoke test failed. Artifact was not copied into release output.')
        shutil.copyfile(built, output)
        if os.name != 'nt':
            output.chmod(0o755)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    (destination / (output.name + '.NOTICES.md')).write_bytes((ROOT / 'THIRD_PARTY_NOTICES.md').read_bytes())
    (destination / (output.name + '.sha256')).write_text(f'{digest}  {output.name}\n', encoding='utf-8')
    (destination / (output.name + '.validation.json')).write_text(json.dumps({'version': __version__, 'platform': system, 'architecture': arch,
        'privacyGate': 'passed', 'syntheticSmoke': 'passed', 'liveHostValidation': 'not part of packaging', 'published': False}, indent=2), encoding='utf-8')
    print(json.dumps({'artifact': output.name, 'privacyGate': 'passed', 'smokeTest': 'passed', 'published': False}))


if __name__ == '__main__':
    main()

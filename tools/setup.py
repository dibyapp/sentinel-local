"""Explicit source setup: one local venv, pinned dependency, optional dashboard."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def environment_python(root):
    directory = root / '.venv'
    executable = directory / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if directory.is_symlink():
        raise ValueError('The project virtual environment must not be a symlink.')
    if directory.exists() and not executable.is_file():
        raise ValueError('This .venv is incomplete or belongs to another OS. Use a fresh source checkout for this platform.')
    return executable


def dependency_ready(executable):
    if not executable.is_file(): return False
    result = subprocess.run([str(executable), '-I', '-c', 'import sys,psutil; sys.exit(0 if sys.version_info >= (3,11) and psutil.__version__ == "7.2.2" else 1)'],
                            capture_output=True, timeout=20, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    return result.returncode == 0


def setup(root, check=False, open_dashboard=False):
    if sys.version_info < (3, 11): raise ValueError('Install Python 3.11 or newer from its official source first.')
    requirements = root / 'requirements.txt'
    if requirements.read_text(encoding='utf-8').strip() != 'psutil==7.2.2':
        raise ValueError('The approved dependency file changed; inspect it before using this setup helper.')
    executable = environment_python(root)
    ready = dependency_ready(executable)
    if check:
        return {'ready': ready, 'installed': False, 'dashboardStarted': False, 'nextStep': 'Open the launcher' if ready else 'Run python tools/setup.py --open to create the project environment'}
    if not executable.exists():
        print('1/3 Creating the project virtual environment.', flush=True)
        subprocess.run([sys.executable, '-I', '-m', 'venv', str(root / '.venv')], check=True)
    if not ready:
        print('2/3 Installing the pinned psutil dependency from PyPI into that environment.', flush=True)
        subprocess.run([str(executable), '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install', '--no-input',
                        '--only-binary=:all:', '--index-url', 'https://pypi.org/simple', '-r', str(requirements)], check=True)
    if not dependency_ready(executable): raise ValueError('Dependency verification failed; the dashboard was not started.')
    print('3/3 Setup verified. No scanner, AI model, startup service, or security-setting change was installed.', flush=True)
    if open_dashboard:
        arguments = [str(executable), str(root / 'app.py'), '--open']
        if os.name == 'nt':
            subprocess.Popen(arguments, cwd=root, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(arguments, cwd=root, check=True)
    return {'ready': True, 'installed': not ready, 'dashboardStarted': open_dashboard}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check setup without installing or starting anything')
    parser.add_argument('--open', action='store_true', help='Open the dashboard after explicit setup')
    args = parser.parse_args()
    if args.check and args.open: parser.error('--check cannot start a dashboard.')
    try:
        result = setup(ROOT, args.check, args.open)
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Setup could not complete. Check Python 3.11+, network access to PyPI, and the platform-specific installation guide. Raw machine details were not printed.', file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result))
    raise SystemExit(0 if result['ready'] else 1)


if __name__ == '__main__': main()

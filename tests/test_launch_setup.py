"""Fictional setup/demo and public documentation checks; no package install."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import setup
from tools import demo
from tools.check_public_docs import check


class SetupTests(unittest.TestCase):
    def root(self, directory):
        root = Path(directory); (root / 'requirements.txt').write_text('psutil==7.2.2\n'); return root

    def test_check_never_creates_installs_or_opens(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.root(directory)
            with patch.object(setup, 'dependency_ready', return_value=False), patch.object(setup.subprocess, 'run') as run:
                self.assertFalse(setup.setup(root, check=True)['ready']); run.assert_not_called()
            self.assertFalse((root / '.venv').exists())

    def test_unapproved_dependency_change_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.root(directory); (root / 'requirements.txt').write_text('fictional-unapproved-package')
            with patch.object(setup.subprocess, 'run') as run:
                with self.assertRaises(ValueError): setup.setup(root)
                run.assert_not_called()

    def test_foreign_environment_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.root(directory); (root / '.venv').mkdir()
            with self.assertRaises(ValueError): setup.environment_python(root)

    def test_failed_install_does_not_open_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.root(directory)
            with patch.object(setup, 'dependency_ready', return_value=False), patch.object(setup.subprocess, 'run', side_effect=[None, subprocess.CalledProcessError(1, ['fictional-pip'])]), patch.object(setup.subprocess, 'Popen') as launch:
                with self.assertRaises(subprocess.CalledProcessError): setup.setup(root, open_dashboard=True)
                launch.assert_not_called()

    def test_explicit_setup_targets_only_project_venv_and_pinned_wheel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.root(directory)
            with patch.object(setup, 'dependency_ready', side_effect=[False, True]), patch.object(setup.subprocess, 'run') as run:
                result = setup.setup(root)
            self.assertTrue(result['ready']); self.assertFalse(result['dashboardStarted'])
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn(str(root / '.venv'), commands[0])
            self.assertIn('--isolated', commands[1]); self.assertIn('--only-binary=:all:', commands[1])
            self.assertIn('https://pypi.org/simple', commands[1]); self.assertIn(str(root / 'requirements.txt'), commands[1])


class PublicDemoTests(unittest.TestCase):
    def test_demo_contains_only_fictional_observations_and_validated_mock(self):
        packet = {'schema':'sentinel-ai-evidence-v1','summary':{}, 'evidence':[{'id':'E003','kind':'process','indicators':{'unsigned_remote_access':True}}], 'coverage':{}}
        result = demo.run_demo_review('ollama', 'fictional:model', packet)
        self.assertFalse(result['cloudUsed']); self.assertFalse(result['nativeMalwareScanStarted'])
        self.assertEqual(result['result']['findings'][0]['reason_code'], 'unsigned_remote_access')
        snapshot = demo.snapshot(); self.assertIn('FICTIONAL DEMO', snapshot['wifiRaw'])
        self.assertTrue(all('Fictional' in p['ExecutablePath'] for p in snapshot['processes']))

    def test_public_documentation_links_and_images(self):
        self.assertEqual(check(), [])

    def test_public_image_gate_rejects_exif_and_missing_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'docs/screenshots').mkdir(parents=True)
            (root/'README.md').write_text('[missing](does-not-exist.md)')
            (root/'docs/screenshots/test.jpg').write_bytes(b'\xff\xd8\xff\xe1\x00\x08Exif\x00\x00\xff\xd9')
            (root/'release-manifest.json').write_text(json.dumps({'files':['README.md','docs/screenshots/test.jpg','release-manifest.json']}))
            findings=check(root); reasons={v['reason'] for v in findings}
            self.assertIn('unreviewed-image-metadata',reasons); self.assertIn('missing-or-unsafe-local-link',reasons)

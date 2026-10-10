import copy
import datetime as dt
import json
import sys
from pathlib import Path
import tempfile
import types
import zipfile
import unittest
from unittest.mock import patch

from backends import PosixBackend, make_backend, split_nmcli
from engine import BehaviorModel, assess
from privacy import public_report
from tools.release_guard import PUBLIC_REPOSITORY, scan_bytes, manifest, audit_source, audit_archive, audit_executable
from tools.build import python_runtime_license
from tools.prepare_source import prepare


class BackendTests(unittest.TestCase):
    def test_supported_platform_selection(self):
        for system in ('Linux', 'Darwin'):
            self.assertEqual(make_backend(None, system=system).name, system)
        self.assertEqual(make_backend(lambda *a: {}, system='Windows').name, 'Windows')
        with self.assertRaises(RuntimeError): make_backend(None, system='ImaginaryOS')

    def test_missing_scanner_disables_scans(self):
        with patch('backends.shutil.which', return_value=None):
            cap = PosixBackend('Linux').capabilities()
        self.assertNotIn('scan', cap['actions'])
        self.assertFalse(cap['scannerInstalled'])
        self.assertNotIn('quick', cap['actions'])

    def test_posix_does_not_claim_defender_disabled(self):
        s = {'platform': 'Linux', 'defender': None, 'capabilities': {'scannerInstalled': False}, 'processes': []}
        findings = assess(s, BehaviorModel())
        self.assertNotIn('defender-unavailable', [f['id'] for f in findings])
        self.assertIn('scanner-unavailable', [f['id'] for f in findings])

    def test_clamav_detection_exit_is_a_verified_detection_result(self):
        with tempfile.TemporaryDirectory() as root:
            backend = PosixBackend('Linux', [root])
            with patch('backends.shutil.which', return_value='/fictional/bin/clamscan'), patch('backends.run_command') as runner:
                runner.return_value = types.SimpleNamespace(returncode=1, stdout='Scanned files: 2\nInfected files: 1\n', stderr='')
                result = backend.action('scan')
                arguments = runner.call_args.args[0]
        self.assertEqual(result['verdict'], 'detections')
        self.assertEqual(result['detectionCount'], 1)
        self.assertFalse(any(x.startswith(('--remove', '--move', '--kill')) for x in arguments))
        self.assertIn('--follow-file-symlinks=0', arguments)
        self.assertIn('--cross-fs=no', arguments)

    def test_clamav_errors_cannot_be_clean_results(self):
        with tempfile.TemporaryDirectory() as root:
            backend = PosixBackend('Darwin', [root])
            with patch('backends.shutil.which', return_value='/fictional/bin/clamscan'), patch('backends.run_command') as runner:
                runner.return_value = types.SimpleNamespace(returncode=2, stdout='', stderr='denied')
                with self.assertRaises(RuntimeError): backend.action('scan')

    def test_scan_root_is_explicit_and_existing(self):
        with self.assertRaises(ValueError): PosixBackend('Linux', ['relative-folder'])
        with self.assertRaises(ValueError): PosixBackend('Linux', ['/fictional/nonexistent/directory'])

    def test_nmcli_escaped_ssid(self):
        self.assertEqual(split_nmcli(r'*:FICTIONAL\:NETWORK:WPA2:75'), ['*', 'FICTIONAL:NETWORK', 'WPA2', '75'])

    def test_linux_security_does_not_invent_cipher(self):
        backend = PosixBackend('Linux')
        s = {'addresses': [{'interface': 'wlan-test'}], 'coverageNotes': []}
        with patch('pathlib.Path.exists', return_value=True), patch('backends.shutil.which', return_value='/fictional/bin/nmcli'), patch('backends.checked', return_value='*:FICTIONAL-NETWORK:WPA2:75'):
            wifi = backend.wifi(s)
        self.assertEqual(wifi['State'], 'connected')
        self.assertEqual(wifi['Cipher'], 'Not verified')

    def test_mac_missing_wifi_metadata_stays_unknown(self):
        s = {'coverageNotes': []}
        with patch('backends.checked', side_effect=['Hardware Port: Wi-Fi\nDevice: en0\n', 'You are not associated with an AirPort network.']):
            self.assertEqual(PosixBackend('Darwin').wifi(s), {})
        self.assertTrue(s['coverageNotes'])

    def test_mac_firewall_parse_enabled_and_disabled(self):
        for value, expected in [('Firewall is enabled. (State = 1)', True), ('Firewall is disabled. (State = 0)', False)]:
            with patch('backends.checked', return_value=value):
                self.assertIs(PosixBackend('Darwin').firewall()[0]['Enabled'], expected)


class PrivacyTests(unittest.TestCase):
    def test_native_auditor_inspects_raw_code_without_deserialization(self):
        reader_module = types.ModuleType('PyInstaller.archive.readers')
        calls = []
        class Embedded:
            toc = {'fictional_module': ()}
            def extract(self, name, raw=False):
                calls.append((name, raw))
                if not raw: raise AssertionError('Foreign Python code must not be deserialized')
                return b'FICTIONAL-PRIVATE-CANARY-111'
        class Archive:
            def __init__(self, path): self.toc = {'PYZ.pyz': ('z',)}
            def open_embedded_archive(self, name): return Embedded()
        reader_module.CArchiveReader = Archive
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'fictional.bin'; binary.write_bytes(b'fake archive')
            with patch.dict(sys.modules, {'PyInstaller.archive.readers': reader_module}):
                findings = audit_executable(binary, ['FICTIONAL-PRIVATE-CANARY-111'])
        self.assertEqual(calls, [('fictional_module', True)])
        self.assertTrue(any(item['reason'] == 'local-private-identifier' for item in findings))

    def test_runtime_license_fallback_is_version_specific(self):
        staging = Path('fictional-source')
        fallback = staging / 'licenses' / 'Python-3.13-LICENSE.txt'
        with patch.object(Path, 'is_file', lambda path: path == fallback):
            self.assertEqual(python_runtime_license(staging, 'fictional-python', (3, 13)), fallback)
            self.assertIsNone(python_runtime_license(staging, 'fictional-python', (3, 14)))

    def test_authorized_repository_url_does_not_disclose_local_identity(self):
        overlapping_seed = PUBLIC_REPOSITORY.split('/')[3][:5]
        for encoding in ('utf-8', 'utf-16-le'):
            self.assertFalse(scan_bytes(PUBLIC_REPOSITORY.encode(encoding), 'public.md', [overlapping_seed]))
            self.assertTrue(scan_bytes((PUBLIC_REPOSITORY + ' private=' + overlapping_seed).encode(encoding), 'public.md', [overlapping_seed]))

    def test_public_url_exception_never_hides_credentials_or_home_paths(self):
        credential = 'sk-' + 'A' * 35
        home = 'C:' + '\\Users\\' + 'fictional-person' + '\\private.txt'
        self.assertTrue(scan_bytes((PUBLIC_REPOSITORY + '?key=' + credential).encode(), 'public.md', []))
        self.assertTrue(scan_bytes((PUBLIC_REPOSITORY + '\n' + home).encode(), 'public.md', []))

    def test_allowlisted_report_drops_all_nested_sensitive_fields(self):
        marker = 'FICTIONAL-PRIVATE-CANARY-123'
        model = BehaviorModel(); model.state['processes'][marker] = {'secret': marker}
        state = {'snapshot': {'platform': marker, 'wifiRaw': marker, 'processes': [{'Name': marker, 'CommandLine': marker}],
                              'events': [{'Message': marker}], 'errors': [marker], 'defender': {'RealTimeProtectionEnabled': marker}},
                 'findings': [{'severity': marker, 'title': marker, 'detail': marker}], 'lastError': marker,
                 'network': {'ssid': marker, 'devices': [{'ip': marker}]}, 'jobs': [{'token': marker}], 'alertHistory': [marker]}
        before = copy.deepcopy(state)
        report = public_report(state, model)
        self.assertNotIn(marker, json.dumps(report))
        self.assertIsNone(report['protection']['RealTimeProtectionEnabled'])
        self.assertEqual(state, before)

    def test_local_identifiers_and_tokens_are_rejected_without_echoing_values(self):
        canary = 'FICTIONAL-PRIVATE-CANARY-987'
        findings = scan_bytes(('some content ' + canary).encode(), 'sample.py', [canary])
        self.assertTrue(findings)
        self.assertNotIn(canary, json.dumps(findings))
        self.assertTrue(scan_bytes(('#token=' + 'a' * 40).encode(), 'sample.py', []))

    def test_secret_keys_and_home_paths_rejected(self):
        secret = ('sk-' + 'A' * 35).encode()
        path = ('C:' + '\\Users\\' + 'fictional-person' + '\\private.txt').encode()
        self.assertTrue(scan_bytes(secret, 'sample.txt', []))
        self.assertTrue(scan_bytes(path, 'sample.txt', []))

    def test_source_allowlist_refuses_runtime_data_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'data').mkdir(); (root / 'data' / 'model.json').write_text('{}')
            (root / 'release-manifest.json').write_text(json.dumps({'files': ['data/model.json']}))
            with self.assertRaises(ValueError): manifest(root)

    def test_source_archive_is_allowlisted_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'; root.mkdir()
            (root / 'file.txt').write_text('fictional public source')
            (root / 'release-manifest.json').write_text(json.dumps({'files': ['file.txt', 'release-manifest.json']}))
            (root / 'data').mkdir(); (root / 'data' / 'secret.json').write_text('PRIVATE-EXCLUDED-DATA')
            first = prepare(root, Path(directory) / 'first', [])
            second = prepare(root, Path(directory) / 'second', [])
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertFalse(audit_archive(first))

    def test_source_bundle_fails_on_private_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); marker = 'FICTIONAL-SENSITIVE-12345'
            (root / 'file.txt').write_text(marker)
            (root / 'release-manifest.json').write_text(json.dumps({'files': ['file.txt', 'release-manifest.json']}))
            with self.assertRaises(ValueError): prepare(root, root / 'output', [marker])

    def test_forged_archive_allowlist_cannot_admit_runtime_files(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'forged.zip'
            with zipfile.ZipFile(output, 'w') as archive:
                archive.writestr('sentinel-local/release-manifest.json', json.dumps({'files': ['release-manifest.json', 'data/token.json']}))
                archive.writestr('sentinel-local/data/token.json', '{}')
            self.assertTrue(any(f['reason'] == 'forbidden-private-archive-member' for f in audit_archive(output)))

    def test_vendor_example_exception_never_hides_a_known_owner_identifier(self):
        fictional_vendor_path = b'C:' + b'/Users/' + b'Barney'
        self.assertFalse(scan_bytes(fictional_vendor_path, 'vendor-library', [], vendor_examples=True))
        self.assertTrue(scan_bytes(fictional_vendor_path, 'vendor-library', ['Barney'], vendor_examples=True))

    def test_public_vendor_compiler_exception_is_binary_scoped_and_identifier_checked(self):
        prefix = b'/Users/' + b'nad/build_macos_installer/'
        source = prefix + b'Python-3.13/Modules/fictional.c'
        unrelated = b'/Users/' + b'fictional-owner/private/file.txt'
        self.assertFalse(scan_bytes(source, 'vendor-library', [], vendor_examples=True))
        self.assertTrue(scan_bytes(source, 'vendor-library', ['nad'], vendor_examples=True))
        self.assertTrue(scan_bytes(source, 'public-source', []))
        self.assertTrue(scan_bytes(unrelated, 'vendor-library', [], vendor_examples=True))
        self.assertTrue(scan_bytes(prefix[:-1] + b'-private/secret.c', 'vendor-library', [], vendor_examples=True))


if __name__ == '__main__':
    unittest.main()

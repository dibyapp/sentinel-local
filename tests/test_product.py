"""Product packaging and API contracts. No real host scans or model requests."""
import http.client
import json
from pathlib import Path
import tempfile
import subprocess
import threading
import unittest
from unittest.mock import patch
import zipfile

from app import Agent, Server, dashboard_server, save_json
from version import __version__
from tools.build_portable import audit_portable, build


class PortableTests(unittest.TestCase):
    def root(self, folder):
        folder.mkdir()
        (folder / 'portable_main.py').write_text('print("fictional launcher")', encoding='utf-8')
        (folder / 'app.py').write_text('fictional public source', encoding='utf-8')
        (folder / 'release-manifest.json').write_text(json.dumps({'files': ['app.py', 'portable_main.py', 'release-manifest.json']}))
        return folder

    def test_portable_artifact_is_deterministic_and_private_files_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); root = self.root(base / 'source')
            (root / '.local').mkdir(); (root / '.local/secret.json').write_text('PRIVATE-EXCLUDED-CANARY')
            original = subprocess.run
            def execute(args, **kwargs):
                if args[-1] == '--self-test':
                    return subprocess.CompletedProcess(args, 0, stdout='{"passed":true}', stderr='')
                return original(args, **kwargs)
            with patch('tools.build_portable.subprocess.run', side_effect=execute):
                first = build(root, base / 'first', []); second = build(root, base / 'second', [])
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertFalse(audit_portable(first, root, []))
            with zipfile.ZipFile(first) as archive:
                self.assertNotIn('.local/secret.json', archive.namelist())
                self.assertEqual(archive.read('__main__.py'), (root / 'portable_main.py').read_bytes())

    def test_portable_gate_rejects_changed_bootstrap_extra_files_and_private_canaries(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); root = self.root(base / 'source')
            for kind in ('bootstrap', 'extra', 'private'):
                output = base / (kind + '.pyz')
                with zipfile.ZipFile(output, 'w') as archive:
                    for path in root.iterdir(): archive.write(path, path.name)
                    archive.writestr('__main__.py', 'changed' if kind == 'bootstrap' else (root / 'portable_main.py').read_bytes())
                    if kind == 'extra': archive.writestr('data/token.json', '{}')
                seeds = ['fictional public source'] if kind == 'private' else []
                self.assertTrue(audit_portable(output, root, seeds))


class ProductApiTests(unittest.TestCase):
    def test_default_launch_preserves_older_monitor_and_explicit_port_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Agent(data_dir=Path(directory))
            with patch('app.Server', side_effect=[OSError('occupied'), 'new server']) as server:
                self.assertEqual(dashboard_server(agent, Path(directory), None, False), 'new server')
                self.assertEqual(server.call_args_list[1].args[0], ('127.0.0.1', 0))
            with patch('app.Server', side_effect=OSError('occupied')):
                with self.assertRaises(SystemExit): dashboard_server(agent, Path(directory), 8877, False)

    def test_matching_release_reuses_authenticated_saved_port(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Agent(data_dir=Path(directory)); server = Server(('127.0.0.1', 0), agent)
            worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
            save_json(Path(directory) / 'instance.json', {'port': server.server_port, 'token': server.token, 'configuration': agent.configuration})
            agent.state['version'] = __version__
            try:
                self.assertIsNone(dashboard_server(agent, Path(directory), None, False))
                changed = Agent(interval=120, data_dir=Path(directory))
                with self.assertRaisesRegex(SystemExit, 'different settings'):
                    dashboard_server(changed, Path(directory), None, False)
                original_view = agent.view
                def older_view():
                    value = original_view(); value['version'] = 'fictional-old-release'; return value
                with patch.object(agent, 'view', side_effect=older_view):
                    replacement = dashboard_server(agent, Path(directory), None, False)
                self.assertIsNotNone(replacement); replacement.server_close()
            finally:
                server.shutdown(); server.server_close(); worker.join(timeout=2)

    def test_help_is_bundled_public_text_and_connection_api_requires_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Agent(data_dir=Path(directory)); server = Server(('127.0.0.1', 0), agent)
            worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
            try:
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                connection.request('GET', '/help/ai'); response = connection.getresponse(); body = response.read().decode()
                self.assertEqual(response.status, 200); self.assertIn('Direct AI security review', body); connection.close()
                for origin, expected in (('https://example.invalid', 403), (server.origin, 202)):
                    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                    with patch.object(agent, 'launch_ai_check', return_value={'status': 'running', 'fictionalEvidenceOnly': True}) as check:
                        connection.request('POST', '/api/ai/check', body='{"provider":"ollama"}', headers={'Origin': origin, 'X-Sentinel-Token': server.token, 'Content-Type': 'application/json'})
                        response = connection.getresponse(); response.read(); self.assertEqual(response.status, expected)
                        self.assertEqual(check.call_count, int(expected == 202))
                    connection.close()
            finally:
                server.shutdown(); server.server_close(); worker.join(timeout=2)

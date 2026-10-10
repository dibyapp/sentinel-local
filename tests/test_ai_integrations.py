"""Private extension contracts and connection checks, using fictional fixtures."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import ai_integrations as integrations
import ai_providers as providers
from app import Agent, fictional_ai_packet
from backends import WindowsBackend


def server_profile():
    return {'id': 'demo-server', 'kind': 'openai-compatible', 'label': 'Fictional server',
            'base_url': 'http://127.0.0.1:1234/v1', 'model': 'fictional-local-model'}


def cli_profile():
    return {'id': 'demo-wrapper', 'kind': 'cli', 'label': 'Fictional wrapper', 'argv': [sys.executable, '-c', 'pass'],
            'trusted_inference_only': True}


def result():
    return {'assessment': 'review', 'findings': [{'evidence_id': 'E001', 'severity': 'review',
                                                'reason_code': 'protection_off', 'next_step': 'review_protection'}]}


class ProfileTests(unittest.TestCase):
    def validate(self, profile):
        return integrations.validate_profiles({'profiles': [profile]}, providers.PROVIDERS)

    def test_builtins_and_duplicate_names_cannot_be_replaced(self):
        p = server_profile(); p['id'] = 'codex'
        with self.assertRaises(ValueError): self.validate(p)
        with self.assertRaises(ValueError): integrations.validate_profiles({'profiles': [server_profile(), server_profile()]})

    def test_plain_remote_http_userinfo_query_and_secret_fields_rejected(self):
        for endpoint in ('http://example.invalid/v1', 'http://localhost/v1', 'https://' + 'name:secret' + '@example.invalid/v1', 'https://example.invalid/v1?token=secret', 'https://example.invalid/v1#secret'):
            p = server_profile(); p['base_url'] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError): self.validate(p)
        p = server_profile(); p['api_key'] = 'FICTIONAL-SECRET-CANARY'
        with self.assertRaises(ValueError): self.validate(p)

    def test_loopback_ipv6_and_https_supported_without_embedded_keys(self):
        for endpoint in ('http://[::1]:1234/v1', 'https://example.invalid/v1'):
            p = server_profile(); p.update(base_url=endpoint, api_key_env='FICTIONAL_MODEL_KEY')
            self.assertEqual(self.validate(p)['demo-server']['base_url'], endpoint)

    def test_profile_file_is_explicit_bounded_and_not_part_of_the_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profiles.json'; path.write_text(json.dumps({'profiles': [server_profile()]}))
            self.assertIn('demo-server', integrations.load_profiles(path, providers.PROVIDERS))
            path.write_text('x' * 32_001)
            with self.assertRaises(ValueError): integrations.load_profiles(path)
        self.assertEqual(integrations.load_profiles(None), {})

    def test_custom_command_needs_explicit_trust_and_array_not_shell(self):
        for change in ({'trusted_inference_only': False}, {'argv': 'some-command'}, {'argv': ['sh', '-c', 'something']},
                       {'argv': ['wrapper.cmd']}, {'argv': ['wrapper', '{prompt}']}, {'argv': ['wrapper', '{secret}']},
                       {'argv': ['wrapper', 'line\nbreak']}):
            p = cli_profile(); p.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): self.validate(p)

    def test_custom_argument_placeholders_expand_without_shell_interpolation(self):
        p = cli_profile(); p['argv'] = [sys.executable, 'fictional.py', '--schema', '{schema}', '--workspace', '{workspace}', '$(literal)']
        p = self.validate(p)['demo-wrapper']
        args = integrations.profile_command(p, Path('/fictional'))
        self.assertIn(str(Path('/fictional/schema.json')), args); self.assertEqual(args[-1], '$(literal)')

    def test_custom_cli_requires_consent_even_when_called_local(self):
        p = self.validate(cli_profile())
        with self.assertRaises(ValueError): providers.run_review('demo-wrapper', '', fictional_ai_packet(), profiles=p)

    def test_custom_cli_only_gets_anonymous_stdin_and_validated_json(self):
        profiles = self.validate(cli_profile())
        def execute(args, **kwargs):
            self.assertFalse(kwargs['shell']); self.assertIn('Fictional fixture', kwargs['input'])
            self.assertEqual(set(p.name for p in kwargs['cwd'].iterdir()), {'schema.json'})
            return SimpleNamespace(returncode=0, stdout=json.dumps(result()), stderr='')
        with patch.object(providers.subprocess, 'run', side_effect=execute):
            value = providers.run_review('demo-wrapper', '', fictional_ai_packet(), allow_cloud=True, profiles=profiles)
        self.assertTrue(value['cloudUsed'])

    def test_model_server_requires_preview_consent_and_never_downloads(self):
        profiles = self.validate(server_profile())
        with patch.object(providers, 'compatible_review', return_value=result()) as review:
            with self.assertRaises(ValueError): providers.run_review('demo-server', '', fictional_ai_packet(), profiles=profiles)
            self.assertEqual(review.call_count, 0)
            value = providers.run_review('demo-server', '', fictional_ai_packet(), allow_cloud=True, profiles=profiles)
        self.assertEqual(value['result']['findings'][0]['reason_code'], 'protection_off')

    def test_server_request_disables_tools_and_credentials_are_env_only(self):
        p = self.validate(server_profile())['demo-server']; p['api_key_env'] = 'FICTIONAL_MODEL_KEY'
        captured = []
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps(result())}}]}).encode()
        class Opener:
            def open(self, request, timeout): captured.append(request); return Response()
        with patch.dict(integrations.os.environ, {'FICTIONAL_MODEL_KEY': 'FAKE-KEY-CANARY'}), patch.object(integrations, 'build_opener', return_value=Opener()) as opener:
            integrations.compatible_review(p, 'Fictional prompt', {})
        body = json.loads(captured[0].data)
        self.assertNotIn('FAKE-KEY-CANARY', json.dumps(body)); self.assertEqual(body['tools'], [])
        self.assertEqual(body['tool_choice'], 'none'); self.assertEqual(opener.call_args.args[0].proxies, {})
        with self.assertRaises(ValueError): integrations.NoServerRedirect().redirect_request(None)


class ConnectionTests(unittest.TestCase):
    def test_connection_probe_does_not_collect_host_or_affect_security_status(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Agent(data_dir=Path(directory), backend=WindowsBackend(lambda *a, **k: (_ for _ in ()).throw(AssertionError('Must not collect'))))
            with patch('app.run_review', return_value={'cloudUsed': False}) as review:
                check = agent.launch_ai_check()
                deadline = time.monotonic() + 3
                while agent.state['aiChecks'][-1]['status'] == 'running' and time.monotonic() < deadline: time.sleep(.01)
                for worker in threading.enumerate():
                    if worker.name == 'ai-connection-check': worker.join(timeout=3)
            self.assertEqual(agent.state['aiChecks'][-1]['status'], 'completed')
            self.assertIsNone(agent.state['snapshot']); self.assertEqual(agent.state['aiReviews'], [])
            self.assertTrue(review.call_args.args[2]['coverage']['fictionalEvidenceOnly'])

    def test_connection_probe_requires_cloud_consent_and_blocks_parallel_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Agent(data_dir=Path(directory))
            with self.assertRaises(ValueError): agent.launch_ai_check('claude')
            agent.state['aiChecks'] = [{'status': 'running'}]
            with self.assertRaises(ValueError): agent.launch_ai_review()

    def test_vendor_diagnostic_is_classified_without_echoing_private_text(self):
        for diagnostic, code in (('Please set an Auth method in FICTIONAL-PRIVATE-PATH', 'authentication_required'),
                                 ('quota exceeded FICTIONAL-PRIVATE-PATH', 'provider_limit'),
                                 ('unknown argument FICTIONAL-PRIVATE-PATH', 'unsupported_cli_version')):
            error = providers.execution_error(diagnostic)
            self.assertEqual(error.code, code); self.assertNotIn('FICTIONAL-PRIVATE-PATH', str(error))

    def test_gemini_uses_dedicated_profile_with_tools_hooks_and_memory_restricted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); working = root / 'work'; working.mkdir(); home = root / 'profile'
            with patch.object(providers.sys, 'platform', 'win32'), patch.dict(providers.os.environ, {'PROGRAMDATA': str(root / 'fictional-system')}, clear=True), patch.object(providers, 'tool_search_path', return_value=''):
                env = providers.gemini_environment(working, home)
            self.assertEqual(env['GEMINI_CLI_HOME'], str(home.resolve()))
            self.assertNotIn('GEMINI_CLI_SYSTEM_SETTINGS_PATH', env)
            settings = json.loads((home / '.gemini/settings.json').read_text())
            self.assertFalse(settings['hooksConfig']['enabled']); self.assertFalse(settings['skills']['enabled'])
            self.assertEqual(settings['context']['fileName'], [])
            self.assertIn('toolName = "*"', (working / 'deny-tools.toml').read_text())
            self.assertIn('decision = "deny"', (working / 'deny-tools.toml').read_text())

    def test_gemini_never_overrides_enterprise_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); system = root / 'gemini-cli'; system.mkdir(); (system / 'settings.json').write_text('{}')
            with patch.object(providers.sys, 'platform', 'win32'), patch.dict(providers.os.environ, {'PROGRAMDATA': str(root)}, clear=True):
                with self.assertRaises(ValueError): providers.gemini_environment(root, root / 'profile')
            self.assertFalse((root / 'profile').exists())

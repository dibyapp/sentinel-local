"""AutoWork-style provider contracts. No model-generated command is executed."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.request import build_opener, ProxyHandler, Request, HTTPRedirectHandler

from ai_evidence import output_schema, review_prompt, validate_result
from ai_integrations import compatible_review, profile_command
from privacy import state_directory

HIDDEN = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
PROVIDERS = {'ollama': 'Ollama (local)', 'codex': 'Codex', 'claude': 'Claude Code', 'gemini': 'Gemini CLI'}


class ProviderError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def execution_error(stderr):
    diagnostic = stderr.lower()
    if any(s in diagnostic for s in ('set an auth method', 'not logged in', 'authentication', 'please login', 'please log in', 'unauthorized', 'api key')):
        return ProviderError('authentication_required', 'Sign in with the selected vendor CLI first. No login or credential change was attempted by Sentinel.')
    if any(s in diagnostic for s in ('rate limit', 'quota', 'usage limit', 'overloaded')):
        return ProviderError('provider_limit', 'The selected provider reported a usage limit or temporary capacity problem. Try later or explicitly select another tool.')
    if any(s in diagnostic for s in ('unknown argument', 'unknown option', 'unrecognized argument', 'unexpected argument')):
        return ProviderError('unsupported_cli_version', 'This CLI version does not support the restricted review contract. Update it using the vendor instructions.')
    return ProviderError('provider_failed', 'Provider execution failed or was blocked; no other provider was tried. Check the private local log and vendor setup.')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Local AI endpoint redirects are forbidden.')


def local_request(endpoint, payload=None, timeout=4):
    if endpoint not in ('tags', 'show', 'chat'):
        raise ValueError('Unknown local AI endpoint.')
    request = Request('http://127.0.0.1:11434/api/' + endpoint,
                      data=json.dumps(payload).encode() if payload is not None else None,
                      headers={'Content-Type': 'application/json'})
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=timeout) as response:
        content = response.read(1_000_001)
    if len(content) > 1_000_000:
        raise ValueError('AI response exceeded the size limit.')
    return json.loads(content)


def local_models():
    models = []
    for item in local_request('tags').get('models', [])[:100]:
        name = item.get('name')
        if isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,120}', name) and ':cloud' not in name.lower() and isinstance(item.get('size'), int) and item['size'] > 100_000_000:
            models.append({'name': name, 'size': item['size']})
    # Prefer a modest downloaded model over tiny models that often fail the
    # result contract; avoid selecting a very large model automatically.
    return sorted(models, key=lambda m: (0 if 1_000_000_000 <= m['size'] <= 3_000_000_000 else 1, m['size']))


def resolve_cli(provider):
    if provider not in ('codex', 'claude', 'gemini'):
        return None
    if provider == 'codex' and os.name == 'nt' and os.environ.get('LOCALAPPDATA'):
        candidates = list((Path(os.environ['LOCALAPPDATA']) / 'OpenAI' / 'Codex' / 'bin').glob('*/codex.exe'))
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        if candidates:
            return str(candidates[0])
    return shutil.which(provider, path=tool_search_path())


def tool_search_path():
    if sys.platform == 'win32':
        base = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'AutoWork'
    elif sys.platform == 'darwin':
        base = Path.home() / 'Library' / 'Application Support' / 'AutoWork'
    else:
        base = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'autowork'
    extra = [base / 'setup-tools', base / 'setup-tools' / 'bin', base / 'setup-tools' / 'node-runtime']
    return os.pathsep.join([os.environ.get('PATH', ''), *(str(p) for p in extra)])


def provider_options(profiles=None):
    try:
        models = local_models(); local_ready = bool(models)
    except Exception:
        models, local_ready = [], False
    options = {'providers': [{'id': name, 'name': label, 'installed': local_ready if name == 'ollama' else bool(resolve_cli(name)),
                           'cloud': name != 'ollama', 'supported': True} for name, label in PROVIDERS.items()],
            'localModels': models, 'defaultProvider': 'ollama',
            'note': 'Local models are checked again before inference. Cloud tools require explicit selection and consent; credentials stay vendor-owned. Provider failures never switch tools automatically.'}
    for ident, profile in (profiles or {}).items():
        installed = True
        if profile['kind'] == 'cli':
            try: profile_command(profile, Path('.'))
            except ValueError: installed = False
        options['providers'].append({'id': ident, 'name': profile['label'], 'installed': installed, 'cloud': True,
                                     'supported': True, 'custom': True, 'kind': profile['kind']})
    return options


def native_command(args):
    # Independently implemented: fixed official npm entry points, never shell
    # execution or arbitrary commands parsed out of a wrapper's contents.
    if os.name != 'nt' or Path(args[0]).suffix.lower() not in ('.cmd', '.bat'):
        return args
    shim = Path(args[0])
    entries = {'codex': [('node_modules', '@openai', 'codex', 'bin', 'codex.js')],
               'claude': [('node_modules', '@anthropic-ai', 'claude-code', 'cli.js')],
               'gemini': [('node_modules', '@google', 'gemini-cli', 'bundle', 'gemini.js'),
                          ('node_modules', '@google', 'gemini-cli', 'dist', 'index.js')]}
    if shim.stem not in entries:
        raise ValueError('Unrecognized Windows CLI shim.')
    bundled_node = shim.parent / 'node.exe'
    node = str(bundled_node) if bundled_node.is_file() else shutil.which('node', path=tool_search_path())
    entry = next((shim.parent.joinpath(*relative).resolve() for relative in entries[shim.stem] if shim.parent.joinpath(*relative).is_file()), shim.parent / 'missing-entry')
    if not node or not entry.is_relative_to(shim.parent.resolve()) or not entry.is_file():
        raise ValueError('Invalid CLI entry point.')
    return [node, str(entry), *args[1:]]


def command(provider, executable, directory, packet=None):
    if provider == 'codex':
        args = [executable, 'exec', '--ignore-user-config', '--sandbox', 'read-only', '--skip-git-repo-check', '--ephemeral',
                '-c', 'approval_policy="never"', '-c', 'forced_login_method="chatgpt"', '-c', 'model_provider="openai"',
                '-c', 'web_search="disabled"', '--cd', str(directory), '--output-schema', str(directory / 'schema.json'),
                '--output-last-message', str(directory / 'result.json'), '--json']
        for feature in ('shell_tool', 'unified_exec', 'multi_agent', 'multi_agent_v2', 'apps', 'plugins', 'hooks', 'computer_use', 'browser_use', 'in_app_browser'):
            args += ['--disable', feature]
        args.append('-')
    elif provider == 'claude':
        args = [executable, '-p', '--output-format', 'json', '--json-schema', json.dumps(output_schema(packet)),
                '--tools', '', '--disallowedTools', 'mcp__*', '--permission-mode', 'plan', '--safe-mode',
                '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--disable-slash-commands',
                '--no-session-persistence', '--setting-sources', '', '--max-turns', '1']
    elif provider == 'gemini':
        args = [executable, '--prompt', 'Return the structured security review requested on stdin.', '--output-format', 'json',
                '--approval-mode', 'plan', '--extensions', 'none', '--admin-policy', str(directory / 'deny-tools.toml')]
    else:
        raise ValueError('Provider restricted-review contract is unavailable.')
    return native_command(args)


def provider_environment():
    # Retain the OS basics and vendor home routing; do not hand inherited API
    # keys, endpoint overrides, project secrets or dashboard tokens to a child.
    allowed = {'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE',
               'APPDATA', 'LOCALAPPDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'LANG', 'LC_ALL',
               'CODEX_HOME', 'CLAUDE_CONFIG_DIR'}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env['PATH'] = tool_search_path()
    env['NO_COLOR'] = '1'
    return env


def gemini_environment(directory, profile_home=None):
    """Do not override established enterprise policy or vendor authentication."""
    if sys.platform == 'win32':
        system_root = Path(os.environ.get('PROGRAMDATA', 'C:/ProgramData')) / 'gemini-cli'
    elif sys.platform == 'darwin':
        system_root = Path('/Library/Application Support/GeminiCli')
    else:
        system_root = Path('/etc/gemini-cli')
    if os.environ.get('GEMINI_CLI_SYSTEM_SETTINGS_PATH') or os.environ.get('GEMINI_CLI_SYSTEM_DEFAULTS_PATH') or (system_root / 'settings.json').exists() or (system_root / 'system-defaults.json').exists() or any((system_root / 'policies').glob('*.toml')):
        raise ValueError('Existing Gemini administrator settings prevent a verified inference-only contract. They were not overridden.')
    settings = {'hooksConfig': {'enabled': False}, 'skills': {'enabled': False},
                'admin': {'secureModeEnabled': True, 'extensions': {'enabled': False}, 'mcp': {'enabled': False}, 'skills': {'enabled': False}},
                'context': {'fileName': [], 'includeDirectoryTree': False, 'includeDirectories': [], 'discoveryMaxDirs': 0},
                'advanced': {'ignoreLocalEnv': True}, 'model': {'maxSessionTurns': 1},
                'telemetry': {'enabled': False, 'logPrompts': False}, 'privacy': {'usageStatisticsEnabled': False}}
    profile_home = Path(profile_home or state_directory() / 'gemini-profile').expanduser().resolve()
    profile_home.mkdir(parents=True, exist_ok=True)
    vendor_dir = profile_home / '.gemini'
    vendor_dir.mkdir(exist_ok=True)
    # This is Sentinel's dedicated vendor profile, never the user's shared
    # Gemini home. Preserve only the vendor-selected authentication method.
    settings_file = vendor_dir / 'settings.json'
    if settings_file.is_symlink(): raise ValueError('Gemini profile settings must not be a symlink.')
    if settings_file.exists():
        previous = json.loads(settings_file.read_text(encoding='utf-8'))
        method = previous.get('security', {}).get('auth', {}).get('selectedType')
        if isinstance(method, str) and method in ('oauth-personal', 'gemini-api-key', 'vertex-ai', 'compute-default-credentials'):
            settings['security'] = {'auth': {'selectedType': method}}
    encoded = json.dumps(settings)
    for location in (settings_file, profile_home / 'settings.json'):
        if location.is_symlink(): raise ValueError('Gemini profile settings must not be a symlink.')
        temporary = location.with_suffix('.tmp')
        temporary.write_text(encoded, encoding='utf-8')
        if os.name != 'nt': temporary.chmod(0o600)
        temporary.replace(location)
    if os.name != 'nt':
        profile_home.chmod(0o700); vendor_dir.chmod(0o700)
    (directory / 'deny-tools.toml').write_text('[[rule]]\ntoolName = "*"\ndecision = "deny"\npriority = 999\n', encoding='utf-8')
    env = provider_environment()
    env['GEMINI_CLI_HOME'] = str(profile_home)
    return env


def run_review(provider, model, packet, allow_cloud=False, profiles=None, gemini_home=None):
    if provider == 'auto':
        provider = 'ollama'  # No cross-provider fallback or silent cloud run.
    profiles = profiles or {}
    if provider not in PROVIDERS and provider not in profiles:
        raise ValueError('Unknown AI provider.')
    prompt = review_prompt(packet)
    if provider == 'ollama':
        models = local_models()
        if not models:
            raise ValueError('No installed local model is available. No download was started.')
        model = model or models[0]['name']
        if model not in {m['name'] for m in models}:
            raise ValueError('Choose an installed local model; cloud models are not allowed.')
        metadata = local_request('show', {'model': model})
        if metadata.get('remote_model') or metadata.get('remote_host') or not metadata.get('model_info') or not metadata.get('details', {}).get('family') or any(x in str(metadata.get('modelfile', '')).lower() for x in ('remote_host', 'remote_model', 'https://ollama.com')):
            raise ValueError('A downloaded local model could not be verified.')
        payload = local_request('chat', {'model': model, 'messages': [{'role': 'user', 'content': prompt}],
                                        'stream': False, 'think': False, 'format': output_schema(packet), 'keep_alive': 0,
                                        'options': {'temperature': 0, 'num_ctx': 8192, 'num_predict': 650, 'num_thread': 2}}, timeout=180)
        if payload.get('done') is not True or payload.get('message', {}).get('tool_calls'):
            raise ValueError('AI response was incomplete or requested tools.')
        value = json.loads(payload['message']['content'])
    elif provider in profiles and profiles[provider]['kind'] == 'openai-compatible':
        if not allow_cloud:
            raise ValueError('Configured model servers require explicit consent. A loopback service may forward requests.')
        if model: raise ValueError('Configured model servers use their profile model.')
        try:
            value = compatible_review(profiles[provider], prompt, output_schema(packet))
        except Exception as exc:
            raise ProviderError('model_server_failed', 'The configured model server failed or returned unsupported output. No other provider was tried; check its model and JSON-schema support.') from exc
    else:
        if not allow_cloud:
            raise ValueError('Cloud AI needs explicit consent to send anonymous indicators to the selected provider.')
        executable = profiles[provider]['argv'][0] if provider in profiles else resolve_cli(provider)
        if not executable:
            raise ValueError('The selected provider CLI is not installed.')
        if model:
            raise ValueError('Cloud reviews use the vendor-configured model; no model override is accepted here.')
        with tempfile.TemporaryDirectory(prefix='sentinel-ai-review-') as temporary:
            directory = Path(temporary)
            if os.name != 'nt': directory.chmod(0o700)
            (directory / 'schema.json').write_text(json.dumps(output_schema(packet)), encoding='utf-8')
            environment = gemini_environment(directory, gemini_home) if provider == 'gemini' else provider_environment()
            arguments = profile_command(profiles[provider], directory) if provider in profiles else command(provider, executable, directory, packet)
            try:
                result = subprocess.run(arguments, input=prompt, cwd=directory,
                                    env=environment, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                    timeout=180, creationflags=HIDDEN, shell=False)
            except subprocess.TimeoutExpired as exc:
                raise ProviderError('provider_timeout', 'The selected AI tool exceeded three minutes. No verified result or fallback is available.') from exc
            if result.returncode:
                raise execution_error(result.stderr + '\n' + result.stdout)
            if len(result.stdout) + len(result.stderr) > 1_000_000:
                raise ValueError('Provider response exceeded the size limit.')
            if provider == 'codex':
                if (directory / 'result.json').stat().st_size > 1_000_000:
                    raise ValueError('Provider result exceeded the size limit.')
                value = json.loads((directory / 'result.json').read_text(encoding='utf-8'))
            else:
                payload = json.loads(result.stdout)
                if payload.get('is_error') or payload.get('error'):
                    raise ValueError('The selected provider returned an error.')
                value = payload if provider in profiles else payload.get('response') if provider == 'gemini' else payload.get('structured_output') or payload.get('result')
                if isinstance(value, str): value = json.loads(value)
    checked = validate_result(value, packet)
    return {'provider': provider, 'transport': 'loopback-local-model' if provider == 'ollama' else 'selected-cloud-cli',
            'result': checked, 'evidenceCount': len(packet['evidence']), 'cloudUsed': provider != 'ollama',
            'nativeMalwareScanStarted': False}

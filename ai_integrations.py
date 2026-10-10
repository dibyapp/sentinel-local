"""Explicit private profiles for compatible model servers and trusted wrappers."""
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, Request, HTTPRedirectHandler


def validate_profiles(value, builtins=()):
    if not isinstance(value, dict) or set(value) != {'profiles'} or not isinstance(value['profiles'], list) or len(value['profiles']) > 20:
        raise ValueError('AI configuration must contain at most 20 profiles.')
    checked = {}
    for raw in value['profiles']:
        if not isinstance(raw, dict): raise ValueError('Invalid AI profile.')
        ident, kind, label = raw.get('id'), raw.get('kind'), raw.get('label')
        if not isinstance(ident, str) or not re.fullmatch(r'[a-z][a-z0-9-]{1,39}', ident) or ident in (*builtins, 'auto') or ident in checked:
            raise ValueError('AI profile IDs must be unique and cannot replace built-in tools.')
        if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(c) < 32 for c in label):
            raise ValueError('AI profiles need a short display label.')
        base = {'id': ident, 'kind': kind, 'label': label}
        if kind == 'openai-compatible':
            if set(raw) - {'id', 'kind', 'label', 'base_url', 'model', 'api_key_env'}:
                raise ValueError('Unsupported model-server settings; never put credentials in this file.')
            endpoint, model = raw.get('base_url'), raw.get('model')
            if not isinstance(endpoint, str) or len(endpoint) > 500: raise ValueError('Invalid model-server URL.')
            url = urlsplit(endpoint)
            try: port = url.port
            except ValueError: raise ValueError('Invalid model-server port.') from None
            if not url.hostname or url.username or url.password or url.query or url.fragment or any(ord(c) < 33 for c in endpoint):
                raise ValueError('Model-server URLs cannot contain credentials, queries, or fragments.')
            if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('127.0.0.1', '::1')):
                raise ValueError('Use HTTPS, or literal IPv4/IPv6 loopback HTTP, for model servers.')
            if not isinstance(model, str) or not 1 <= len(model) <= 120 or any(ord(c) < 32 for c in model):
                raise ValueError('Choose a model already served by this endpoint.')
            key_env = raw.get('api_key_env', '')
            if not isinstance(key_env, str) or key_env and not re.fullmatch(r'[A-Z][A-Z0-9_]{2,79}', key_env):
                raise ValueError('API credential references must be environment variable names, not key values.')
            base.update(base_url=endpoint.rstrip('/'), model=model, api_key_env=key_env)
        elif kind == 'cli':
            if set(raw) != {'id', 'kind', 'label', 'argv', 'trusted_inference_only'} or raw.get('trusted_inference_only') is not True:
                raise ValueError('Custom CLI requires explicit trusted_inference_only acknowledgement.')
            argv = raw.get('argv')
            if not isinstance(argv, list) or not 1 <= len(argv) <= 40 or any(not isinstance(a, str) or not a or len(a) > 2000 or any(ord(c) < 32 for c in a) for a in argv):
                raise ValueError('Custom CLI must be an argument array, never a shell command string.')
            if any('{prompt}' in a or re.search(r'\{(?!schema\}|workspace\})[^}]*\}', a) for a in argv):
                raise ValueError('Prompts go through stdin. Only {schema} and {workspace} placeholders are supported.')
            if '{' in argv[0] or '}' in argv[0] or Path(argv[0]).suffix.lower() in ('.cmd', '.bat', '.ps1'):
                raise ValueError('Use a native executable or interpreter for a custom CLI; shell wrappers are not executed.')
            if Path(argv[0]).stem.lower() in ('cmd', 'powershell', 'pwsh', 'sh', 'bash', 'zsh'):
                raise ValueError('Shell command interpreters are not custom inference adapters.')
            base.update(argv=list(argv), trusted_inference_only=True)
        else:
            raise ValueError('Profile kind must be openai-compatible or cli.')
        checked[ident] = base
    return checked


def load_profiles(path, builtins=()):
    if path is None: return {}
    path = Path(path).expanduser().resolve()
    if not path.is_file() or path.stat().st_size > 32_000:
        raise ValueError('AI profile file is missing or too large.')
    try:
        value = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        raise ValueError('AI profile file could not be read as JSON.') from None
    return validate_profiles(value, builtins)


def profile_command(profile, directory):
    argv = list(profile['argv'])
    executable = shutil.which(argv[0])
    if not executable:
        path = Path(argv[0]).expanduser()
        executable = str(path.resolve()) if path.is_absolute() and path.is_file() else None
    if not executable or Path(executable).suffix.lower() in ('.cmd', '.bat', '.ps1'):
        raise ValueError('The selected native custom adapter is unavailable.')
    return [executable, *(a.replace('{schema}', str(directory / 'schema.json')).replace('{workspace}', str(directory)) for a in argv[1:])]


class NoServerRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('AI model-server redirects are forbidden.')


def compatible_review(profile, prompt, schema):
    key_name = profile.get('api_key_env')
    key = os.environ.get(key_name, '') if key_name else ''
    if key_name and not key: raise ValueError('The selected model-server credential environment variable is not set.')
    if any(c in key for c in ('\r', '\n')): raise ValueError('Invalid model-server credential.')
    body = {'model': profile['model'], 'messages': [{'role': 'user', 'content': prompt}], 'stream': False,
            'temperature': 0, 'max_tokens': 1000, 'tools': [], 'tool_choice': 'none',
            'response_format': {'type': 'json_schema', 'json_schema': {'name': 'sentinel_review', 'schema': schema}}}
    headers = {'Content-Type': 'application/json'}
    if key: headers['Authorization'] = 'Bearer ' + key
    request = Request(profile['base_url'] + '/chat/completions', data=json.dumps(body).encode(), headers=headers)
    with build_opener(ProxyHandler({}), NoServerRedirect()).open(request, timeout=180) as response:
        content = response.read(1_000_001)
    if len(content) > 1_000_000: raise ValueError('AI model-server response exceeded the size limit.')
    payload = json.loads(content)
    choices = payload.get('choices')
    if not isinstance(choices, list) or len(choices) != 1 or choices[0].get('finish_reason') != 'stop' or choices[0].get('message', {}).get('tool_calls'):
        raise ValueError('AI model-server response was incomplete or requested tools.')
    return json.loads(choices[0]['message']['content'])

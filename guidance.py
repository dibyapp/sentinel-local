"""Plain-language local guidance; AI handoffs contain allowlisted summaries only."""
import datetime as dt
import json
import platform
import shutil

from engine import rows, timestamp
from privacy import public_report


def system_profile():
    system = platform.system()
    machine = platform.machine().lower()
    return {'os': system if system in ('Windows', 'Linux', 'Darwin') else 'unknown',
            'label': 'macOS' if system == 'Darwin' else system if system in ('Windows', 'Linux') else 'Unsupported OS',
            'architecture': 'ARM64' if machine in ('arm64', 'aarch64') else 'x64' if machine in ('amd64', 'x86_64') else 'other',
            'assistants': [{'name': name, 'cliDetected': bool(shutil.which(command))}
                           for name, command in (('Codex', 'codex'), ('Claude', 'claude'), ('Ollama', 'ollama'))],
            'assistantMode': 'Manual handoff. Detection checks PATH only; no assistant is launched or connected.'}


def next_steps(state, capabilities):
    snapshot = state.get('snapshot') or {}
    observed = timestamp(snapshot.get('collectedAt'))
    fresh = bool(observed) and 0 <= (dt.datetime.now(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds() <= 240
    findings = rows(state.get('findings'))
    active = sum(t.get('IsActive') is True for t in rows(snapshot.get('threats')))
    historical = sum(t.get('IsActive') is False for t in rows(snapshot.get('threats')))
    system = capabilities.get('platform')
    defender = snapshot.get('defender') or {}
    firewalls = rows(snapshot.get('firewall'))
    verified = (system == 'Windows' and len(firewalls) == 3
                and all(f.get('Enabled') is True or f.get('Enabled') == 1 for f in firewalls)
                and all(defender.get(k) is True for k in ('AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled')))
    if not fresh or state.get('lastError'):
        status, title, detail = 'unknown', 'Refresh your security check', 'The available snapshot is missing, old, or failed. Refresh before relying on its status.'
    elif active:
        status, title, detail = 'attention', 'Active malware needs attention', 'Open Windows Security → Virus & threat protection → Protection history. Follow the antivirus engine’s instructions.'
    elif any(f.get('severity') == 'critical' for f in findings):
        status, title, detail = 'attention', 'A security check needs attention', 'Review the highlighted finding below. A protection setting or review signal does not by itself prove infection.'
    elif snapshot.get('errors') or system == 'Windows' and not verified:
        status, title, detail = 'unknown', 'Some protections could not be verified', 'Check Monitor health and the OS security app. Unknown checks are not a clean bill of health.'
    elif findings:
        status, title, detail = 'review', 'Review the advisory findings', 'The checks found items to review. Behavior alerts are clues, not malware verdicts.'
    elif verified:
        status, title, detail = 'clear', 'No current issues in the available checks', 'Your core defenses are on and Defender reports no active threat. Keep monitoring; this is not a guarantee that every file is safe.'
    else:
        status, title, detail = 'limited', 'Host checks are available', 'Check your OS protections separately. Sentinel does not provide real-time malware blocking on this platform.'
    actions = capabilities.get('actions', [])
    steps = [{'title': '1. Check your status', 'detail': 'OS and scanner are selected automatically. Monitoring starts when Sentinel opens.', 'action': 'refresh'}]
    if 'quick' in actions:
        steps.append({'title': '2. Scan when you are ready', 'detail': 'A quick scan uses Microsoft Defender. Start it yourself when downloads and other work permit.', 'action': 'quick'})
    elif 'scan' in actions:
        steps.append({'title': '2. Scan your selected folders', 'detail': 'ClamAV scans only folders selected at launch. Detected files are left for review.', 'action': 'scan'})
    else:
        steps.append({'title': '2. Set up optional file scanning', 'detail': 'Install ClamAV from your OS package manager, then select folders with --scan-root. Monitoring works without it.', 'action': None})
    steps.append({'title': '3. Review findings or ask an AI helper', 'detail': 'Choose a local AI review below, or preview anonymous evidence before an optional cloud review. Nothing is sent automatically.', 'action': None})
    return {'status': status, 'title': title, 'detail': detail, 'activeThreatCount': active,
            'historicalThreatCount': historical, 'steps': steps}


def assistant_handoff(state, model):
    # No raw string from a snapshot, finding, job, executable, or installed
    # assistant enters this prompt. Usernames/paths/SSID/IP/token stay local.
    summary = public_report(state, model)
    prompt = ('Help me understand this Sentinel Local security summary in plain language. '
              'Distinguish active detections, historical detections, advisory behavior signals, and unknown checks. '
              'Do not declare the computer clean based on this summary. Ask for sanitized clarification if needed.\n\n'
              'If you have authorized local terminal access, run `python app.py --diagnose` from the Sentinel project first. '
              'Use `python app.py --scan quick` on Windows only if I explicitly request a quick malware scan. '
              'On Linux/macOS, explain how to select folders with --scan-root before I request `--scan selected`. '
              'Use the platform antivirus engine for scanning. A chat-only assistant cannot scan my computer. '
              'Do not inspect Downloads, run a full scan, change security settings, remove files, install tools, '
              'upload files/logs, or publish anything without my specific instruction. '
              'Keep raw reports and dashboard credentials local. Return only a sharing-safe summary.\n\n'
              'Sharing-safe summary (no identifiers or raw evidence):\n' + json.dumps(summary, indent=2))
    return {'prompt': prompt, 'summary': summary, 'connected': False,
            'mode': 'Review and copy manually into your chosen assistant; no AI service is contacted.'}

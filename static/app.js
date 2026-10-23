'use strict';
const $ = id => document.getElementById(id);
const token = new URLSearchParams(location.hash.slice(1)).get('token') || sessionStorage.getItem('sentinel-token') || '';
if (token) sessionStorage.setItem('sentinel-token', token);
history.replaceState(null, '', location.pathname);
let latest;
let aiOptionsLoaded = false, evidencePreviewed = false, aiPreviewToken = '';
const aiReasonLabels = {native_active_detection: 'Native protection reports an active detection', encoded_command: 'Encoded shell command needs review', temporary_network_process: 'Internet activity from a temporary program', unusual_network_activity: 'Connection activity needs review', protection_off: 'Protection setting is off', weak_wifi: 'Weak Wi-Fi security indicator', unsigned_remote_access: 'Unsigned application uses a remote-access port', persistence_indicator: 'Startup command needs review', unknown_visibility: 'Some checks are unavailable'};
const aiNextSteps = {verify_app: 'Next: confirm you installed and expect this application. An unfamiliar app needs further local investigation.', review_protection: 'Next: open your OS security app and review protection settings or detection history.', review_wifi: 'Next: check router encryption settings locally.', inspect_startup: 'Next: inspect the startup entry locally before making changes.', refresh_status: 'Next: refresh status and review missing tools or permissions in Monitor health.'};
function node(tag, text, className) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (className) e.className = className; return e; }
function date(value) { if (!value) return 'Not recorded'; const match = /\/Date\((-?\d+)/.exec(value); const d = new Date(match ? Number(match[1]) : value); return isNaN(d.getTime()) ? 'Unknown' : d.toLocaleString(); }
function list(value) { return Array.isArray(value) ? value : value ? [value] : []; }
function detail(parent, label, value) { const row = node('div', undefined, 'detail'); row.append(node('span', label), node('strong', String(value))); parent.append(row); }
function notice(text) { $('notice').textContent = text; $('notice').hidden = !text; }
async function api(path, body) { const response = await fetch(path, { method: body ? 'POST' : 'GET', headers: { 'X-Sentinel-Token': token, ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) }); const data = await response.json(); if (!response.ok) throw Error(data.error || 'Request failed'); return data; }
function fallbackGuide(s, findings, errors, stale, isWindows, protectedNow) {
  const active = list(s.threats).filter(t => t.IsActive === true).length;
  const historical = list(s.threats).filter(t => t.IsActive === false).length;
  return {status: stale ? 'unknown' : active || findings.some(f => f.severity === 'critical') ? 'attention' : errors.length || isWindows && !protectedNow ? 'unknown' : findings.length ? 'review' : isWindows ? 'clear' : 'limited',
    title: stale ? 'Refresh your security check' : active ? 'Active malware needs attention' : findings.length ? 'Review the findings below' : errors.length || isWindows && !protectedNow ? 'Some protections could not be verified' : isWindows ? 'No current issues in the available checks' : 'Host checks are available',
    detail: 'Monitoring refreshes automatically. Review findings and coverage before relying on the status.', historicalThreatCount: historical};
}
function renderGuide(data, guide, capabilities) {
  const system = data.system;
  $('system-badge').textContent = system ? `${system.label} · ${system.architecture} · detected` : `${capabilities.platform === 'Darwin' ? 'macOS' : capabilities.platform} · detected`;
  $('plain-summary').textContent = guide.title + '. ' + guide.detail;
  $('plain-summary').className = ['attention', 'unknown', 'review'].includes(guide.status) ? 'warning' : '';
  $('historical-summary').hidden = !guide.historicalThreatCount;
  $('historical-summary').textContent = `${guide.historicalThreatCount || 0} inactive historical detection(s). These records do not show a current infection. Review Detection & alert history if needed.`;
  const steps = $('next-steps'); steps.replaceChildren();
  for (const step of guide.steps || [{title: '1. Check your status', detail: 'Review protection and findings. Status refreshes automatically.'}, {title: '2. Scan when you are ready', detail: 'Use the scan button for your platform after your other work permits.'}, {title: '3. Understand the results', detail: 'Read findings or generate a prompt for the AI helper below.'}]) {
    const item = node('article', undefined, 'step'); item.append(node('strong', step.title), node('p', step.detail)); steps.append(item);
  }
  const tools = $('assistant-tools'); tools.replaceChildren();
  for (const assistant of system?.assistants || []) tools.append(node('span', `${assistant.name} CLI · ${assistant.cliDetected ? 'detected' : 'not found on PATH'}`));
  $('assistant-note').textContent = system ? system.assistantMode + ' Desktop apps and account access are not checked. You can use any assistant manually.' : 'This running monitor predates assistant detection. The generic prompt still works with your chosen AI; the updated source provides local detection.';
  $('prepare-ai').disabled = !!data.lastError || !data.snapshot;
  $('direct-ai').hidden = !data.directAiReview;
  if (data.directAiReview && !aiOptionsLoaded) { aiOptionsLoaded = true; loadAiOptions(); }
  const reviews = $('ai-reviews'); reviews.replaceChildren();
  const checks = $('ai-checks'); checks.replaceChildren();
  for (const check of list(data.aiChecks).slice(-2).reverse()) {
    const item = node('article', undefined, 'job');
    item.append(node('strong', `${check.provider} connection test · ${check.status}`), node('p', check.error || check.message || 'Testing with fictional evidence only.'));
    if (check.errorCode === 'authentication_required') item.append(node('small', 'Next: sign in through the vendor. Gemini uses a separate Sentinel profile; see AI setup instructions.'));
    checks.append(item);
  }
  const newestReview = list(data.aiReviews).slice(-1)[0];
  if (newestReview?.status === 'completed' && $('direct-ai-status').textContent.startsWith('AI review started.')) $('direct-ai-status').textContent = 'AI review completed. Review the advisory findings and next steps below; no malware scan was performed.';
  for (const review of list(data.aiReviews).slice(-3).reverse()) {
    const item = node('article', undefined, 'job'); const response = review.result?.result;
    item.append(node('strong', `${review.provider} · ${review.status}`));
    if (review.status === 'completed') item.append(node('small', review.evidenceCurrent ? 'Evidence matches the current snapshot.' : 'Historical AI review: evidence no longer matches current observations. Run a new explicit review if needed.'));
    if (review.error) item.append(node('p', review.error));
    if (response) {
      item.append(node('p', response.assessment === 'review' ? 'Evidence-backed advisory findings to review' : response.assessment === 'insufficient_evidence' ? 'Insufficient evidence for an assessment' : 'AI proposed no additional signals in this sample'));
      for (const finding of list(response.findings)) { item.append(node('p', `${review.aliases?.[finding.evidence_id]?.name || finding.evidence_id}: ${aiReasonLabels[finding.reason_code] || 'Review indicator'} · ${finding.severity}`)); item.append(node('small', aiNextSteps[finding.next_step] || 'Review this indicator locally.')); }
      item.append(node('small', response.scope));
      if (review.coverage?.omittedCandidates) item.append(node('small', `${review.coverage.omittedCandidates} candidate observations were outside this bounded review.`));
    }
    reviews.append(item);
  }
  const aiBusy = [...list(data.aiReviews), ...list(data.aiChecks)].some(r => r.status === 'running');
  $('run-ai').disabled = aiBusy || !!data.lastError;
  $('test-ai').disabled = aiBusy;
  document.querySelector('.advanced').hidden = !list(capabilities.actions).includes('full');
}
function render(data) {
  latest = data;
  const s = data.snapshot, errors = s ? list(s.errors) : [];
  $('live-state').textContent = data.lastError ? 'Collection error' : data.collecting ? 'Reading system' : 'Monitoring active';
  const stale = s && Date.now() - new Date(s.collectedAt).getTime() > 240000;
  notice(data.lastError || (stale ? 'This snapshot is stale. Protection status needs a fresh collection.' : errors.length ? `${errors.length} security checks could not be read. See Monitor health for coverage.` : ''));
  if (!s) return;
  const capabilities = data.capabilities || s.capabilities || { platform: 'Windows', engine: 'Microsoft Defender', actions: ['quick', 'full', 'update', 'network'] };
  const isWindows = capabilities.platform === 'Windows';
  document.querySelectorAll('[data-action]').forEach(button => { button.hidden = !list(capabilities.actions).includes(button.dataset.action); });
  $('platform-description').textContent = isWindows ? 'Malware protection from Defender. An extra set of eyes from Sentinel.' : `${capabilities.platform === 'Darwin' ? 'macOS' : capabilities.platform} host monitoring. Optional folder scans from ClamAV.`;
  $('engine-name').textContent = capabilities.engine || 'SCAN ENGINE';
  $('scan-footnote').textContent = isWindows ? 'Defender handles blocking and quarantine. Full scans can take hours. Windows may deny actions without elevation.' : 'Sentinel does not provide real-time malware blocking on this OS. Install ClamAV and launch with --scan-root to enable selected-folder scans. Scans never remove files.';
  $('export-footnote').textContent = data.version ? 'Exports contain summary counts and protection flags; identifiers and raw evidence are excluded.' : 'This running version exports private host details. Keep its reports local.';
  const d = s.defender || {}, findings = list(data.findings), active = list(s.threats).filter(t => t.IsActive);
  const firewalls = list(s.firewall), firewallOn = firewalls.length > 0 && (!isWindows || firewalls.length === 3) && firewalls.every(f => f.Enabled === true || f.Enabled === 1);
  const protectedNow = d.AntivirusEnabled && d.RealTimeProtectionEnabled && d.BehaviorMonitorEnabled && firewallOn;
  const guide = data.guide || fallbackGuide(s, findings, errors, stale, isWindows, protectedNow);
  renderGuide(data, guide, capabilities);
  $('protection-title').textContent = active.length ? 'Defender detected active threats' : stale ? 'Waiting for a fresh security check' : protectedNow ? 'Your core defenses are active' : 'Check your protection settings';
  $('protection-detail').textContent = protectedNow ? 'Defender is protecting your computer. Sentinel watches for changes and unusual behavior.' : 'Some protections are off or could not be verified. Review the findings below.';
  if (!isWindows) { $('protection-title').textContent = stale ? 'Waiting for a fresh host check' : 'Host monitoring is active'; $('protection-detail').textContent = capabilities.realtime; }
  $('realtime').textContent = 'Real-time · ' + (d.RealTimeProtectionEnabled === true ? 'on' : d.RealTimeProtectionEnabled === false ? 'off' : 'unknown');
  $('firewall').textContent = 'Firewall · ' + (firewallOn ? 'on' : firewalls.length ? 'check' : 'unknown');
  $('behavior').textContent = 'Behavior · ' + (d.BehaviorMonitorEnabled === true ? 'on' : d.BehaviorMonitorEnabled === false ? 'off' : 'unknown');
  if (!isWindows) { $('realtime').textContent = 'Malware blocking · external'; $('behavior').textContent = 'Local model · ' + (data.model.ready ? 'active' : 'learning'); }
  $('last-checked').textContent = 'Last checked ' + date(s.collectedAt);
  $('process-count').textContent = list(s.processes).length;
  $('connection-count').textContent = s.connections === null ? 'Unknown' : list(s.connections).length;
  $('review-count').textContent = findings.length;
  $('finding-count').textContent = findings.length;
  $('model-progress').textContent = data.model.paused ? 'Paused' : data.model.ready ? 'Active' : `${Math.min(100, Math.round(data.model.samples / data.model.warmup * 100))}%`;
  $('model-detail').textContent = `${data.model.samples} samples · ${data.model.processes} process profiles`;
  const findingList = $('finding-list'); findingList.replaceChildren();
  if (!findings.length) findingList.append(node('div', errors.length ? 'No findings in the available checks; some sources are unavailable.' : '✓ No findings in the available checks', errors.length ? 'empty' : 'good'));
  for (const f of findings) { const e = node('article', undefined, 'finding ' + f.severity); e.append(node('strong', f.title), node('p', f.detail), node('small', `${f.source} · ${f.severity}${f.score ? ' · advisory score ' + f.score + '/100' : ''}`)); findingList.append(e); }
  const fields = {}; for (const line of (s.wifiRaw || '').split('\n')) { const idx = line.indexOf(':'); if (idx >= 0) fields[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim(); }
  $('wifi-name').textContent = fields.ssid || 'No connected Wi-Fi verified';
  const weak = /open|wep|tkip/i.test(`${fields.authentication || ''} ${fields.cipher || ''}`);
  $('wifi-badge').textContent = weak ? 'Weak encryption' : /wpa|sae|802\.1x/i.test(fields.authentication || '') ? 'Security reported' : 'Unknown';
  $('wifi-badge').classList.toggle('warning', weak);
  const wifi = $('wifi-details'); wifi.replaceChildren();
  detail(wifi, 'Authentication', fields.authentication || 'Unavailable'); detail(wifi, 'Cipher', fields.cipher || 'Unavailable'); detail(wifi, 'Signal / band', `${fields.signal || '—'} / ${fields.band || '—'}`);
  const adapter = list(s.addresses).find(a => a.interface === fields.name);
  detail(wifi, 'Router', adapter ? list(adapter.gateways).join(', ') || 'Unknown' : 'Unknown');
  const network = $('network-results'); network.replaceChildren();
  if (data.network && data.network.ssid && data.network.ssid !== fields.ssid) network.append(node('p', `Saved discovery belongs to ${data.network.ssid}. Discover devices on the current Wi-Fi to refresh it.`, 'warning'));
  else if (data.network) { network.append(node('p', `${data.network.subnet} · ${list(data.network.devices).length} device / cache entries · ${date(data.network.completedAt)}`)); for (const device of list(data.network.devices)) { const e = node('div', undefined, 'device'); e.append(node('span', device.ip), node('small', device.kind)); network.append(e); } const services = list(data.network.routerServices); network.append(node('p', 'Open router services: ' + (services.map(x => `${x.service} (${x.port})`).join(', ') || 'None responded to these checks'))); if (services.some(x => [21, 23, 445, 3389].includes(x.port))) network.append(node('p', 'Review exposed legacy or remote-access services in your router settings.', 'warning')); }
  const byPid = new Map(list(s.processes).map(p => [p.ProcessId, p.Name]));
  const connections = $('connections'); connections.replaceChildren();
  for (const c of list(s.connections).slice(0, 100)) { const row = node('tr'); row.append(node('td', byPid.get(c.OwningProcess) || `PID ${c.OwningProcess}`), node('td', c.RemoteAddress), node('td', c.RemotePort)); connections.append(row); }
  const scans = $('scan-status'); scans.replaceChildren(); detail(scans, 'Last completed quick scan', date(d.QuickScanEndTime)); detail(scans, 'Last completed full scan', date(d.FullScanEndTime)); detail(scans, 'Definitions updated', date(d.AntivirusSignatureLastUpdated)); detail(scans, 'Tamper protection', d.IsTamperProtected === true ? 'On' : d.IsTamperProtected === false ? 'Off' : 'Unknown');
  if (!isWindows) { scans.replaceChildren(); detail(scans, 'Scanner', capabilities.engine); detail(scans, 'Scope', capabilities.scanScope); detail(scans, 'Real-time blocking', 'Not provided by Sentinel'); }
  const jobs = $('jobs'); jobs.replaceChildren();
  for (const j of list(data.jobs).slice(-6).reverse()) { const result = j.result || {}; const detected = result.engine === 'ClamAV' && result.exitCode === 1; const e = node('div', `${j.action.toUpperCase()} · ${detected ? 'detections reported' : j.status}`, 'job ' + (detected ? 'failed' : j.status)); e.append(node('small', j.error || date(j.finishedAt || j.startedAt))); if (result.engine === 'ClamAV' && j.action === 'scan') { e.append(node('small', `Scanned files: ${result.scannedFiles ?? 'unknown'} · Detections: ${result.detectionCount ?? 'unknown'}`)); if (result.coverage) e.append(node('small', result.coverage)); if (result.errors) e.append(node('small', 'Scanner warnings/errors are present in the private local result.')); } jobs.append(e); }
  const running = list(data.jobs).filter(j => j.status === 'running'); document.querySelectorAll('[data-action]').forEach(button => { button.disabled = running.some(j => j.group === (button.dataset.action === 'network' ? 'network' : 'defender')); });
  const defenderScans = list(data.defenderScans); if (defenderScans.length) detail(scans, 'Latest Defender scan event', `${defenderScans[0].status} · ${date(defenderScans[0].finishedAt || defenderScans[0].startedAt)}`);
  if (defenderScans.some(x => x.status === 'running')) document.querySelectorAll('[data-action="quick"], [data-action="full"]').forEach(button => { button.disabled = true; });
  const archive = $('alert-history'); archive.replaceChildren();
  for (const threat of list(s.threats)) { const e = node('div', `${threat.ThreatName} · ${threat.IsActive === true ? 'active' : threat.IsActive === false ? 'inactive historical detection' : 'current state unknown'}`, 'job'); e.append(node('small', 'Microsoft Defender detection history')); archive.append(e); }
  for (const f of list(data.alertHistory).slice(-8).reverse()) { const e = node('div', f.title, 'job'); e.append(node('small', `${date(f.observedAt)} · ${f.detail}`)); archive.append(e); }
  if (!archive.childNodes.length) archive.append(node('p', 'No detections or recorded review signals.', 'empty'));
  const coverage = $('coverage'); coverage.replaceChildren(); detail(coverage, 'Last completed collection', date(s.collectedAt)); detail(coverage, 'Collection interval', `${data.interval} seconds after each collection`); detail(coverage, 'Model', data.model.ready ? 'Learning from observed process connection counts and destination ports' : 'Learning baseline; rule-based review signals are active');
  if (errors.length) for (const error of errors) coverage.append(node('p', error, 'warning')); else coverage.append(node('p', 'All configured data sources returned successfully.', 'good'));
  for (const note of list(s.coverageNotes)) coverage.append(node('p', note));
  if (capabilities.connectionCoverage) coverage.append(node('p', capabilities.connectionCoverage));
  if (data.model.manualPause) coverage.append(node('p', 'You paused baseline learning. Existing checks continue.', 'warning'));
  if (data.model.paused && !data.model.manualPause) coverage.append(node('p', 'Behavior learning is paused because process or TCP observations are unavailable. Missing data is never learned as zero activity.', 'warning'));
  $('sampling-label').textContent = `SAMPLED AFTER EACH ${data.interval}-SECOND WAIT`;
  SentinelWorkbench.render(data, {api, node, refresh, token});
}
async function refresh() { try { render(await api('/api/status')); } catch (e) { notice(e.message); $('live-state').textContent = 'Disconnected'; if (!token) notice('Open Sentinel with its launcher or --open to reconnect. The dashboard needs its local access link.'); } }
document.querySelectorAll('[data-action]').forEach(button => button.addEventListener('click', async () => { button.disabled = true; try { await api('/api/action', { action: button.dataset.action }); await refresh(); } catch (e) { notice(e.message); button.disabled = false; } }));
$('refresh').addEventListener('click', async () => { try { await api('/api/refresh', { refresh: true }); await refresh(); } catch (e) { notice(e.message); } });
$('export').addEventListener('click', async () => { try { const report = await api('/api/report'); const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })); const a = node('a'); a.href = url; a.download = 'sentinel-security-report.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); } catch (e) { notice(e.message); } });
$('prepare-ai').addEventListener('click', async () => {
  $('prepare-ai').disabled = true;
  try {
    if (latest?.system && latest?.guide) {
      const handoff = await api('/api/assistant'); $('ai-prompt').value = handoff.prompt;
    } else {
      // Never use this older monitor's private export or raw status in a handoff.
      $('ai-prompt').value = 'Help me use Sentinel Local in plain language. It monitors locally and uses the platform antivirus engine to scan. If you have authorized local terminal access, begin with python app.py --diagnose in the updated project. Only run python app.py --scan quick on Windows if I explicitly request it. For Linux/macOS explain selected-folder scanning first. Do not inspect Downloads, upload files or raw logs, change security settings, remove files, or publish anything without my specific instruction. A chat-only assistant cannot scan my computer. Return only a sharing-safe summary. This generic prompt contains no system observations.';
    }
    $('copy-ai').disabled = false; $('ai-status').textContent = 'Prompt prepared locally. Review it before copying. Nothing has been sent.';
  } catch (e) { $('ai-status').textContent = 'Could not prepare a safe prompt. Use python app.py --assistant-prompt from the updated source. ' + e.message; }
  finally { $('prepare-ai').disabled = false; }
});
$('copy-ai').addEventListener('click', async () => { try { await navigator.clipboard.writeText($('ai-prompt').value); $('ai-status').textContent = 'Copied to your clipboard. Paste into your chosen assistant only when you are ready to share this summary.'; } catch { $('ai-status').textContent = 'Select the prompt above and copy it manually.'; } });
async function loadAiOptions() {
  try {
    const options = await api('/api/ai/options'); const selector = $('ai-provider'); selector.replaceChildren();
    for (const provider of options.providers) { const option = node('option', `${provider.name}${provider.installed ? '' : ' · unavailable'}${provider.supported ? '' : ' · integration pending'}`); option.value = provider.id; option.disabled = !provider.installed || !provider.supported; selector.append(option); }
    selector.value = 'ollama'; const models = $('ai-model'); models.replaceChildren(); models.disabled = false;
    $('cloud-consent').hidden = true; $('allow-cloud-ai').checked = false; evidencePreviewed = false; aiPreviewToken = '';
    for (const model of options.localModels) { const option = node('option', `${model.name} · ${(model.size / 1024**3).toFixed(1)} GB`); option.value = model.name; models.append(option); }
    if (!options.localModels.length) models.append(node('option', 'No downloaded local model detected'));
    $('direct-ai-status').textContent = options.note;
  } catch { $('direct-ai-status').textContent = 'AI tool detection failed. No model was run.'; }
}
$('refresh-ai-tools').addEventListener('click', loadAiOptions);
$('test-ai').addEventListener('click', async () => {
  const provider = $('ai-provider').value, cloud = provider !== 'ollama';
  if (cloud && !$('allow-cloud-ai').checked) { $('direct-ai-status').textContent = 'Explicitly consent to the selected provider test first. Only fictional evidence will be sent; account usage may apply.'; return; }
  $('test-ai').disabled = true;
  try { await api('/api/ai/check', {provider, model: cloud ? '' : $('ai-model').value, allowCloud: cloud && $('allow-cloud-ai').checked}); $('allow-cloud-ai').checked = false; $('direct-ai-status').textContent = 'Connection test started with fictional data. No host check or malware scan is performed by this test.'; await refresh(); }
  catch (e) { $('direct-ai-status').textContent = e.message; $('test-ai').disabled = false; }
});
$('ai-provider').addEventListener('change', () => { const local = $('ai-provider').value === 'ollama'; $('cloud-consent').hidden = local; $('ai-model').disabled = !local; $('allow-cloud-ai').checked = false; evidencePreviewed = false; aiPreviewToken = ''; $('ai-evidence').textContent = 'Preview evidence for this provider before requesting a cloud review.'; $('direct-ai-status').textContent = local ? 'Local AI selected. Choose a downloaded model and run a review when ready.' : 'Cloud AI selected. Preview anonymous evidence and explicitly consent before running a review.'; });
$('preview-evidence').addEventListener('click', async () => { try { const preview = await api('/api/ai/preview', {provider: $('ai-provider').value}); $('ai-evidence').textContent = JSON.stringify(preview.evidence, null, 2); aiPreviewToken = preview.previewToken; evidencePreviewed = true; $('ai-evidence').closest('details').open = true; $('direct-ai-status').textContent = 'Anonymous evidence prepared locally. Program identity mapping stays on this computer.'; } catch (e) { $('direct-ai-status').textContent = e.message; } });
$('run-ai').addEventListener('click', async () => {
  const provider = $('ai-provider').value, cloud = provider !== 'ollama';
  if (cloud && (!evidencePreviewed || !$('allow-cloud-ai').checked)) { $('direct-ai-status').textContent = 'Preview the anonymous evidence and explicitly consent to the selected cloud provider first.'; return; }
  $('run-ai').disabled = true;
  try { await api('/api/ai/review', {provider, model: cloud ? '' : $('ai-model').value, allowCloud: cloud && $('allow-cloud-ai').checked, previewToken: aiPreviewToken}); evidencePreviewed = false; aiPreviewToken = ''; $('allow-cloud-ai').checked = false; $('direct-ai-status').textContent = 'AI review started. No malware scan, file removal, or security-setting change was requested.'; await refresh(); }
  catch (e) { $('direct-ai-status').textContent = e.message; $('run-ai').disabled = false; }
});
SentinelWorkbench.init({api, node, refresh, token});
refresh(); setInterval(refresh, 5000);

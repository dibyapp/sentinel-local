# Direct AI security review

Sentinel asks an installed AI tool to review anonymous security indicators. This follows AutoWork's architecture: explicit provider selection, fixed arguments, stdin prompts, structured results, vendor-owned authentication, and no silent fallback. Sentinel does not import AutoWork, execute its workflows, read its credentials, or copy its runtime data.

## Simple local use

1. Open Sentinel and refresh the status.
2. Open **AI security review**, choose **Ollama (local)** and an already downloaded model. Select **Test AI connection** to check its contract with fictional evidence; this test does not collect the host or affect findings. Preview anonymous host evidence before a review if you want to inspect it.
3. Select **Run AI review**. Read the advisory findings and their coverage. Failed or unsupported results stay unverified.

```text
python app.py --ai-review ollama --ai-model qwen3:1.7b
```

The model must already exist in Ollama. Sentinel does not download models, restart Ollama, install tools, or start a native malware scan during AI review. The CLI exits after review and prints anonymous references; the dashboard resolves those references using its private application-name mapping.

Local inference uses the fixed IPv4 loopback Ollama endpoint, bypasses HTTP proxies, refuses redirects, rejects cloud model tags and remote aliases, and verifies downloaded model metadata. Generation uses two threads, a bounded context/output, a three-minute timeout, and immediate model unloading. These limits reduce overhead but are not an OS resource quota. `auto` selects Ollama only; it never switches to a cloud provider.

## Provider coverage

| Provider | Review mode | Validation status |
| --- | --- | --- |
| Ollama | Downloaded local model; no tools | Live local review validated with `qwen3:1.7b`; small models may return rejected results |
| Codex | Opt-in cloud CLI; read-only, ephemeral, ignored user config, tools/features disabled | Live fictional-evidence review and regression tests passed |
| Claude Code | Opt-in cloud CLI; empty tools, strict empty MCP, safe mode, no session persistence | Live fictional-evidence review and regression tests passed |
| Gemini CLI | Dedicated Sentinel vendor profile; denied tools, disabled hooks/extensions/memory | Restriction and authentication-failure tests; vendor sign-in required before live inference |
| Compatible model server | Private profile, structured chat-completions protocol, no tools/redirects | Contract tests; verify each selected server/model with Test AI connection |
| Trusted custom CLI | Private argument-array profile; anonymous stdin, JSON stdout | Extensible wrapper contract; its own permissions must be verified |
| Other chat assistants | Reviewed manual summary prompt | Manual fallback for tools without a compatible headless interface |

Detection checks PATH, bundled Codex locations, and AutoWork's managed tool directories. Detection does not prove authentication or support for the restrictions. An unsupported flag, account problem, blocked request, invalid result, or timeout fails closed. There is no permissive retry or alternative provider.

For Codex or Claude, select the provider, preview the exact evidence, then check the explicit cloud consent box. A short-lived single-use token binds that preview to that provider. Sentinel sends precisely that preview. CLI users explicitly opt in with `--allow-cloud-ai`:

```text
python app.py --ai-review codex --allow-cloud-ai
python app.py --ai-review claude --allow-cloud-ai
```

Cloud providers receive counts, protection booleans, anonymous evidence IDs, and indicator flags. They do not receive executable names, file contents, command lines, paths, IP/MAC addresses, SSIDs, hostnames, usernames, tokens, raw errors, or identity mappings from Sentinel. The selected vendor CLI still uses its own authentication, account, billing, and service metadata policies; Sentinel cannot make those clients anonymous. No API key is requested or copied into source. Inherited project secrets and endpoint overrides are removed from the child environment. Cloud review can consume account usage.

## Add another provider

Keep provider profiles in a private file outside the checkout. They are never part of release archives. Only a file explicitly selected with `--ai-config` is loaded. Profiles cannot override built-in providers or execute through a shell.

For a server supporting structured chat completions, use a profile like this:

```json
{"profiles":[{"id":"my-model-server","kind":"openai-compatible","label":"My selected model server","base_url":"http://127.0.0.1:1234/v1","model":"your-installed-model","api_key_env":"SENTINEL_MODEL_TOKEN"}]}
```

Replace the model and endpoint with those you select. HTTPS is required except for literal loopback addresses. The optional `api_key_env` names an environment variable; never put the key itself in the profile. No proxies or redirects are allowed. The server must support the structured-output schema and return a single completed response without tool calls. A server may proxy cloud inference even when its address is local, so these profiles require explicit consent. [LM Studio structured output](https://lmstudio.ai/docs/developer/openai-compat/structured-output) describes one compatible protocol; model support still needs testing.

```text
python app.py --ai-config /private/provider-profiles.json --ai-check my-model-server --allow-cloud-ai
python app.py --ai-config /private/provider-profiles.json --open
```

Use an existing absolute private path on your own OS. **Test AI connection** sends fictional evidence, collects no host observations, and never affects security findings. It verifies that particular tool/model's response contract, not malware-detection accuracy.

After changing profiles, close your Sentinel monitor before relaunching it. A verified monitor is reused only when its release and settings match. For independent configurations, use different private `--data-dir` folders and explicit `--port` values; sharing runtime storage across monitors can corrupt history.

A trusted headless wrapper can instead use:

```json
{"profiles":[{"id":"my-ai-wrapper","kind":"cli","label":"My trusted AI wrapper","argv":["/absolute/path/to/wrapper","--schema","{schema}","--workspace","{workspace}"],"trusted_inference_only":true}]}
```

The wrapper receives the anonymous prompt on stdin, writes only the review JSON object to stdout, and accepts a temporary schema/workspace. Arguments are passed literally; commands, shell scripts, prompt interpolation, and automatic installs are not supported. Sentinel validates results and filters the child environment, but cannot enforce an arbitrary wrapper's tools, hooks, subprocesses, network use, or filesystem permissions. Set the trust acknowledgement only after verifying its inference-only behavior. GUI-only assistants use the manual handoff. No universal assistant integration is claimed.

## Gemini sign-in

Run a fictional connection test first to create Sentinel's restricted Gemini profile. An authentication-required result is expected until you sign in with the vendor. On Windows, for the default runtime location:

```powershell
$env:GEMINI_CLI_HOME = Join-Path $env:LOCALAPPDATA 'SentinelLocal\gemini-profile'
gemini
```

Follow Gemini's own interactive sign-in. For a custom `--data-dir`, select its `gemini-profile` subfolder instead. Linux defaults to the XDG state directory's `sentinel-local/gemini-profile`; macOS defaults to the user's Application Support `SentinelLocal/gemini-profile`. The adapter preserves only the vendor-selected authentication method and leaves credentials owned by Gemini. It never copies a shared profile or signs in automatically. Existing enterprise system settings/policies cause the adapter to refuse invocation rather than override them. The adapter denies tool calls and disables hooks, extensions, skills, memory filenames, project environment loading, and directory-tree context; its dedicated profile is not an OS sandbox.

## Evidence and result boundaries

The read-only collector samples protections, processes, TCP connections, startup entries, and Wi-Fi metadata. Evidence is limited to 24 anonymous references. Windows additionally checks at most 12 executable signatures for selected candidates; Downloads paths are excluded. Coverage records omitted candidates and that no file-content malware scan occurred. Stale, future-dated, or failed host status cannot be reviewed.

Structured generation limits each reason to a supported evidence pair. Validation independently rejects invented references, unsupported reasons, false indicators, extra fields, executable instructions, inconsistent assessments, and excessive findings. The dashboard renders static explanations with locally retained aliases. Model output cannot become a command, deletion, quarantine, setting change, trust decision, or clean-computer certification. A valid signature does not prove safety; an unsigned application does not prove malware.

Each completed review is bound to an exact private snapshot fingerprint. The fingerprint is local metadata and is never sent to a provider. A new observation, failed collection, stale/unknown freshness or baseline restart/restore makes the prior review historical; it remains in the journal but cannot represent current evidence. A fresh result does not trigger an automatic follow-up AI request. Review and snooze controls affect only the advisory queue, never malware protection or status totals.

AI review supports investigation. Microsoft Defender or another validated engine remains responsible for malware scanning and blocking. Sampled TCP activity cannot detect every infection, short-lived process, UDP activity, unsafe router configuration, or malware on another Wi-Fi device. Missing visibility and failed inference remain explicit.

## Privacy and contribution

Evidence mappings, AI results, host reports, errors, model state, and screenshots remain in private runtime storage. They are excluded from public exports and the release manifest. Use only fictional fixtures in tests, issues, and screenshots. Before sharing source or binaries, run the release privacy gate and inspect the exact archive. Do not publish runtime storage or Git history.

Provider contracts were checked against [Codex non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode), [Claude CLI reference](https://code.claude.com/docs/en/cli-reference), [Ollama chat API](https://docs.ollama.com/api/chat), and [Gemini policy engine](https://geminicli.com/docs/reference/policy-engine/). CLI versions and restrictions require ongoing native validation.

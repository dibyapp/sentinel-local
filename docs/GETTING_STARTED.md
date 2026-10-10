# Start Sentinel in three steps

1. **Open Sentinel.** On Windows, double-click `Open-Sentinel.cmd` in the source folder. For a native executable, open it to start the dashboard automatically. Linux/macOS source users run `sh start-sentinel.sh`. The source launchers prefer the project's virtual environment and explain missing dependencies; they do not install software automatically.
2. **Read the status.** Sentinel detects Windows, Linux, or macOS and selects its adapter. It reads available protections, processes, TCP activity, and Wi-Fi metadata automatically. Missing permissions/tools are shown as unknown. Monitoring updates without repeated clicks.
3. **Scan when you are ready.** Windows uses the **Run quick scan** button for Microsoft Defender. Linux/macOS show **Scan selected folders** only when ClamAV and explicit scan roots are available. Full scans are under Advanced and may use substantial disk resources. Scan history shows completion, failure, or an unverified result.

No malware scan, Wi-Fi device discovery, download inspection, security-setting change, or file deletion starts just because the dashboard opens. Leave resource-heavy scans until your downloads and other work permit them. The monitor only samples observations; the OS engine remains responsible for real-time blocking.

## Understand a finding

- **Active native detection:** the antivirus engine reports a current threat. Review its protection history and follow its instructions.
- **Inactive historical detection:** a past record. It does not show a current infection and does not prove every previously detected file was removed.
- **Advisory behavior signal:** an unusual observation to review, not a malware verdict.
- **Unknown:** a check could not be verified; review Monitor health.
- **No current issues in available checks:** the visible checks found no issue. This is not a clean-computer certificate.

## Use any AI assistant

Open **AI security review**, choose **Ollama (local)** and a downloaded model, then select **Run AI review**. No model download or malware scan starts. Sentinel verifies local model metadata, sends only anonymous indicator flags, and validates every proposed finding against collected evidence. Read [Direct AI review](AI_REVIEW.md) for coverage and CLI commands.

Codex and Claude CLI are optional cloud providers. Select one, preview the exact anonymous evidence, then explicitly consent before starting. Gemini uses a dedicated restricted profile and requires vendor sign-in. Compatible model servers and trusted inference wrappers can be added with a private `--ai-config` profile. Use **Test AI connection** with fictional evidence first; see the setup instructions in [Direct AI review](AI_REVIEW.md). Tool detection does not verify an account, model, subscription, or installed CLI behavior. No API key is requested and no AI inference starts automatically.

For any other assistant, expand **Manual handoff → Generate summary prompt**, read the text, then copy it into the assistant you choose. No assistant is launched or connected through that manual handoff.

The generated prompt contains summary counts and boolean protection flags. Usernames, computer names, command lines, process paths, network addresses, Wi-Fi names, tokens, raw errors, and logs are excluded. The older running prototype receives a generic prompt with no observations. You decide whether to share the reviewed text; cloud assistants may process what you paste according to their own policies. Do not attach private runtime files or real system screenshots to public issues.

A chat-only assistant can explain results. An assistant with authorized local terminal access can invoke the native scanner through fixed CLI options. Open this source project in the assistant, then request the read-only check:

```text
python app.py --diagnose
```

If you specifically want a Windows quick scan:

```text
python app.py --scan quick
```

On Linux/macOS, first install ClamAV with current definitions from the OS package manager. Select an existing absolute folder you intend to scan:

```text
python app.py --scan selected --scan-root /opt/fictional-scan-folder
```

Replace the fictional path with a folder you explicitly choose. No automatic home, whole-disk, or Downloads scan is supplied. The one-shot command prints a sharing-safe result and exits; it does not start a new monitoring service. Raw scanner results remain in private local state. A completed command does not establish malware-detection efficacy or complete coverage.

Generate a reviewed handoff from the command line with:

```text
python app.py --assistant-prompt
```

It performs a read-only host check and prints the safe prompt without contacting an assistant. Installed assistants are not automatically trusted to run arbitrary commands. The prompt asks them to obtain specific instructions before scanning, changing settings, removing files, inspecting Downloads, or publishing.

Official Codex guidance: [Codex CLI](https://learn.chatgpt.com/docs/codex/cli) and [security and approvals](https://learn.chatgpt.com/docs/security). These describe a local coding assistant; Sentinel's malware scans still use the native scanning engine. The same manual handoff can be used with any other assistant.

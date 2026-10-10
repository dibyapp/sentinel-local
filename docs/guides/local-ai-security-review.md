# Private local AI security review with Ollama

Use an already installed Ollama model to explain sampled security indicators without sending program identities or host files to a cloud AI service. Core monitoring also works with no AI tool at all.

1. [Open Sentinel](../INSTALLATION.md) and read collection health.
2. Choose **Ollama local** and a model already downloaded in your own Ollama installation.
3. Select **Test AI connection**. This sends fictional evidence, collects no host observations, and leaves findings unchanged.
4. Preview anonymous host evidence, then select **Run AI review** when ready.
5. Read the advisory explanation and coverage. Invalid or unsupported output remains unverified.

The adapter verifies local model metadata, uses a fixed loopback endpoint, bypasses proxies, refuses redirects, and rejects cloud model aliases. It does not pull a model, install tools, scan file contents, or change protection settings. Small models can return inaccurate/invalid results and be rejected; there is no permissive fallback.

Only counts, booleans, anonymous IDs, and supported indicator flags enter the prompt. Local private state maps the IDs back to application names for the dashboard. Structured output is independently validated against current evidence; unsupported reasons and invented IDs are rejected. A valid response is an advisory review, not an antivirus verdict.

Codex, Claude Code, Gemini CLI, compatible servers, and trusted wrappers have separate contracts. Cloud or potentially forwarding endpoints need explicit consent and an evidence preview. Vendor clients retain their own account/authentication metadata policies. [Full provider setup and limitations](../AI_REVIEW.md).

For interpretation, read [connection activity](connection-activity.md). A fixed connection threshold can flag legitimate browser/AI work, especially before a meaningful baseline exists.

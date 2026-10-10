# Sentinel Local keyword and search-intent research

Research date: **11 October 2026**. Scope: public search results, official project documentation, GitHub discovery guidance, and the implemented feature set. This is qualitative search-intent research. No paid keyword-volume, clickstream, Google Search Console, or rank-tracker dataset was available. Search volume, keyword difficulty, conversion, rankings, and future stars are **unknown**, not estimated facts.

## Positioning decision

Lead with **local AI security monitor**, **Windows Defender dashboard**, and **private endpoint monitoring**. These describe actual functions and a specific audience: individual developers, privacy-conscious desktop users, and contributors evaluating explainable security signals. Use **open-source AI antivirus** as an explanatory FAQ query with the engine boundary stated immediately. Broad antivirus searches often imply guaranteed prevention, automatic remediation, or a replacement engine that this project does not provide.

Keep the established brand and short repository slug `sentinel-local`. Search results also include Sentinel-named antivirus projects, and Microsoft's security ecosystem uses Sentinel terminology. Pair the brand with a descriptive purpose in every introduction to reduce ambiguity. This is naming/search-intent judgment, not a trademark clearance or search-volume measurement.

Google emphasizes useful content and descriptive organization; effects can take weeks or months. Apply that by answering concrete setup and interpretation questions with working examples, linked guides, and original fictional screenshots. Do not mass-produce keyword pages or publish private monitoring data. [Google SEO starter guide](https://developers.google.com/search/docs/fundamentals/seo-starter-guide), [people-first content guidance](https://developers.google.com/search/docs/fundamentals/creating-helpful-content).

## Search-result observations

The queried families included open-source antivirus on Windows; Windows Defender dashboards; local AI security monitoring; private endpoint monitoring; ClamAV desktop dashboards; Wi-Fi security monitors; and Ollama antivirus/security monitoring. Broad families led to antivirus engines, enterprise security platforms, LLM application security, wireless attack tools, and installation false-positive discussions. The exact “Ollama antivirus” family was particularly ambiguous: results included antivirus alerts on Ollama binaries and model-install troubleshooting rather than endpoint review.

These observations favor explicit intent over broad claims. They do not establish low competition, an underserved market, or numerical keyword demand. Search results vary by date, geography, personalization, and query wording.

| Primary reference | What its own documentation describes | Implication for Sentinel content |
| --- | --- | --- |
| [Wazuh platform](https://wazuh.com/platform/overview/) | XDR/SIEM platform | Explain the individual desktop audience; avoid positioning as enterprise XDR |
| [osquery](https://osquery.io/) | Queryable endpoint/OS instrumentation | Explain readable sampled findings and the simpler local dashboard |
| [ClamAV](https://docs.clamav.net/) | Antivirus scanning engine | State that Sentinel integrates scanning rather than supplying signatures |
| [ClamAV Desktop](https://github.com/ivangabriele/clamav-desktop) | Desktop GUI for ClamAV | Use accurate folder-scan/control keywords; avoid claims about full daemon configuration |
| [Aegis Antivirus](https://github.com/rounak1434/aegis-antivirus) | Windows scanner/antivirus project | Distinguish a protection companion from an independent engine |
| [SentinelXP](https://github.com/C0m3b4ck/SentinelXP) | Sentinel-branded Windows antivirus project | Always attach “Local” and the monitoring purpose to the brand |
| [PromptGuard](https://github.com/Mayankpawar28/promptguard-llm-security-gateway) | LLM application/gateway security | “AI security” alone can attract the wrong intent; specify endpoint observations |

These are intent references, not independently audited benchmarks, endorsements, or competitors whose code/claims were validated.

## Keyword priorities and content map

Priority reflects **feature fit and actionable intent**, not volume or predicted ranking. P1 belongs in the README, repository description, and a substantive guide. P2 supports documentation and FAQs. P3 requires careful scope language; avoid it as a headline promise.

| Query or phrase | Intent | Priority | Best destination / accurate answer |
| --- | --- | --- | --- |
| local AI security monitor | Find a private endpoint tool | P1 | README + local AI guide |
| Windows Defender dashboard | View protection and scan controls | P1 | Windows guide + installation |
| private endpoint monitoring | Find privacy-conscious monitoring | P1 | README privacy section |
| open source security monitor | Evaluate source and capability | P1 | README + architecture |
| Windows Defender companion | Extend status visibility | P1 | Windows guide; Defender remains the engine |
| local endpoint security dashboard | See host checks in one place | P1 | Overview screenshot + README |
| Ollama security review | Explain collected indicators locally | P1 | Local AI guide; no file-content scan |
| local LLM security monitoring | Evaluate model-assisted endpoint review | P1 | AI review and evidence boundaries |
| private AI security assistant | Explain results without raw logs | P1 | Local AI guide + privacy |
| open source Windows security dashboard | Install an inspectable desktop tool | P1 | Windows installation |
| explainable endpoint alerts | Understand findings | P1 | Connection activity guide |
| AI security review without uploading files | Protect private evidence | P1 | AI guide and provider contracts |
| Microsoft Defender quick scan dashboard | Run a user-requested quick scan | P2 | Windows scan guide |
| Defender scan completed or failed | Interpret engine result | P2 | Windows guide + scan workflow |
| security monitor no telemetry | Evaluate privacy design | P2 | SECURITY.md + privacy section |
| process network connection monitor | Attribute sampled TCP activity | P2 | Connection activity guide; no bandwidth accounting |
| high TCP connections normal browser | Investigate a noisy signal | P2 | Connection guide; threshold is advisory |
| Claude many network connections | Understand expected tool activity | P2 | Connection guide with fictional app examples |
| AI antivirus false positives | Understand limitations | P2 | FAQ + connection guide |
| Wi-Fi security monitor | Review connected network metadata | P2 | Wi-Fi guide |
| Wi-Fi health dashboard | Read encryption and visibility | P2 | Wi-Fi screenshot + guide |
| local Wi-Fi device discovery | Find responding local devices | P2 | Bounded /24 discovery explanation |
| router open ports check | Review nine selected TCP services | P2 | Wi-Fi guide; no WAN/firmware audit |
| WPA2 WPA3 Wi-Fi security check | Read reported authentication | P2 | Wi-Fi guide; no independent cryptographic audit |
| ClamAV selected folder scan | Scan a chosen folder | P2 | ClamAV guide |
| ClamAV dashboard Linux | Start supported folder scans | P2 | Linux installation + ClamAV guide |
| ClamAV scan GUI macOS | Explore experimental source flow | P2 | Clearly labeled macOS source support |
| Python security dashboard | Develop or inspect implementation | P2 | Architecture + setup helper |
| open source security tool beginner | Get a clear first run | P2 | Three steps + fictional screenshots |
| Codex security review tool | Use a selected vendor adapter | P2 | Provider guide; cloud consent required |
| Claude Code security review | Test inference-only adapter | P2 | Provider guide; explicit cloud consent |
| Gemini CLI security monitoring | Configure restricted profile | P2 | Dedicated profile and authentication steps |
| LM Studio security review | Configure compatible endpoint | P2 | Model-server profiles; test schema support |
| OpenAI compatible security assistant | Configure selected model server | P2 | Private profile documentation |
| security monitoring without cloud AI | Use core monitor / local model | P2 | README and local AI guide |
| open source AI antivirus | Compare prevention and monitoring | P3 | FAQ: native engine supplies detection/blocking |
| free antivirus for all platforms | Find turnkey protection | P3 | Poor fit: do not promise universal support |
| open source EDR replacement | Replace managed endpoint response | P3 | Poor fit: no enterprise prevention/response claim |
| Wi-Fi penetration testing tool | Attack/assess wireless protocols | P3 | Poor fit: no exploit/capture features |
| automatic malware removal AI | Expect autonomous remediation | P3 | Unsupported; AI never removes files |
| Android AI antivirus / iPhone antivirus | Find mobile protection | P3 | Outside desktop scope |
| best antivirus / guaranteed protection | Seek validated protection | P3 | Unsupported ranking/efficacy claim |

## Metadata implemented

- Repository: **sentinel-local**.
- README heading: **Sentinel Local — Local AI Security Monitor & Windows Defender Dashboard**.
- About description: **Open-source local AI security monitor and Windows Defender dashboard. Private endpoint and Wi-Fi checks, Ollama review, optional ClamAV scans. Desktop beta.**
- Topics: `endpoint-security`, `security-monitoring`, `windows-defender`, `clamav`, `wifi-security`, `network-monitoring`, `privacy`, `local-ai`, `ollama`, `python`, `windows`, `linux`, `macos`, `open-source`, `anomaly-detection`, `security-tools`.
- Original screenshot alt text describes the actual fictional UI, not an invented protection score.
- Source pages link to installation, provider coverage, specific guides, security, and contributions. The private dashboard remains `noindex,nofollow`.

GitHub topics improve classification and topic-based discovery; they do not promise search placement. Stay below the platform's 20-topic limit and use relevant lowercase topic names. [GitHub topic documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics).

## Measurement and iteration

After publication, inspect repository traffic, clones, referring sources, release downloads, and stars at days 7, 14, and 30. GitHub traffic has a limited retention window, so record aggregate snapshots privately if longer comparison is wanted. [GitHub repository traffic](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-traffic-to-a-repository).

If a public informational site is authorized later, verify it in Search Console before making query-impression claims. Use observed impressions to refine terms and answer actual questions. Keyword Planner or a licensed keyword dataset can supplement demand analysis when access is available; no such figures are claimed here. [Google Keyword Planner](https://support.google.com/google-ads/answer/7337243).

The 100-star goal is a target rather than a forecast. Installation success, useful docs, credible scope, and contributor responsiveness are controllable. Indexing, external attention, adoption, and stars are not. See the [30-day discovery plan](LAUNCH_PLAN.md).

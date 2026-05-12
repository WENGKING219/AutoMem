# Report Skill: Forensic Report Template

Use this when the user asks for a formal report. Follow the template exactly.

## Tools cited in this template

Plugin sources allowed in the Source columns: `get_image_info`, `pslist`,
`psscan`, `pstree`, `psxview`, `cmdline`, `netscan`, `malfind`, `dlllist`,
`handles`, `svcscan`, `amcache`. Reporting helper: `save_report`. Use
`query_plugin_rows` for drill-downs; cite the underlying plugin name in
the Source column, not `query_plugin_rows`.

## Hard rules

1. Match the user's report scope: triage, full case, network, malware, or execution history.
2. Every claim must trace back to a Volatility tool call made this turn or earlier in the thread. Reuse evidence already collected in the conversation rather than re-running plugins.
3. Use the exact local analysis time injected by the harness. Do not guess the date.
4. Confidence values must be High, Medium, or Low.
5. Keep normal report generation within 8 Volatility tool calls before `save_report`. In long sessions where evidence is already collected, target 0-4 new calls.
6. Only Amcache `SHA1` values are real file hashes - list them directly in the IOC table and Section 8. Do NOT hash indicator strings (paths, commands, IPs, service names); list them verbatim.
7. VirusTotal file lookups are appropriate only for real file hashes (e.g. amcache SHA1). If no real file hashes were collected, write "No suspicious evidence hashes were generated in this pass."
8. Write the full Markdown report first. Then call `save_report`.
9. Skip plugins the OS does not support (e.g. `netscan`/`amcache` on XP). Document the gap as a limitation rather than retrying.
10. Before claiming a tool was "not run", search the conversation history. If a previous turn already executed the tool, cite that result instead of reporting it as missing.
11. The IOC Summary Table is for indicators of compromise only. Do NOT include standard system processes (`lsass.exe`, `svchost.exe`, `services.exe`, etc.) unless they show concrete suspicious behavior (wrong path, wrong parent, anomalous network, injected memory). "Standard system process" is not an IOC.

## Filling discipline

- If a section has no findings, write "No suspicious activity detected" or "Evidence not collected in this pass."
- Sort suspicious finding tables by confidence, High first.
- Cite plugin names in source columns.
- Copy IPs, ports, paths, command lines, account names, and hashes verbatim.
- Remove all placeholders before saving. Never save text containing `[Current Date/Time]`, `[Summary of ...]`, `{event}`, or similar template markers.

## Template

```markdown
# Memory Forensics Analysis Report

**Date**: {exact_local_analysis_time}
**Analyst**: Memory Forensics Agent (AI)
**Memory Dump**: {dump_filename}
**OS Profile**: {detected_os_or_unknown}

---

## 1. Executive Summary

{4_to_6_sentence_bottom_line}

**Overall Risk Assessment**: {Low | Medium | High | Critical}

---

## 2. System Profile

| Property | Value | Source |
|---|---|---|
| OS Version | {os_version_from_ntbuildlab} | get_image_info |
| NTBuildLab | {ntbuildlab} | get_image_info |
| Capture/System Time | {time_or_unknown} | get_image_info |
| Architecture | {x86_or_x64_or_unknown} | get_image_info |

---

## 3. Process Analysis

| PID | Name | PPID | Anomaly | Confidence | Source |
|---|---|---|---|---|---|
| {pid_or_none} | {name} | {ppid} | {reason} | {High/Medium/Low} | {pslist/psscan/pstree/psxview} |

---

## 4. Network Analysis

| Foreign Address | Port | State | PID | Process | Confidence | Source |
|---|---:|---|---:|---|---|---|
| {addr_or_none} | {port} | {state} | {pid} | {process} | {High/Medium/Low} | netscan |

---

## 5. Persistence & Execution History

Service entries from `svcscan`, plus notable executables seen in `amcache`
(executions from user-writable paths, unfamiliar publishers, recent
InstallDates). On Windows XP `amcache` is unavailable - write
"Evidence not collected (plugin unsupported on this OS)" instead.

| Mechanism | Detail | Confidence | Source |
|---|---|---|---|
| {service_or_executable_or_none} | {binary_path_sha1_or_reason} | {High/Medium/Low} | svcscan / cmdline / amcache |

---

## 6. Injection / Code Analysis

| PID | Process | Finding | Disposition | Confidence | Source |
|---:|---|---|---|---|---|
| {pid_or_none} | {process} | {malfind_summary} | {Confirmed/Likely FP/Needs validation} | {High/Medium/Low} | malfind |

---

## 7. IOC Summary Table

Use one row per indicator. Type can be `process`, `network`, `path`,
`service`, or `file_hash` (e.g. amcache SHA1). Skip standard system
processes unless they show concrete suspicious behavior.

| Type | Value | Confidence | Context | Source |
|---|---|---|---|---|
| {process/network/path/service/file_hash/string_hash} | {value} | {High/Medium/Low} | {why_it_matters} | {pslist/netscan/svcscan/amcache/...} |

---

## 8. Evidence Hashes / VirusTotal Lookup Notes

| Source File / Path | SHA1 | VirusTotal Use |
|---|---|---|
| {amcache_path} | {sha1_from_amcache} | yes |

Notes:
- Amcache `SHA1` values come from file bytes - they are real file hashes
  and are appropriate for VirusTotal lookups. Note: Volatility3's amcache
  plugin parses Win8/Win10 keys, so on Windows 7 the result is usually
  empty and on XP the call is refused.
- If no Amcache SHA1 hashes were collected, write: "No suspicious evidence
  hashes were generated in this pass."

---

## 9. Recommendations

1. {specific_next_step}
2. {specific_next_step}
3. {specific_next_step}

---

## 10. Limitations

- Plugins run: {list}
- Plugins not run and why: {list_or_none}
- Truncated outputs: {plugin_names_or_none}
- Evidence caveats: {limitations}
```

## Sanity checks before calling `save_report`

- Does the executive summary state the bottom line?
- Does every suspicious row have evidence, confidence, and source?
- Is OS identification based on NTBuildLab, not the Major/Minor row alone?
- Did you list amcache SHA1 hashes (if any) or state that no suspicious file hashes were collected?
- Are clean system processes (lsass.exe, svchost.exe, services.exe with no anomaly) excluded from the IOC table?
- For every "X was not run" statement, did you check earlier turns to confirm it really was not run?
- Are all placeholders removed?
- Is the date the exact harness-provided local time?

If all checks pass, call `save_report(memory_dump="<dump_name>", content="<the markdown above>")`. The harness picks the canonical filename automatically - do not pass `filename`.

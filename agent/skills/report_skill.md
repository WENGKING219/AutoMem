# Report Skill: Forensic Report Template

Use this when the user asks for a formal report. Follow the template exactly.

## Tools cited in this template

Plugin sources allowed in the Source columns: `get_image_info`, `pslist`,
`psscan`, `pstree`, `psxview`, `cmdline`, `netscan`, `malfind`, `dlllist`,
`handles`, `svcscan`, `amcache`. Reporting helpers: `hash_evidence`,
`save_report`. Use `query_plugin_rows` for drill-downs; cite the underlying
plugin name in the Source column, not `query_plugin_rows`.

## Hard rules

1. Match the user's report scope: triage, full case, network, malware, or execution history.
2. Every claim must trace back to a Volatility tool call made this turn or earlier in the thread. Reuse evidence already collected in the conversation rather than re-running plugins.
3. Use the exact local analysis time injected by the harness. Do not guess the date.
4. Confidence values must be High, Medium, or Low.
5. Keep normal report generation within 8 Volatility tool calls before `save_report`. In long sessions where evidence is already collected, target 0-4 new calls.
6. If suspicious evidence exists, call `hash_evidence` on the exact suspicious indicator strings (paths, commands, IPs, service names) and include its output. Amcache `SHA1Hash` values are real file hashes — do not pass them through `hash_evidence`; list them directly.
7. Clearly label hash types:
   - file hash: a real SHA1 from `amcache`, or another value derived from file bytes
   - indicator-string hash: hash of a path, command, IP, service name, or other exact text indicator
8. VirusTotal file lookups are appropriate for real file hashes (e.g. amcache SHA1). Do not present path-string hashes as file hashes.
9. Write the full Markdown report first. Then call `save_report`.
10. Skip plugins the OS does not support (e.g. `netscan`/`amcache` on XP). Document the gap as a limitation rather than retrying.

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
InstallDates). On Windows XP `amcache` is unavailable — write
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
`service`, `file_hash` (e.g. amcache SHA1), or `string_hash` (output of
`hash_evidence`).

| Type | Value | Confidence | Context | Source |
|---|---|---|---|---|
| {process/network/path/service/file_hash/string_hash} | {value} | {High/Medium/Low} | {why_it_matters} | {pslist/netscan/svcscan/amcache/...} |

---

## 8. Evidence Hashes / VirusTotal Lookup Notes

| Evidence Type | Original Value | MD5 | SHA1 | SHA256 | VirusTotal Use |
|---|---|---|---|---|---|
| {file_hash/indicator_string_hash} | {value} | {md5} | {sha1} | {sha256} | {yes_real_file_hash_or_no_indicator_string_only} |

Notes:
- Amcache `SHA1Hash` values come from file bytes — they are real file hashes
  and are appropriate for VirusTotal lookups. Mark VirusTotal Use = `yes`.
- `hash_evidence` outputs hash exact indicator strings (paths, commands,
  IPs). Mark VirusTotal Use = `no, indicator string only`.
- If nothing suspicious was found, write: "No suspicious evidence hashes
  were generated in this pass."

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
- Did you call `hash_evidence` for suspicious values or state that no suspicious hashes were generated?
- Are all placeholders removed?
- Is the date the exact harness-provided local time?

If all checks pass, call `save_report(filename="report_{stem}_{YYYYMMDD}.md", content="<the markdown above>")`.

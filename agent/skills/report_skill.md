# Report Skill: Forensic Report Template

Use this when the user asks for a formal report. Follow the template exactly.

## Hard rules

1. Match the user's report scope: triage, full case, network, malware, or credential hashes.
2. Every claim must trace back to a Volatility tool call made this turn or earlier in the thread.
3. Use the exact local analysis time injected by the harness. Do not guess the date.
4. Confidence values must be High, Medium, or Low.
5. Keep normal report generation within 8 Volatility tool calls before `save_report`.
6. Run `run_hashdump` only when the user asks for credential/account hashes, hashdump, or credential evidence.
7. If suspicious evidence exists, call `hash_evidence` on the exact suspicious values and include its output.
8. Clearly label hash types:
   - file hash: only when the value came from file bytes or a known file hash field
   - credential hash: LM/NTLM/hashdump output
   - indicator-string hash: hash of a path, command, IP, service name, or other exact text indicator
9. VirusTotal file lookups are appropriate for real file hashes. Do not present path-string hashes as file hashes.
10. Write the full Markdown report first. Then call `save_report`.

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

## 5. Persistence

| Mechanism | Detail | Confidence | Source |
|---|---|---|---|
| {service_or_none} | {binary_path_or_reason} | {High/Medium/Low} | svcscan/cmdline |

---

## 6. Injection / Code Analysis

| PID | Process | Finding | Disposition | Confidence | Source |
|---:|---|---|---|---|---|
| {pid_or_none} | {process} | {malfind_summary} | {Confirmed/Likely FP/Needs validation} | {High/Medium/Low} | malfind |

---

## 7. IOC Summary Table

| Type | Value | Confidence | Context | Source |
|---|---|---|---|---|
| {process/network/path/credential_hash/string_hash} | {value} | {High/Medium/Low} | {why_it_matters} | {plugin/tool} |

---

## 8. Evidence Hashes / VirusTotal Lookup Notes

| Evidence Type | Original Value | MD5 | SHA1 | SHA256 | VirusTotal Use |
|---|---|---|---|---|---|
| {file_hash/credential_hash/indicator_string_hash} | {value} | {md5} | {sha1} | {sha256} | {real_file_hash_only_or_not_file_hash} |

If no suspicious evidence was found, write: "No suspicious evidence hashes were generated in this pass."

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
- Are credential hashes clearly labeled as credential hashes, not file hashes?
- Are all placeholders removed?
- Is the date the exact harness-provided local time?

If all checks pass, call `save_report(filename="report_{stem}_{YYYYMMDD}.md", content="<the markdown above>")`.

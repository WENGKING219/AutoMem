# Forensics Skill: Windows Memory Analysis with Volatility3

This file is your operational playbook. Skim it before any non-trivial
investigation. The system prompt has the high-level decision tree; this
file gives you concrete signal-to-action mappings, query recipes, and the
exact things to look at in tool output.

## Reading tool output (do this every time)

Every Volatility tool returns JSON shaped like:

```
{
  "plugin": "windows.netscan.NetScan",
  "row_count": 412,
  "truncated": true,
  "data": {
    "total_rows": 412,
    "showing_first": 60,
    "statistics": {
       "row_count": 412,
       "columns": ["Offset","Proto","LocalAddr","LocalPort", ...],
       "top_local_ports": {"445": 12, "139": 8, ...},
       "top_foreign_ports": {"443": 38, "80": 21, "4444": 3},
       "top_foreign_addrs": {"185.10.20.30": 3},
       "state_counts": {"LISTENING": 60, "ESTABLISHED": 9, "CLOSED": 343},
       "command_indicator_rows": [{"PID": 1168, "matched": ["powershell"]}],
       "flagged_rows": [{"PID": 1168, "name": "svchost.exe",
                          "path": "C:\\Users\\Public\\svchost.exe"}],
       "flagged_count": 1,
       "sample_pids": [4, 372, 1168, ...]
    },
    "suggested_filters": [
      {"reason": "Inspect flagged PID", "filter_field": "PID", "filter_value": "1168"}
    ],
    "sample_data": [ ... up to 60 rows ... ],
    "next_action_hint": "Use query_plugin_rows to drill in."
  }
}
```

Always check `statistics` first. Most questions are answered by
`top_*`, `state_counts`, `command_indicator_rows`, `flagged_rows`, or
`top_paths` without reading individual rows. If `suggested_filters` is
present, use one of those filters for the next drill-down.

## Drilling in without re-running plugins

When `sample_data` does not contain the row you need, call
`query_plugin_rows`:

```
query_plugin_rows(
  plugin="netscan",          # short name, not the full Volatility path
  memory_dump="sample.raw",
  filter_field="ForeignPort",
  filter_value="4444",
  filter_field_2="State",    # optional second filter for large matches
  filter_value_2="ESTABLISHED",
  max_rows=50
)
```

Rules:
- PID-like fields (PID, PPID, TID) match by integer equality.
- Other fields match by case-insensitive substring on the cell value.
- Use the optional second filter when a first filter still returns many
  rows, for example PID + State or PID + Path.
- Re-running the original plugin without filters is wasteful and almost
  never produces new information. Use `query_plugin_rows` instead.

## Routing rubric (signal -> next tool)

| User signal                         | First tool         | Then |
|-------------------------------------|--------------------|------|
| "What's on this dump"               | get_image_info     | pslist, pstree |
| "Hidden processes"                  | psscan             | psxview, compare with pslist |
| "Suspicious processes"              | pslist             | look at flagged_rows + cmdline |
| "Network", "C2", "exfil"            | netscan            | query_plugin_rows by port/IP |
| "Injection", "malware in memory"    | malfind            | dlllist + handles for the PID |
| "Persistence"                       | svcscan            | cmdline for suspicious service PIDs |
| "Credential hashes", "hashdump"     | hashdump           | hash_evidence on recovered hashes |

## Recipes

### Recipe A -- Triage from cold
1. `get_image_info`  -- confirm OS, capture time
2. `run_pslist`      -- read `flagged_rows` and `top_names`
3. `run_pstree`      -- look for unusual parents
4. For each PID flagged: `query_plugin_rows(plugin="cmdline", memory_dump=dump, filter_field="PID", filter_value="<pid>")`
5. STOP once you can answer. Do NOT run every tool by reflex.

### Recipe B -- Network triage
1. `run_netscan`
2. From `top_foreign_ports`: any high port (4444, 5555, 6667, 8080)?
3. `query_plugin_rows(plugin="netscan", memory_dump=dump, filter_field="ForeignPort", filter_value="<port>")` to get rows.
4. For each unique PID, `query_plugin_rows(plugin="pslist", memory_dump=dump, filter_field="PID", filter_value="<pid>")`.
5. If the PID looks like a system process from a wrong path, escalate to malware path.

### Recipe C -- Malware focus on one PID
1. `run_pslist` -> confirm the PID exists; note image path.
2. `run_malfind(memory_dump=dump, pid=<n>)` -> look for PAGE_EXECUTE_READWRITE, MZ headers.
3. `query_plugin_rows(plugin="dlllist", memory_dump=dump, filter_field="PID", filter_value="<n>", max_rows=200)`
   -> look for DLLs outside `C:\Windows\System32\` or `C:\Windows\SysWOW64\`.
4. `query_plugin_rows(plugin="handles", memory_dump=dump, filter_field="PID", filter_value="<n>", max_rows=200)`
   -> look for unusual mutex names, registry Run keys, files in Temp.

### Recipe D -- Hidden process check
1. `run_pslist`, `run_psscan`, `run_psxview`
2. PIDs in psscan but not pslist -> likely terminated or hidden.
3. PIDs missing from one psxview source but present in others -> suspicious.
4. Confirm with `query_plugin_rows(plugin="cmdline", memory_dump=dump, filter_field="PID", filter_value="<n>")`.

### Recipe E -- Persistence sweep
1. `run_svcscan`        -- read `top_paths` for service binaries in odd dirs.
2. `run_cmdline`        -- search for `powershell -enc`, `mshta`, `regsvr32 /s /u`.
3. Use `query_plugin_rows` on `svcscan` for suspicious service names or paths.

### Recipe F -- Credential hash check
1. Use only when the user asks for credential hashes, account hashes, or hashdump.
2. `run_hashdump` once for the selected dump.
3. If hashes are recovered, report username/RID and LM/NTLM values exactly.
4. Call `hash_evidence` on recovered hash strings for MD5/SHA1/SHA256 indicator hashes.
5. State clearly that LM/NTLM hashes are credential hashes, not VirusTotal file hashes.

## What "suspicious" looks like (quick reference)

### Processes
- `svchost.exe` not under `C:\Windows\System32\` or `C:\Windows\SysWOW64\`.
- `svchost.exe` invoked without `-k`.
- Two or more `lsass.exe`.
- `csrss.exe` / `smss.exe` whose parent is not System (PID 4).
- Names off by one letter from real system binaries (`scvhost.exe`, `lsasss.exe`).

### Paths
- Anything running from `C:\Users\Public\`, `C:\ProgramData\`,
  `\AppData\Local\Temp\`, `\Downloads\`, or any user-writable directory.

### Network
- ESTABLISHED to ports 4444, 5555, 6667, 8080, 8443 from non-browser PIDs.
- One PID talking to many distinct foreign IPs (beaconing).
- Listeners on ephemeral ports owned by non-service processes.

### Memory
- malfind regions with PAGE_EXECUTE_READWRITE.
- MZ header found in heap or unmapped regions.
- DLL paths outside system directories.

## Honest reporting (every turn)

Every tool-using turn must end with:
1. **Direct answer** -- what the user asked, in one or two sentences.
2. **Evidence bullets** -- plugin name + concrete value (PID, IP, port, path).
3. **Confidence: High / Medium / Low** + one-line reason.
4. **Limitations** -- truncation, empty results, missing corroboration.
5. **Next best step** -- the single tool call you would make next, if any.

Never end with only "tasks completed" or todo status. Always answer.

### Windows profile accuracy

For `windows.info.Info`, use `NtMajorVersion`, `NtMinorVersion`, `CSDVersion`,
`NTBuildLab`, `NtSystemRoot`, architecture, and symbol path for the OS profile.
Do not identify the OS from the `Major/Minor` row alone; that value is not the
same as the Windows product release.

### Process triage accuracy

When both `pslist` and `psscan` are available, compare their process sets before
saying there are no suspicious processes. A PID or image found by `psscan` but
not `pslist` is not automatically malicious, but it is a triage candidate that
should be called out with the correct confidence and limitation.

## Anti-patterns (do not do these)

- Running every tool just to be thorough. Pick 2 to 6 for the question.
- Re-running a plugin to "see more rows" -- use `query_plugin_rows`.
- Pasting raw JSON into the user reply. Summarise as bullets or a short
  table.
- Claiming a clean dump from a truncated result. Say "preview only" if
  `truncated` is true.
- Drawing a conclusion from one indicator alone. Tie at least two
  artefacts together.

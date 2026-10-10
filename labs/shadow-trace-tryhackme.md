# Malware triage — `windows-update.exe` (TryHackMe: Shadow Trace)

**Type:** lab exercise (TryHackMe, "Shadow Trace" — Malware Concepts for SOC)
**Role:** SOC L1 / initial malware assessment
**Goal:** statically triage a suspicious binary, extract host- and network-based IOCs, and map observed capabilities to MITRE ATT&CK.

> Lab exercise, not a real incident. Written to practise the initial-triage workflow a SOC analyst runs on a flagged file. CTF flag values are redacted.

---

## 1. Sample identification

| Property | Value |
|---|---|
| File name | `windows-update.exe` (dropped on the user Desktop) |
| SHA-256 | `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc` |
| File type | PE, **64-bit**, console subsystem |
| Size / entropy | 50,176 bytes / 5.789 (not packed) |
| Toolchain | Microsoft Linker 14.x, Visual Studio |
| Compile timestamp | 2025-10-03 03:13:45 UTC |
| PDB path | `C:\Users\User\source\repos\windows-update\x64\Release\windows-update.pdb` |

The file name impersonates a legitimate Windows update — a classic **masquerading** lure. The leftover PDB path shows it was freshly built from a custom project, not a signed Microsoft binary.

## 2. Static analysis — capabilities from imports

Imports (via pestudio) reveal the binary's intent before it is ever executed:

| Imported functions | Capability |
|---|---|
| `WS2_32.dll`: `getaddrinfo`, `InetPton` | **Socket communication** (Winsock) — confirmed at runtime as a bind shell listening on **TCP/4443** |
| `WININET`: `InternetOpen`, `InternetConnect`, `HttpOpenRequest`, `HttpSendRequest` | HTTP client — C2 / staging |
| `urlmon`: `URLDownloadToFile` | **Download of a second-stage payload** |
| `CreateToolhelp32Snapshot`, `Process32First/Next`, `K32EnumProcesses`, `K32EnumProcessModules` | **Process discovery** |
| `ShellExecuteEx`, `CreateProcess` | Execution of downloaded payloads |
| `FindFirstFile`, `FindNextFile`, `DeleteFile`, `SHGetKnownFolderPath` | File enumeration / cleanup |

Recovered strings tie these capabilities to concrete infrastructure, including the status line `Hosts file exfiltrated to http://...`, which indicates the sample reads and exfiltrates the local `hosts` file. A base64-encoded string was also embedded (prefix `VEhN…`, which decodes to `THM`); decoding it yielded a benign CTF marker (redacted).

## 3. Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|---|---|---|
| SHA-256 | `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc` | the sample |
| URL | `http://tryhatme.com/update/security-update.exe` | second-stage download |
| URL | `https://tryhatme.com/dev/main.exe` | alert — triggered by `powershell.exe` |
| URL | `https://reallysecureupdate.tryhatme.com/update.exe` | alert — triggered by `chrome.exe` |
| Domain | **`responses.tryhatme.com`** | exfiltration endpoint (`hosts` file) — highest-value IOC |
| Domain | `tryhatme.com`, `reallysecureupdate.tryhatme.com` | typosquat of `tryhackme.com` |
| Port | `TCP/4443` | inbound bind shell |
| File | `test.txt` | file written by the `chrome.exe`-triggered activity |

> Triage note: the **exfiltration/C2 domain `responses.tryhatme.com` is the priority IOC**, not the download URL — blocking where data leaves the network contains the impact even if the delivery URL rotates.

## 4. ATT&CK mapping

| Tactic | Technique |
|---|---|
| Defense Evasion | T1036 Masquerading (`windows-update.exe`) |
| Command and Control | T1105 Ingress Tool Transfer; T1571 Non-Standard Port (4443) |
| Execution | T1059.001 PowerShell (download of `main.exe`); T1106 Native API |
| Discovery | T1057 Process Discovery (Toolhelp32) |
| Collection / Exfiltration | T1005 Data from Local System (`hosts`); T1048 Exfiltration Over Alternative Protocol |

## 5. Detection & response

**Detection**
- Alert on a process named `windows-update.exe` executing from a user Desktop / outside `C:\Windows`.
- Network: outbound to `*.tryhatme.com`; a local service **listening on TCP/4443**.
- Hunt for `powershell.exe` / `chrome.exe` fetching `*.exe` from the URLs above.
- Add every IOC in §3 to the blocklist and threat-intel feed.

**Response**
- Isolate the host from the network (kill the 4443 listener first).
- Collect the binary, memory, and relevant logs; submit the hash to VirusTotal / internal sandbox.
- Rotate credentials that could have been exposed; review the `hosts` file for tampering.
- Reimage the host; block the domains at the proxy/DNS layer.

---

## Techniques & tools

`pestudio` · `strings` (Sysinternals) · `Get-FileHash` · `CyberChef` (Base64) · PE/import analysis · IOC extraction · MITRE ATT&CK mapping

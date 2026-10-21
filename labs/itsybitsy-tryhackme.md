# SIEM triage — C2 beacon investigation (TryHackMe: ItsyBitsy)

**Type:** lab exercise (TryHackMe, "ItsyBitsy" — SIEM Triage for SOC)
**Role:** SOC L1 / alert triage in the Elastic Stack (Kibana)
**Goal:** triage an IDS alert for suspected C2 communication using a week of HTTP connection logs, and recover the malicious indicator.

> Lab exercise, not a real incident. Written to practise the Kibana/ELK triage workflow. The CTF marker is redacted.

---

## 1. Scenario

An IDS alert flagged possible C2 traffic from user **Browne** (HR). A suspicious file reportedly contained a malicious `THM{...}` pattern. Only a week of HTTP connection logs could be pulled; they are ingested into the **`connection_logs`** index in Kibana.

## 2. Triage in Kibana (Discover)

**Scope the data.** Select the `connection_logs` data view and set the time range to the incident window (March 2022 — the data is years old, so the default "last 15 minutes" returns nothing). The hit counter over the histogram gives the event count for the period.

**Pivot to the suspect.** The logs are structured, so filtering beats free-text search. Filtering on the source address isolates the user's traffic:

```
source_ip : "192.166.65.54"
```

Expanding a document (JSON view) exposes the full connection metadata — `source_ip`, `destination_ip`, `host`, `uri`, `method`, `user_agent`, `status_code`, and body sizes.

## 3. Findings

| Field | Value | Meaning |
|---|---|---|
| `source_ip` | `192.166.65.54` | the suspect host (Browne) |
| `user_agent` | **`bitsadmin`** | a legitimate Windows binary (LOLBin) used to download the payload |
| `host` | **`pastebin.com`** | a trusted file-sharing site abused as C2 |
| `uri` | `/yTg0Ah6a` | the C2 path |
| full C2 URL | `pastebin.com/yTg0Ah6a` | where the host beaconed |
| file name | **`secret.txt`** | the paste's title on the file-sharing site |
| content | `THM{…}` (redacted) | the malicious marker from the IDS alert |

The two requests (`HEAD` then `GET`) are a classic download pattern: check the resource, then pull it.

## 4. The key triage lesson

`connection_logs` holds **connection metadata only** — including `response_body_len` (the size of the response, 14 bytes) but **not the response body itself**. So the actual file content and the `THM{...}` marker cannot be recovered by filtering in Kibana; that required opening the C2 URL (`pastebin.com/raw/yTg0Ah6a`) directly. Knowing *what your telemetry does and does not contain* is half of triage.

## 5. ATT&CK mapping

| Tactic | Technique |
|---|---|
| Command and Control | T1071.001 Application Layer Protocol: Web; T1102 Web Service (pastebin as dead-drop/C2) |
| Command and Control / Ingress | T1105 Ingress Tool Transfer (payload download) |
| Execution / Defense Evasion | T1218 / LOLBin abuse — `bitsadmin` (BITS, T1197) to blend with legitimate activity |

## 6. Detection & response

**Detection**
- Alert on `bitsadmin` making outbound HTTP, especially to paste/file-sharing hosts.
- Flag access to `pastebin.com/raw/*` and similar raw-content endpoints from endpoints that have no business reason.
- Baseline per-user destinations; a single HR host beaconing to a paste site is an outlier.

**Response**
- Isolate the host; pull the downloaded file and the BITS job list (`bitsadmin /list`).
- Block the C2 URL/domain at the proxy; add the indicators to the blocklist.
- Hunt other hosts for the same `user_agent` + destination pattern.

---

## Techniques & tools

`Elastic Stack / Kibana (Discover)` · `KQL filtering` · `field/JSON inspection` · IOC extraction · LOLBin awareness (`bitsadmin`, BITS) · MITRE ATT&CK mapping

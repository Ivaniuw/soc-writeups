# SOC Write-ups

Analizy incydentów i podejrzanych wiadomości, wykonywane samodzielnie w ramach przygotowania
do pracy w SOC. Każda analiza opiera się na rzeczywistym materiale, a nie na scenariuszu
laboratoryjnym, i jest napisana w formacie zbliżonym do zgłoszenia obsługiwanego przez
analityka pierwszej linii.

*Self-directed SOC analyst write-ups, based on real-world samples. Written in Polish.*

---

## Analizy

| Data | Temat | Czego dotyczy |
|---|---|---|
| 27.09.2026 | [Kampania phishingowa wykorzystująca Google Cloud Storage](analiza-phishingu-google-cloud-storage.md) | uwierzytelnianie poczty (SPF/DKIM), sfałszowana nazwa HELO, wieloetapowe przekierowanie, cloaking, obejście systemów reputacyjnych |

---

## Ćwiczenia laboratoryjne / Lab exercises

Osobna sekcja: analizy wykonane na materiale **laboratoryjnym** (TryHackMe), trzymane oddzielnie
od rzeczywistych incydentów powyżej. Pisane po angielsku, w formacie raportu z triażu.

*Separate from the real-world analyses above: malware-triage reports done on lab material (TryHackMe), written in English.*

| Data | Platforma | Temat | Czego dotyczy |
|---|---|---|---|
| 10.10.2026 | TryHackMe (Shadow Trace) | [Malware triage — windows-update.exe](labs/shadow-trace-tryhackme.md) | statyczna analiza PE, ekstrakcja IOC, dekodowanie Base64, mapowanie MITRE ATT&CK, bind shell + eksfiltracja |
| 21.10.2026 | TryHackMe (ItsyBitsy) | [SIEM triage — C2 beacon investigation](labs/itsybitsy-tryhackme.md) | triage alertu IDS w Elastic/Kibana (KQL), analiza logów połączeń, LOLBin (bitsadmin), pastebin jako C2, mapowanie MITRE ATT&CK |
| 31.10.2026 | TryHackMe (Tempest, **Capstone**) | [Full attack-chain DFIR — compromised workstation](labs/tempest-tryhackme.md) | pełny łańcuch ataku: Follina (CVE-2022-30190), Sysmon/EVTX (Timeline Explorer), deobfuskacja C2 (base64, tshark), chisel, PrintSpoofer, persystencja, MITRE ATT&CK |
| 01.11.2026 | TryHackMe (Boogeyman 1, **Capstone**) | [Phishing to DNS exfiltration — rebuilding a stolen password database](labs/boogeyman-1-tryhackme.md) | phishing z zaszyfrowanym ZIP, LNK → PowerShell C2, logi ScriptBlock (jq), eksfiltracja przez DNS, odtworzenie pliku KeePass z pcap (tshark, xxd) |
| 01.11.2026 | TryHackMe (Boogeyman 2, **Capstone**) | [Memory forensics — malicious résumé to fileless persistence](labs/boogeyman-2-tryhackme.md) | analiza zrzutu pamięci w Volatility 3, makro VBA (olevba), wscript → C2, zadanie harmonogramu z payloadem w rejestrze |
| 02.11.2026 | TryHackMe (Boogeyman 3, **Capstone**) | [SIEM investigation — CEO phishing to domain compromise](labs/boogeyman-3-tryhackme.md) | Elastic/KQL na wielu hostach: ISO + HTA, rundll32, obejście UAC, Mimikatz, pass-the-hash, WinRM, DCSync, ransomware |

---

## Podejście

- **Materiał rzeczywisty** — wiadomości z własnej skrzynki, nie przygotowane ćwiczenia.
- **Bezpieczna analiza** — odnośników nie otwiera się w przeglądarce; wyłącznie VirusTotal,
  urlscan.io, zapytania DNS i analiza nagłówków.
- **Rozdzielenie obserwacji od hipotez** — to, czego nie udało się potwierdzić, jest w tekście
  wprost oznaczone jako hipoteza.
- **Weryfikacja przed oskarżeniem** — jeżeli w łańcuchu pojawia się nazwa istniejącej firmy,
  jest sprawdzana, zanim trafi do wniosków.
- **Anonimizacja** — dane odbiorcy są redagowane, publikowane są wyłącznie wskaźniki
  po stronie atakującego.

## Narzędzia

`Gmail – Pokaż oryginał` · `VirusTotal` · `urlscan.io` · `Resolve-DnsName` (PowerShell) ·
`MITRE ATT&CK` · `Python` (parsowanie nagłówków i logów)

---

## O mnie

Ivan Tatur — przygotowuję się do pracy jako analityk SOC L1.

- TryHackMe: [tatur38](https://tryhackme.com/p/tatur38) — **SOC Level 1 ukończony (certyfikat, 11.2026)**,
  SOC Simulator, moduły Security Monitoring oraz Network Security and Traffic Analysis
- LinkedIn: [ivan-tatur](https://www.linkedin.com/in/ivan-tatur-1a50b0234)
- Kontakt: tatur38@gmail.com

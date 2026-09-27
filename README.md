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

- TryHackMe: [tatur38](https://tryhackme.com/p/tatur38) — SOC Level 1, SOC Simulator,
  moduły Security Monitoring oraz Network Security and Traffic Analysis
- LinkedIn: [ivan-tatur](https://www.linkedin.com/in/ivan-tatur-1a50b0234)
- Kontakt: tatur38@gmail.com

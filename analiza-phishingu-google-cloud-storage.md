# Analiza kampanii phishingowej wykorzystującej Google Cloud Storage jako przekierowanie

**Autor:** Ivan Tatur
**Data analizy:** 27.09.2026
**Źródło:** wiadomość otrzymana na prywatną skrzynkę Gmail, automatycznie zaklasyfikowana jako spam
**Narzędzia:** nagłówki z „Pokaż oryginał" w Gmailu, VirusTotal, urlscan.io, `Resolve-DnsName` (PowerShell)

> Analiza wykonana samodzielnie, na własnej skrzynce, w celach edukacyjnych. Rekomendacje
> w sekcji 8 sformułowano tak, jak trafiłyby do zgłoszenia w środowisku korporacyjnym.

---

## 1. Podsumowanie

25 września 2026 r. na moją skrzynkę trafiła wiadomość podszywająca się pod usługę przechowywania zdjęć w chmurze. Nadawca straszył zablokowaniem konta i usunięciem plików tego samego wieczoru, a jedyną możliwą reakcją było kliknięcie przycisku.


Wiadomość jest phishingiem, ale nie standardowym. Cała kampania opiera się na **pożyczonym zaufaniu**: uwierzytelnianie poczty przechodzi poprawnie (SPF i DKIM pass), strona docelowa hostowana jest na domenie `storage.googleapis.com`, a adres URL jest oceniany jako czysty przez 91 z 92 silników VirusTotal, przez urlscan.io oraz przez Google Safe Browsing. Plik na infrastrukturze Google nie jest jednak stroną logowania — to licząca 692 bajty zaślepka, która przekierowuje ofiarę na serwer atakującego.


Serwer docelowy stosuje **cloaking**: żądaniom pochodzącym od skanerów odmawia podania treści (odpowiedzi `406 Not Acceptable` oraz `{"warning": "You're not logged in!"}`), a dodatkowo zbiera strefę czasową i język przeglądarki, prawdopodobnie po to, by właściwą stronę pokazać wyłącznie odbiorcom z oczekiwanej lokalizacji.


W łańcuchu dostarczenia pojawia się dodatkowo host podający się za domenę istniejącej,
niepowiązanej firmy. Weryfikacja DNS wykazała, że nazwa ta została sfałszowana, a infrastruktura
tej firmy nie została wykorzystana (sekcja 3.5).

**Werdykt:** phishing · **Pewność:** wysoka
**Status na dzień analizy:** infrastruktura nadal aktywna (HTTP 200)

---

## 2. Dane wiadomości

| Pole | Wartość |
|---|---|
| Temat | `⚠️Account Has been Blocked! Your Photos and Videos will be Removed 09-25-2026 . take action!⚠️` |
| Data otrzymania | 25.09.2026, 09:08 |
| Nadawca (From) | `tatur38 <yolgkrjtgdi@vvcgkneot.mctorta.h2o.nodeeor3bi.biz.id>` |
| Return-Path | `Return-smlsxgj@mctorta.h2o.nodeeor3bi.biz.id` |
| Delivered-To | `[zredagowane]@gmail.com` |
| To | `[zredagowane]@aol.com` |
| Adres IP nadawcy | `45.147.46.178` |
| Klasyfikacja Gmaila | Spam |


---


## 3. Analiza nagłówków

### 3.1 Uwierzytelnianie przeszło poprawnie

```
dkim=pass header.i=@vvcgkneot.mctorta.h2o.nodeeor3bi.biz.id header.s=smtp
spf=pass (domain of return-smlsxgj@mctorta.h2o.nodeeor3bi.biz.id
          designates 45.147.46.178 as permitted sender)
```

To najważniejsza obserwacja w całej analizie. SPF i DKIM **nie sprawdzają, czy wiadomość jest uczciwa** — sprawdzają jedynie, czy serwer miał prawo wysłać pocztę w imieniu danej domeny i czy treść nie została zmieniona po drodze. Atakujący jest właścicielem domeny `nodeeor3bi.biz.id`, więc poprawnie skonfigurował dla niej rekordy SPF i podpis DKIM. Zielony wynik uwierzytelniania jest tu dowodem na to, że domena należy do nadawcy, a nie na to, że nadawca jest godny zaufania.

Praktyczny wniosek dla SOC: **wynik `spf=pass` nie może być samodzielną przesłanką do uznania wiadomości za bezpieczną.**

### 3.2 Podszywanie się w polu From

Nazwa wyświetlana nadawcy to `tatur38` — czyli identyczna z lokalną częścią adresu odbiorcy. W kliencie pocztowym odbiorca widzi więc wiadomość pozornie od samego siebie lub od konta o znajomej nazwie. Rzeczywisty adres (`yolgkrjtgdi@vvcgkneot.mctorta.h2o.nodeeor3bi.biz.id`) jest widoczny dopiero po rozwinięciu szczegółów.

Lokalna część adresu (`yolgkrjtgdi`) oraz identyfikator w Return-Path (`Return-smlsxgj`) są ciągami losowymi — typowe dla generowania adresów per odbiorca, co utrudnia blokowanie po pełnym adresie e-mail.

### 3.3 Niezgodność adresata

Wiadomość została dostarczona na adres w domenie `gmail.com`, natomiast w nagłówku `To` widnieje adres w domenie `aol.com`. Oznacza to, że rzeczywisty odbiorca znajdował się w kopercie SMTP (`RCPT TO`), a nie w widocznym nagłówku — typowe dla rozsyłki masowej z ukrytą listą adresatów. Potwierdza to, że nie mamy do czynienia z atakiem ukierunkowanym.


### 3.4 Infrastruktura wysyłkowa

| Element | Wartość | Uwaga |
|---|---|---|
| IP wysyłające | `45.147.46.178` | |
| HELO | `sabilue.click` | domena w taniej strefie `.click` |
| Reverse DNS | `ecp.netcore.co.in` | infrastruktura dostawcy masowej wysyłki |
| Domena From | `vvcgkneot.mctorta.h2o...` | |
| Domena Return-Path | `mctorta.h2o...` | inna subdomena niż w From |

Trzy różne nazwy w jednym połączeniu — nazwa w HELO, rzeczywisty reverse DNS oraz domena nadawcy — nie mają ze sobą nic wspólnego. Atakujący korzysta z platformy do masowej wysyłki, podając w HELO własną domenę jednorazową.

Fragment łańcucha `Received` (nagłówki czyta się od dołu do góry — najstarszy wpis jest ostatni):

```
Received: from efianalytics.com (efianalytics.com. 216.244.76.116)
Received: from sabilue.click (ecp.netcore.co.in. [45.147.46.178])
          by mx.google.com with ESMTPS id ffacd0b85a97d-4887a644c69si3291870f8f.155
          for <[zredagowane]@gmail.com>
          (version=TLS1 cipher=ECDHE-ECDSA-AES128-SHA bits=128/128);
          Fri, 25 Sep 2026 00:08:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of return-smlsxgj@mctorta.h2o.nodeeor3bi.biz.id
          designates 45.147.46.178 as permitted sender) client-ip=45.147.46.178;
Received: by 2002:a05:6f02:62a:b0:128:1e4d:31c1 with SMTP id 42csp17238589rce;
          Fri, 25 Sep 2026 00:08:20 -0700 (PDT)
```

Znacznik czasu `00:08:19 -0700 (PDT)` odpowiada godzinie 09:08 czasu środkowoeuropejskiego,
co zgadza się z godziną widoczną w kliencie pocztowym.

### 3.5 Sfałszowana nazwa HELO — weryfikacja

W łańcuchu `Received` pojawia się host przedstawiający się jako `efianalytics.com`
(`216.244.76.116`). EFI Analytics to istniejąca firma produkująca oprogramowanie do strojenia
sterowników silnikowych — domena ma 13 lat, prowadzi działającą witrynę i nie wykazuje oznak
złośliwości. Postawiłem więc hipotezę: albo infrastruktura pocztowa tej firmy została użyta do
przekazania wiadomości, albo nazwa w HELO została sfałszowana.

Weryfikacja — cztery zapytania DNS:

```powershell
Resolve-DnsName 216.244.76.116 -Type PTR   # 116.wowrack.com
Resolve-DnsName efianalytics.com -Type MX  # mail.efianalytics.com
Resolve-DnsName mail.efianalytics.com -Type A   # 40.130.79.86
Resolve-DnsName efianalytics.com -Type TXT
# v=spf1 ip4:40.130.79.86 include:secureserver.net -all
```

| Sprawdzenie | Wynik | Wniosek |
|---|---|---|
| Reverse DNS adresu `216.244.76.116` | `116.wowrack.com` | adres należy do hostingu WowRack, nie do EFI Analytics |
| Serwer pocztowy `efianalytics.com` | `40.130.79.86` | zupełnie inny adres |
| Rekord SPF `efianalytics.com` | `ip4:40.130.79.86 include:secureserver.net -all` | `216.244.76.116` **nie jest** autoryzowany |

Trzy niezależne sprawdzenia są zgodne: **nazwa `efianalytics.com` w HELO została sfałszowana.**
Infrastruktura EFI Analytics nie została wykorzystana ani skompromitowana — atakujący korzysta
z serwera w sieci WowRack i podczas powitania SMTP podał cudzą nazwę domeny. Serwer odbierający
zapisał tę deklarację w nagłówku bez weryfikacji.

Warto zauważyć, dlaczego nie wykryło tego uwierzytelnianie: **SPF sprawdzany jest dla domeny
z Return-Path** (`mctorta.h2o.nodeeor3bi.biz.id`), a nie dla nazwy podanej w HELO. Sprawdzanie
SPF dla HELO jest opcjonalne i często pomijane. Gdyby zostało wykonane, wynik byłby `fail` —
rekord SPF firmy kończy się twardym `-all`.

Ten sam mechanizm — podawanie w HELO nazwy niezwiązanej z rzeczywistym adresem — widoczny jest
także w drugim wpisie łańcucha (`sabilue.click` przy reverse DNS `ecp.netcore.co.in`).

---

## 4. Analiza treści

Zastosowane techniki socjotechniczne:

- **Presja czasu** — data usunięcia plików podana wprost w temacie (`09-25-2026`), w treści `will be deleted tonight`.
- **Groźba utraty danych osobistych** — zdjęcia i filmy, a nie pieniądze; odwołanie do wartości emocjonalnej.
- **Pojedyncze wezwanie do działania** — cała wiadomość prowadzi do jednego przycisku.
- **Wzmocnienie wizualne** — emotikony ostrzegawcze w temacie, nagłówek „Storage Alert”, grafika chmury.

Przesłanki techniczne widoczne bez analizy nagłówków:

- Format daty `09-25-2026` (amerykański) w wiadomości kierowanej do odbiorcy w Europie.
- W treści wyświetla się dosłownie ciąg `&#65039` zamiast znaku, który miał reprezentować. Encja HTML została zapisana bez średnika, czyli szablon wiadomości jest generowany automatycznie i nie był sprawdzany wizualnie.
- Brak jakiejkolwiek personalizacji poza nazwą wyświetlaną nadawcy.
- Nazwa usługi, pod którą podszywa się nadawca, nie pada ani razu.

---

## 5. Analiza odnośnika

> Odnośnika nie otwierano w przeglądarce. Analiza wyłącznie przez VirusTotal i urlscan.io.

Adres z przycisku w treści wiadomości:

```
hxxps://storage.googleapis[.]com/betweenthemiseasy/trustedbycommunities.html#4nKEeu241277ucMz4093trbnmlbcml3929YMZUTJROIVIMBQW30935NZMP1973934B20
```

### 5.1 Hosting na infrastrukturze Google

Strona nie znajduje się na domenie łudząco podobnej do prawdziwej — leży w publicznym zasobniku Google Cloud Storage. Nazwa pliku (`trustedbycommunities.html`) została dobrana tak, aby w pasku adresu pojawiło się słowo budzące zaufanie.

Konsekwencja: **mechanizmy reputacyjne oceniają domenę, a ta należy do Google.** Nie da się jej zablokować ani obniżyć jej reputacji, ponieważ korzystają z niej codziennie legalne usługi.

### 5.2 Wyniki weryfikacji reputacyjnej

| Źródło | Wynik |
|---|---|
| VirusTotal | **1 / 92** (wyłącznie Phishing Database) |
| urlscan.io | brak klasyfikacji |
| Google Safe Browsing | brak klasyfikacji |
| Status HTTP | 200 — strona aktywna w dniu analizy |

Trzy niezależne systemy reputacyjne nie zakwalifikowały tego adresu jako złośliwego.

### 5.3 Łańcuch przekierowań

Obiekt na Google Cloud Storage ma **692 bajty** — to nie jest strona logowania, lecz zaślepka przekierowująca:

```
https://storage.googleapis.com/betweenthemiseasy/trustedbycommunities.html
   (692 B, Google 142.251.20.207 — zaślepka przekierowująca)
     ↓
http://mypsx.miami-people.uk.eu.org/rd/      HTTP 307
https://mypsx.miami-people.uk.eu.org/rd/     HTTP 307
     ↓
strona docelowa — po HTTP, nie HTTPS
```

| Element drugiego etapu | Wartość |
|---|---|
| Domena | `mypsx.miami-people.uk.eu.org` |
| IP | `104.168.141.164` (HOSTWINDS LLC, AS54290, US) |
| Wiek domeny | ok. 3 miesiące |
| Strefa | `eu.org` — bezpłatne subdomeny |
| Liczba skanów na urlscan.io | 1214 |

Domena w bezpłatnej strefie, zarejestrowana trzy miesiące temu, przeskanowana ponad tysiąc razy — infrastruktura jednorazowa, wykorzystywana w kampanii o dużej skali.

### 5.4 Przeznaczenie fragmentu URL — weryfikacja eksperymentalna

Wszystko po znaku `#` (fragment) **nie jest wysyłane do serwera** — pozostaje wyłącznie w przeglądarce. Aby ustalić jego rolę, wykonałem dwa skany tego samego adresu:

| Skan | Adres przesłany | Adres końcowy |
|---|---|---|
| 1 | z fragmentem `#4nKEeu…` | `/rd/` |
| 2 | **bez fragmentu** | `/t/?undefined=undefined&tz=Europe%2FWarsaw&lang=pl-PL` |

W skanie bez fragmentu w parametrze pojawiła się wartość `undefined`. Oznacza to, że skrypt na stronie pośredniczącej odczytuje fragment adresu i przekazuje go dalej jako parametr — przy jego braku zmienna pozostaje niezdefiniowana. Fragment pełni więc funkcję **identyfikatora odbiorcy lub kampanii**, przenoszonego w sposób niewidoczny dla serwerów pośredniczących.

Ma to bezpośrednie znaczenie operacyjne: **w logach serwera proxy fragment nie będzie widoczny**, więc identyfikacja konkretnych ofiar na tej podstawie jest niemożliwa.

Poza identyfikatorem strona przekazuje dalej **strefę czasową i język przeglądarki** (`tz=Europe/Warsaw`, `lang=pl-PL`).

### 5.5 Cloaking

Serwer docelowy nie udostępnił treści narzędziom analitycznym:

- `/rd/` zwrócił `{"warning": "You're not logged in!"}`
- `/t/` zwrócił `406 Not Acceptable` (66 bajtów, `text/plain`)
- urlscan.io nie wykonał zrzutu ekranu — brak treści do wyrenderowania

W połączeniu ze zbieraniem strefy czasowej i języka wskazuje to na **cloaking**: właściwa strona serwowana jest wyłącznie żądaniom spełniającym oczekiwane kryteria (poprawny identyfikator, zgodna lokalizacja, właściwe nagłówki przeglądarki), a pozostałym — w tym skanerom bezpieczeństwa — odmawia się treści.

Jest to prawdopodobnie główny powód, dla którego systemy reputacyjne nie zakwalifikowały tego adresu jako złośliwego: **nigdy nie zobaczyły złośliwej treści.**

> Ostatecznej strony nie udało się zaobserwować. Charakter strony docelowej — najprawdopodobniej wyłudzanie danych uwierzytelniających — pozostaje **hipotezą**, wynikającą z treści wiadomości, a nie z bezpośredniej obserwacji.

---

## 6. Wskaźniki kompromitacji (IOC)

| Typ | Wartość |
|---|---|
| Adres nadawcy | `yolgkrjtgdi@vvcgkneot.mctorta.h2o.nodeeor3bi.biz.id` |
| Return-Path | `Return-smlsxgj@mctorta.h2o.nodeeor3bi.biz.id` |
| Domena nadawcy (korzeń) | `nodeeor3bi.biz.id` |
| HELO | `sabilue.click` |
| IP wysyłające | `45.147.46.178` |
| IP w łańcuchu Received | `216.244.76.116` (PTR: `116.wowrack.com`) |
| Sfałszowana nazwa HELO | `efianalytics.com` |
| URL etapu 1 | `hxxps://storage.googleapis[.]com/betweenthemiseasy/trustedbycommunities.html` |
| Zasobnik GCS | `betweenthemiseasy` |
| Domena etapu 2 | `mypsx.miami-people.uk.eu[.]org` |
| IP etapu 2 | `104.168.141.164` |
| Ścieżki etapu 2 | `/rd/`, `/t/` |

---

## 7. Mapowanie na MITRE ATT&CK

| Technika | ID | Uzasadnienie |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | wiadomość zawiera wyłącznie odnośnik, bez załącznika |
| Acquire Infrastructure: Web Services | T1583.006 | wykorzystanie Google Cloud Storage do hostowania etapu 1 |
| Acquire Infrastructure: Domains | T1583.001 | domena w bezpłatnej strefie `eu.org`, wiek 3 miesiące |
| User Execution: Malicious Link | T1204.001 | atak wymaga kliknięcia przez odbiorcę |
| Impersonation | T1656 | podszywanie się pod usługę chmurową, pod nazwę odbiorcy oraz pod cudzą domenę w HELO |

---

## 8. Rekomendacje

1. **Nie blokować domeny `storage.googleapis.com`** — jest wykorzystywana legalnie. Blokada musi być precyzyjna: pełna ścieżka URL lub nazwa zasobnika `betweenthemiseasy`.
2. **Zablokować domenę etapu drugiego** `mypsx.miami-people.uk.eu.org` oraz — do rozważenia — całą strefę `*.uk.eu.org` na bramie proxy, jeżeli organizacja nie korzysta z niej biznesowo.
3. **Zablokować domenę nadawcy** `*.nodeeor3bi.biz.id` na bramie pocztowej.
4. **Przeszukać logi poczty** pod kątem innych odbiorców z tej samej domeny nadawcy oraz wiadomości o zbliżonym temacie.
5. **Przeszukać logi proxy i DNS** pod kątem zapytań do `storage.googleapis.com/betweenthemiseasy/` oraz do domeny etapu drugiego. Uwaga: fragment URL nie będzie widoczny w logach.
6. **W przypadku wykrycia kliknięcia** — wymusić zmianę hasła, sprawdzić logowania z nietypowych lokalizacji i aktywne sesje.
7. **Reguła detekcyjna:** wiadomość z zewnątrz, w której nazwa wyświetlana nadawcy odpowiada lokalnej części adresu odbiorcy, a domena nadawcy jest inna — silna przesłanka phishingu, warta osobnego alertu.
8. **Reguła detekcyjna:** rozbieżność między nazwą podaną w HELO a reverse DNS adresu źródłowego — warta odnotowania jako przesłanka, szczególnie gdy nazwa w HELO należy do istniejącej, niepowiązanej firmy.
9. **Zgłoszenie nadużycia** — zasobnik do Google Cloud Abuse, domena etapu drugiego do dostawcy hostingu (Hostwinds), adres `216.244.76.116` do zespołu abuse WowRack oraz zgłoszenie do CERT Polska.

> Status zgłoszeń: zaplanowane. Infrastruktura pozostawała aktywna w dniu publikacji tej analizy.
> Data i wynik zgłoszeń zostaną dopisane po ich wysłaniu.


---

## 9. Wnioski

Najciekawszym elementem tej kampanii nie jest sama wiadomość — jest nią konsekwentne budowanie ataku na elementach, którym systemy bezpieczeństwa ufają domyślnie. Uwierzytelnianie poczty przechodzi, bo domena należy do atakującego. Reputacja adresu URL jest czysta, bo host należy do Google. Skanery nie widzą złośliwej treści, bo serwer im jej nie pokazuje.

Żaden z trzech mechanizmów, na których zwykle opiera się automatyczna ocena wiadomości, nie zadziałał — a mimo to Gmail zaklasyfikował wiadomość jako spam. Zadecydowały więc sygnały innego rodzaju: cechy treści, reputacja nadawcy i wzorce zachowania, a nie wynik SPF czy lista blokowanych domen.

Analiza pokazała też, jak łatwo wpisać do nagłówków cudzą nazwę. Host przedstawiający się jako `efianalytics.com` nie miał z tą firmą nic wspólnego, co udało się wykazać trzema zapytaniami DNS. Warto o tym pamiętać, zanim wskaże się w raporcie konkretny podmiot jako źródło ataku — deklaracja w nagłówku nie jest dowodem.

Dla analityka L1 płynie z tego jeden praktyczny wniosek: **zielony wynik uwierzytelniania i czysty wynik reputacyjny nie zamykają analizy zgłoszenia.** Dopiero zestawienie kilku słabych przesłanek — niezgodność nazwy nadawcy z adresem, niezgodność adresata, wiek i strefa domeny, rozmiar strony docelowej, odmowa podania treści — pozwoliło jednoznacznie zakwalifikować tę wiadomość.

---

*Dane osobowe odbiorcy zostały zredagowane. Odnośników nie otwierano w przeglądarce —
analizę przeprowadzono wyłącznie przez VirusTotal i urlscan.io.*

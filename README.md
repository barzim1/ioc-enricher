# IoC Auto-Enricher 🛡️

Narzędzie CLI dla analityków pierwszej linii SOC. Przyjmuje wskaźniki kompromitacji (IP, domeny, URL, hashe), sprawdza je w kilku źródłach threat intelligence i zwraca **ocenę ryzyka z uzasadnieniem** w formacie gotowym do wklejenia do ticketu (Jira, TheHive, ServiceNow).

## Funkcje

- **Typy IoC:** IPv4/IPv6, domeny, URL, MD5/SHA1/SHA256. Typ jest rozpoznawany automatycznie.
- **Defang / refang:** rozumie zapis `hxxps://evil[.]com` i `1[.]2[.]3[.]4`.
- **Providery:** VirusTotal (wszystkie typy) i AbuseIPDB (adresy IP).
- **Ekstrakcja z logów (`-x`):** wyciąga IoC z dowolnego tekstu (log, mail, treść zgłoszenia), pomija adresy prywatne, nazwy plików (`run.ps1`) i duplikaty.
- **Wyjaśnialny scoring 0-100:** każdy punkt ma uzasadnienie w raporcie (patrz niżej). Wynik `UNKNOWN` oznacza brak danych, a nie "bezpieczny".
- **Cache SQLite (TTL):** powtórne zapytania nie zużywają limitu API. Błędy nie są cache'owane.
- **Rate limiting + ponowienia:** domyślnie 4 zapytania/min do VirusTotal (limit darmowego planu), ponowienia przy 429/5xx z respektowaniem `Retry-After`.
- **Formaty wyjścia:** Markdown (domyślnie), JSON, CSV; zapis do pliku (`-o`).
- **Automatyzacja:** `--fail-on malicious|suspicious` zwraca kod wyjścia 2, więc da się to wpiąć w skrypt lub pipeline.

## Instalacja

```bash
git clone https://github.com/barzim1/ioc-enricher.git
cd ioc-enricher
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # i uzupełnij klucze API
```

Klucze trzymane są wyłącznie lokalnie w `.env` (plik jest w `.gitignore`):

```
VT_API_KEY=...
ABUSEIPDB_API_KEY=...
```

Provider bez klucza jest pomijany z ostrzeżeniem, więc wystarczy jeden z nich.

## Użycie

```bash
# pojedyncze wskaźniki (typ wykrywany automatycznie)
ioc-enricher 185.220.101.5 evil-domain.com hxxp://bad[.]site/payload

# stare flagi nadal działają
ioc-enricher -i 8.8.8.8 -H 44d88612fea8a8f36de82e1278abb02f

# lista z pliku (jeden IoC na linię, # = komentarz)
ioc-enricher -f iocs.txt --format json -o report.json

# wyciągnięcie IoC z logu i sprawdzenie ich
ioc-enricher -x /var/log/auth.log -o triage.md

# z potoku
cat alert.txt | ioc-enricher -x - --fail-on malicious
```

Bez instalacji pakietu można też uruchomić `python enrich.py ...` lub `python -m ioc_enricher ...`.

## Scoring

| Składnik | Punkty |
|:---|:---|
| VirusTotal | `min(80, 6 × złośliwe + 2 × podejrzane)` |
| AbuseIPDB | `round(0.4 × pewność nadużyć)` (0-40) |
| Węzeł wyjściowy Tor (AbuseIPDB) | +10 |
| Ujemna reputacja społeczności VT | +5 |

Progi: **≥70 MALICIOUS**, **≥30 SUSPICIOUS**, **≥1 LOW RISK**, **0 CLEAN**, brak danych = **UNKNOWN**. Hashe, domeny i URL są oceniane wyłącznie przez VirusTotal, więc do MALICIOUS wystarczy im 12 złośliwych silników. Wagi są arbitralne i jawne (`ioc_enricher/scoring.py`). Traktuj wynik jako pomoc w triage, a nie wyrok.

## Kody wyjścia

| Kod | Znaczenie |
|:---:|:---|
| 0 | OK |
| 1 | błąd użycia/konfiguracji (zły IoC, brak kluczy, brak wskaźników) |
| 2 | osiągnięto próg z `--fail-on` |

## Ograniczenia

- Darmowy VirusTotal to 4 zapytania/min i 500/dzień. Duże listy będą trwać (narzędzie wypisze szacunek), cache pomaga przy powtórkach.
- Adresy prywatne i zarezerwowane (RFC1918, loopback, zakresy dokumentacyjne) są domyślnie pomijane (`--include-private`).
- Ekstrakcja domen z tekstu jest heurystyczna: nazwy plików z popularnymi rozszerzeniami są odrzucane, ale fałszywe trafienia są możliwe.
- Testy jednostkowe używają zamockowanych odpowiedzi HTTP. Format odpowiedzi API wynika z dokumentacji dostawców, więc przy zmianach po ich stronie parser może wymagać poprawek.

## Rozwój

```bash
pip install -e ".[dev]"
pytest
```

Struktura: `indicators.py` (rozpoznawanie/ekstrakcja), `providers.py` (VirusTotal, AbuseIPDB), `scoring.py`, `cache.py`, `ratelimit.py`, `enricher.py` (orkiestracja), `report.py`, `cli.py`. Nowy provider to jedna klasa dziedzicząca po `Provider`.

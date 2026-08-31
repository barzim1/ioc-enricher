# IoC Auto-Enricher 🛡️

Lekkie narzędzie CLI stworzone z myślą o analitykach pierwszej linii SOC (Security Operations Center). Automatyzuje proces wstępnego wzbogacania wskaźników kompromitacji (IoC) poprzez integrację z API VirusTotal. Zamiast ręcznie przeklejać dane między zakładkami, skrypt natychmiast generuje sformatowaną tabelę w Markdownie, gotową do umieszczenia w systemie biletowym (Jira, TheHive, ServiceNow).

**Główne funkcje**
* **Skanowanie IP (`-i`):** Pobiera statystyki detekcji, kraj oraz właściciela infrastruktury (ASN).
* **Skanowanie Hashy (`-H`):** Weryfikuje pliki (MD5/SHA1/SHA256) i wyciąga ich najpopularniejsze nazwy z sieci.
* **Formatowanie Triage:** Wynik jest od razu zrzucony do tabeli Markdown, co oszczędza czas przy dokumentowaniu incydentu.
* **Bezpieczeństwo:** Klucze API są wczytywane lokalnie z pliku `.env`, zapobiegając wyciekom poświadczeń.

**Instalacja**
1. Sklonuj repozytorium:
   ```bash
   git clone [https://github.com/barzim1/ioc-enricher.git]
   cd ioc-enricher

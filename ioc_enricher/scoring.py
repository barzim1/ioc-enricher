"""Jawny, wyjaśnialny scoring 0-100. Każdy punkt ma uzasadnienie w `reasons`.

Składniki:
  VirusTotal : min(80, 6 * malicious + 2 * suspicious)   (12 złośliwych silników = MALICIOUS samo w sobie)
  AbuseIPDB  : round(0.4 * abuse_confidence)          (0-40)
  Tor exit   : +10
  Reputacja VT < 0 : +5

Progi: >=70 MALICIOUS, >=30 SUSPICIOUS, >=1 LOW RISK, 0 CLEAN.
Brak jakichkolwiek danych od providerów => UNKNOWN (to NIE znaczy "bezpieczny").
"""
from __future__ import annotations

from typing import List

from .indicators import Indicator
from .models import ProviderResult, Verdict

MALICIOUS_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 30

RECOMMENDATIONS = {
    "MALICIOUS": "Eskalacja / blokada IoC, sprawdzenie hostów, które się z nim komunikowały.",
    "SUSPICIOUS": "Zweryfikować kontekst (kto, kiedy, jaki proces). Rozważyć dodanie do watchlisty.",
    "LOW RISK": "Pojedyncze, słabe sygnały. Zwykle false positive, ale zanotować w tickecie.",
    "CLEAN": "Brak detekcji u providerów. Nie wyklucza to nowego/celowanego zagrożenia.",
    "UNKNOWN": "Brak danych. Sprawdzić ręcznie (sandbox, WHOIS, kontekst w logach).",
}


def score(indicator: Indicator, results: List[ProviderResult]) -> Verdict:
    usable = [r for r in results if r.has_data]
    if not usable:
        reasons = []
        for r in results:
            if r.error:
                reasons.append(f"{r.provider}: błąd ({r.error})")
            elif r.not_found:
                reasons.append(f"{r.provider}: brak wpisu w bazie")
        return Verdict(0, "UNKNOWN", reasons or ["brak danych od providerów"],
                       RECOMMENDATIONS["UNKNOWN"])

    total = 0
    reasons: List[str] = []

    for r in usable:
        if r.provider == "virustotal":
            pts = min(80, 6 * r.malicious + 2 * r.suspicious)
            if pts:
                reasons.append(
                    f"VirusTotal: {r.malicious} złośliwych / {r.suspicious} podejrzanych "
                    f"z {r.total_engines} silników (+{pts})"
                )
            else:
                reasons.append(f"VirusTotal: 0 detekcji z {r.total_engines} silników")
            total += pts
            rep = r.details.get("reputation")
            if isinstance(rep, int) and rep < 0:
                total += 5
                reasons.append(f"VirusTotal: ujemna reputacja społeczności ({rep}) (+5)")

        elif r.provider == "abuseipdb":
            pts = round(0.4 * (r.abuse_confidence or 0))
            reports = r.details.get("total_reports", 0)
            reasons.append(
                f"AbuseIPDB: pewność nadużyć {r.abuse_confidence}%, {reports} zgłoszeń"
                + (f" (+{pts})" if pts else "")
            )
            total += pts
            if r.details.get("is_tor"):
                total += 10
                reasons.append("AbuseIPDB: węzeł wyjściowy Tor (+10)")

    total = max(0, min(100, total))
    if total >= MALICIOUS_THRESHOLD:
        label = "MALICIOUS"
    elif total >= SUSPICIOUS_THRESHOLD:
        label = "SUSPICIOUS"
    elif total >= 1:
        label = "LOW RISK"
    else:
        label = "CLEAN"
    return Verdict(total, label, reasons, RECOMMENDATIONS[label])

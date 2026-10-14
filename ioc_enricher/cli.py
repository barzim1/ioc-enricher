from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List, Optional

from dotenv import find_dotenv, load_dotenv

from . import __version__
from .cache import Cache
from .enricher import Enricher
from .indicators import Indicator, classify, extract, parse_list
from .providers import AbuseIPDB, Provider, VirusTotal
from .ratelimit import RateLimiter
from .report import FORMATTERS

PLACEHOLDER_KEYS = {"", "TWOJ_KLUCZ", "YOUR_KEY", "changeme"}
EXIT_OK, EXIT_ERROR, EXIT_THRESHOLD = 0, 1, 2
THRESHOLD_LABELS = {
    "suspicious": {"SUSPICIOUS", "MALICIOUS"},
    "malicious": {"MALICIOUS"},
}


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc-enricher",
        description="Narzędzie SOC: wzbogacanie IoC (IP, domeny, URL, hashe) z oceną ryzyka.",
    )
    p.add_argument("indicators", nargs="*", help="IoC do sprawdzenia (obsługuje zapis hxxp / [.])")
    p.add_argument("-i", "--ip", action="append", default=[], help="adres IP (alias, można powtarzać)")
    p.add_argument("-H", "--hash", action="append", default=[], help="hash MD5/SHA1/SHA256 (alias)")
    p.add_argument("-f", "--file", help="plik z listą IoC, jeden na linię ('-' = stdin)")
    p.add_argument("-x", "--extract", metavar="PLIK",
                   help="wyciągnij IoC z logu/tekstu i je sprawdź ('-' = stdin)")
    p.add_argument("--include-private", action="store_true",
                   help="nie pomijaj adresów prywatnych/lokalnych")
    p.add_argument("--providers", default="virustotal,abuseipdb",
                   help="lista providerów po przecinku (domyślnie: virustotal,abuseipdb)")
    p.add_argument("--format", choices=sorted(FORMATTERS), default="md", help="format wyjścia")
    p.add_argument("-o", "--output", help="zapisz raport do pliku zamiast na stdout")
    p.add_argument("--no-cache", action="store_true", help="wyłącz cache")
    p.add_argument("--cache-ttl", type=float, default=24.0, metavar="GODZ",
                   help="ważność cache w godzinach (domyślnie 24)")
    p.add_argument("--cache-path", default=os.getenv(
        "IOC_ENRICHER_CACHE", "~/.cache/ioc-enricher/cache.sqlite"))
    p.add_argument("--vt-rate", type=float, default=4.0, metavar="N",
                   help="limit zapytań VirusTotal na minutę (free tier: 4)")
    p.add_argument("--fail-on", choices=sorted(THRESHOLD_LABELS),
                   help="zwróć kod 2, jeśli któryś IoC osiągnie ten poziom (do automatyzacji)")
    p.add_argument("-q", "--quiet", action="store_true", help="bez komunikatów postępu")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def build_providers(names: List[str], env: Dict[str, str], vt_rate: float,
                    session=None) -> List[Provider]:
    providers: List[Provider] = []
    for name in names:
        if name == "virustotal":
            key = env.get("VT_API_KEY", "")
            if key in PLACEHOLDER_KEYS:
                _err("[!] Pomijam virustotal: brak VT_API_KEY w .env")
                continue
            providers.append(VirusTotal(key, session=session, limiter=RateLimiter(vt_rate)))
        elif name == "abuseipdb":
            key = env.get("ABUSEIPDB_API_KEY", "")
            if key in PLACEHOLDER_KEYS:
                _err("[!] Pomijam abuseipdb: brak ABUSEIPDB_API_KEY w .env")
                continue
            providers.append(AbuseIPDB(key, session=session, limiter=RateLimiter(60)))
        else:
            raise ValueError(f"Nieznany provider: {name}")
    return providers


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def collect_indicators(args: argparse.Namespace) -> List[Indicator]:
    collected: List[Indicator] = []
    seen = set()

    def add(ind: Indicator) -> None:
        if ind not in seen:
            seen.add(ind)
            collected.append(ind)

    invalid = []
    for raw in [*args.indicators, *args.ip, *args.hash]:
        ind = classify(raw)
        if ind is None:
            invalid.append(raw)
        else:
            add(ind)
    if invalid:
        raise ValueError("Nierozpoznane wskaźniki: " + ", ".join(repr(i) for i in invalid))

    if args.file:
        for ind in parse_list(_read(args.file).splitlines()):
            add(ind)
    if args.extract:
        for ind in extract(_read(args.extract), include_private=True):
            add(ind)

    if not args.include_private:
        skipped = [i for i in collected if i.is_private]
        if skipped:
            _err(f"[i] Pominięto {len(skipped)} adresów prywatnych/lokalnych "
                 f"(użyj --include-private): {', '.join(i.value for i in skipped[:5])}"
                 + (" ..." if len(skipped) > 5 else ""))
        collected = [i for i in collected if not i.is_private]
    return collected


def main(argv: Optional[List[str]] = None, session=None) -> int:
    load_dotenv(find_dotenv(usecwd=True))
    parser = build_parser()
    args = parser.parse_args(argv)

    if not (args.indicators or args.ip or args.hash or args.file or args.extract):
        parser.print_usage(sys.stderr)
        _err("[-] Podaj przynajmniej jeden IoC, -f PLIK albo -x PLIK.")
        return EXIT_ERROR

    try:
        indicators = collect_indicators(args)
        names = [n.strip().lower() for n in args.providers.split(",") if n.strip()]
        providers = build_providers(names, dict(os.environ), args.vt_rate, session=session)
    except (ValueError, OSError) as exc:
        _err(f"[-] {exc}")
        return EXIT_ERROR

    if not providers:
        _err("[-] Brak skonfigurowanych providerów. Uzupełnij klucze w pliku .env (zob. .env.example).")
        return EXIT_ERROR
    if not indicators:
        _err("[-] Brak wskaźników do sprawdzenia.")
        return EXIT_ERROR

    cache = None if args.no_cache else Cache(args.cache_path, int(args.cache_ttl * 3600))
    progress = None if args.quiet else _err

    vt_calls = sum(1 for p in providers if p.name == "virustotal" for i in indicators if p.supports(i))
    if vt_calls > 1 and not args.quiet:
        eta = int((vt_calls - 1) * 60 / args.vt_rate)
        _err(f"[i] {vt_calls} zapytań do VirusTotal przy limicie {args.vt_rate:g}/min "
             f"(do ~{eta} s, mniej przy trafieniach w cache)")

    try:
        enricher = Enricher(providers, cache=cache, on_progress=progress)
        results = enricher.enrich_many(indicators)
    except KeyboardInterrupt:
        _err("[-] Przerwano.")
        return EXIT_ERROR
    finally:
        if cache:
            cache.close()

    report = FORMATTERS[args.format](results)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        _err(f"[+] Zapisano raport: {args.output}")
    else:
        sys.stdout.write(report)

    if args.fail_on and any(e.verdict.label in THRESHOLD_LABELS[args.fail_on] for e in results):
        return EXIT_THRESHOLD
    return EXIT_OK


def run() -> None:
    sys.exit(main())

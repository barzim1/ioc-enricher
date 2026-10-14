"""Formatery raportu: Markdown (do ticketu), JSON, CSV."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import List

from .models import Enrichment

_LABEL_ORDER = {"MALICIOUS": 0, "SUSPICIOUS": 1, "LOW RISK": 2, "UNKNOWN": 3, "CLEAN": 4}


def sort_by_risk(items: List[Enrichment]) -> List[Enrichment]:
    return sorted(items, key=lambda e: (_LABEL_ORDER.get(e.verdict.label, 9), -e.verdict.score))


def _short(value: str, limit: int = 60) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _escape(value: str) -> str:
    return value.replace("|", "\\|")


def to_markdown(items: List[Enrichment]) -> str:
    items = sort_by_risk(items)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"**Raport IoC** ({now}, {len(items)} wskaźników)", ""]

    out += ["| IoC | Typ | Werdykt | Score | VT zło/podej | AbuseIPDB |",
            "|:---|:---:|:---:|:---:|:---:|:---:|"]
    for e in items:
        vt = next((r for r in e.results if r.provider == "virustotal" and r.has_data), None)
        ab = next((r for r in e.results if r.provider == "abuseipdb" and r.has_data), None)
        vt_cell = f"{vt.malicious}/{vt.suspicious}" if vt else "-"
        ab_cell = f"{ab.abuse_confidence}%" if ab else "-"
        out.append(
            f"| `{_escape(_short(e.indicator.value))}` | {e.indicator.type.value} | "
            f"**{e.verdict.label}** | {e.verdict.score} | {vt_cell} | {ab_cell} |"
        )

    out += ["", "**Szczegóły**", ""]
    for e in items:
        out.append(f"- `{_escape(_short(e.indicator.value, 100))}`: {e.verdict.label} ({e.verdict.score}/100)")
        for reason in e.verdict.reasons:
            out.append(f"  - {reason}")
        for r in e.results:
            meta = {k: v for k, v in r.details.items() if v not in (None, "", [])}
            if meta and r.has_data:
                pretty = ", ".join(f"{k}={v}" for k, v in meta.items())
                out.append(f"  - dane {r.provider}{' (cache)' if r.cached else ''}: {pretty}")
        out.append(f"  - rekomendacja: {e.verdict.recommendation}")
    return "\n".join(out) + "\n"


def to_json(items: List[Enrichment]) -> str:
    payload = [
        {
            "indicator": e.indicator.value,
            "type": e.indicator.type.value,
            "verdict": e.verdict.label,
            "score": e.verdict.score,
            "reasons": e.verdict.reasons,
            "recommendation": e.verdict.recommendation,
            "results": [r.to_dict() for r in e.results],
        }
        for e in sort_by_risk(items)
    ]
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def to_csv(items: List[Enrichment]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["indicator", "type", "verdict", "score", "vt_malicious",
                     "vt_suspicious", "abuse_confidence"])
    for e in sort_by_risk(items):
        vt = next((r for r in e.results if r.provider == "virustotal" and r.has_data), None)
        ab = next((r for r in e.results if r.provider == "abuseipdb" and r.has_data), None)
        writer.writerow([
            e.indicator.value, e.indicator.type.value, e.verdict.label, e.verdict.score,
            vt.malicious if vt else "", vt.suspicious if vt else "",
            ab.abuse_confidence if ab else "",
        ])
    return buf.getvalue()


FORMATTERS = {"md": to_markdown, "json": to_json, "csv": to_csv}

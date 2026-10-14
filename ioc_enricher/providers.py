"""Providery threat intelligence: VirusTotal i AbuseIPDB."""
from __future__ import annotations

import base64
import time
from typing import Any, Callable, Dict, Optional
from urllib.parse import quote

import requests

from .indicators import Indicator, IOCType
from .models import ProviderResult
from .ratelimit import RateLimiter

DEFAULT_TIMEOUT = 15
MAX_RETRIES = 2


class Provider:
    name = "base"
    supported: frozenset = frozenset()

    def __init__(self, api_key: str, session: Optional[requests.Session] = None,
                 limiter: Optional[RateLimiter] = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.api_key = api_key
        self.session = session or requests.Session()
        self.limiter = limiter
        self._sleep = sleep

    def supports(self, indicator: Indicator) -> bool:
        return indicator.type in self.supported

    def lookup(self, indicator: Indicator) -> ProviderResult:
        raise NotImplementedError

    def _get(self, url: str, headers: Dict[str, str],
             params: Optional[Dict[str, Any]] = None):
        """GET z rate limitem i ponowieniem przy 429/5xx. Zwraca response albo ProviderResult z błędem."""
        last_error = "nieznany błąd"
        for attempt in range(MAX_RETRIES + 1):
            if self.limiter:
                self.limiter.wait()
            try:
                resp = self.session.get(url, headers=headers, params=params,
                                        timeout=DEFAULT_TIMEOUT)
            except requests.RequestException as exc:
                last_error = f"błąd połączenia: {exc}"
            else:
                if resp.status_code == 429 or resp.status_code >= 500:
                    last_error = f"HTTP {resp.status_code}"
                    if attempt < MAX_RETRIES:
                        retry_after = resp.headers.get("Retry-After", "")
                        delay = float(retry_after) if retry_after.isdigit() else 2 ** (attempt + 1)
                        self._sleep(min(delay, 60))
                        continue
                else:
                    return resp
            if attempt < MAX_RETRIES:
                self._sleep(2 ** (attempt + 1))
        return ProviderResult(provider=self.name, ok=False, error=last_error)

    def _http_error(self, resp) -> ProviderResult:
        if resp.status_code in (401, 403):
            msg = "nieprawidłowy klucz API lub brak uprawnień"
        else:
            msg = f"HTTP {resp.status_code}"
        return ProviderResult(provider=self.name, ok=False, error=msg)


class VirusTotal(Provider):
    name = "virustotal"
    supported = frozenset({
        IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL,
        IOCType.MD5, IOCType.SHA1, IOCType.SHA256,
    })
    BASE = "https://www.virustotal.com/api/v3"

    def _endpoint(self, ind: Indicator) -> str:
        if ind.type.is_ip:
            return f"{self.BASE}/ip_addresses/{quote(ind.value, safe='')}"
        if ind.type is IOCType.DOMAIN:
            return f"{self.BASE}/domains/{quote(ind.value, safe='')}"
        if ind.type is IOCType.URL:
            ident = base64.urlsafe_b64encode(ind.value.encode()).decode().rstrip("=")
            return f"{self.BASE}/urls/{ident}"
        return f"{self.BASE}/files/{ind.value}"

    def lookup(self, indicator: Indicator) -> ProviderResult:
        resp = self._get(self._endpoint(indicator),
                         {"accept": "application/json", "x-apikey": self.api_key})
        if isinstance(resp, ProviderResult):
            return resp
        if resp.status_code == 404:
            return ProviderResult(provider=self.name, not_found=True)
        if resp.status_code != 200:
            return self._http_error(resp)

        try:
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
        except (ValueError, KeyError, TypeError):
            return ProviderResult(provider=self.name, ok=False,
                                  error="nieoczekiwany format odpowiedzi")

        details: Dict[str, Any] = {"reputation": attrs.get("reputation")}
        for key in ("country", "as_owner", "registrar", "meaningful_name",
                    "type_description", "tags"):
            if attrs.get(key):
                details[key] = attrs[key]
        names = attrs.get("names") or []
        if names and "meaningful_name" not in details:
            details["meaningful_name"] = names[0]

        return ProviderResult(
            provider=self.name,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            total_engines=sum(int(v) for v in stats.values()),
            details=details,
        )


class AbuseIPDB(Provider):
    name = "abuseipdb"
    supported = frozenset({IOCType.IPV4, IOCType.IPV6})
    URL = "https://api.abuseipdb.com/api/v2/check"

    def lookup(self, indicator: Indicator) -> ProviderResult:
        resp = self._get(
            self.URL,
            {"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": indicator.value, "maxAgeInDays": 90},
        )
        if isinstance(resp, ProviderResult):
            return resp
        if resp.status_code != 200:
            return self._http_error(resp)

        try:
            data = resp.json()["data"]
            confidence = int(data["abuseConfidenceScore"])
        except (ValueError, KeyError, TypeError):
            return ProviderResult(provider=self.name, ok=False,
                                  error="nieoczekiwany format odpowiedzi")

        details = {
            "total_reports": data.get("totalReports"),
            "distinct_users": data.get("numDistinctUsers"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
            "whitelisted": data.get("isWhitelisted"),
        }
        return ProviderResult(
            provider=self.name,
            abuse_confidence=confidence,
            details={k: v for k, v in details.items() if v is not None},
        )

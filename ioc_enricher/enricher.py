from __future__ import annotations

from typing import Callable, Iterable, List, Optional

from .cache import Cache
from .indicators import Indicator
from .models import Enrichment, ProviderResult
from .providers import Provider
from .scoring import score


class Enricher:
    def __init__(self, providers: List[Provider], cache: Optional[Cache] = None,
                 on_progress: Optional[Callable[[str], None]] = None):
        self.providers = providers
        self.cache = cache
        self._progress = on_progress or (lambda msg: None)

    def enrich(self, indicator: Indicator) -> Enrichment:
        results: List[ProviderResult] = []
        for provider in self.providers:
            if not provider.supports(indicator):
                continue
            results.append(self._lookup(provider, indicator))
        return Enrichment(indicator, results, score(indicator, results))

    def enrich_many(self, indicators: Iterable[Indicator]) -> List[Enrichment]:
        return [self.enrich(i) for i in indicators]

    def _lookup(self, provider: Provider, indicator: Indicator) -> ProviderResult:
        key = Cache.make_key(provider.name, indicator.type.value, indicator.value)
        if self.cache:
            hit = self.cache.get(key)
            if hit is not None:
                result = ProviderResult.from_dict(hit)
                result.cached = True
                self._progress(f"[cache] {provider.name}: {indicator.value}")
                return result

        self._progress(f"[api]   {provider.name}: {indicator.value}")
        result = provider.lookup(indicator)
        # Błędów (limity, timeouty) nie cache'ujemy, żeby kolejne uruchomienie mogło spróbować ponownie.
        if self.cache and result.ok:
            self.cache.put(key, result.to_dict())
        return result

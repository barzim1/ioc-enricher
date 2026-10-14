import pytest

from ioc_enricher.cache import Cache
from ioc_enricher.enricher import Enricher
from ioc_enricher.indicators import classify
from ioc_enricher.providers import VirusTotal
from ioc_enricher.ratelimit import RateLimiter

from conftest import FakeResponse, FakeSession, vt_payload


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_cache_roundtrip_and_ttl():
    clock = Clock()
    c = Cache(":memory:", ttl_seconds=60, clock=clock)
    key = Cache.make_key("virustotal", "ipv4", "8.8.8.8")
    assert c.get(key) is None
    c.put(key, {"a": 1})
    assert c.get(key) == {"a": 1}
    clock.now += 61
    assert c.get(key) is None


def test_cache_purge():
    clock = Clock()
    c = Cache(":memory:", ttl_seconds=10, clock=clock)
    c.put("k1", {"x": 1})
    clock.now += 11
    c.put("k2", {"x": 2})
    assert c.purge_expired() == 1
    assert c.get("k2") == {"x": 2}


def test_enricher_uses_cache_and_skips_api(no_sleep):
    _, sleep = no_sleep
    session = FakeSession(FakeResponse(200, vt_payload(malicious=2)))
    enricher = Enricher([VirusTotal("K", session=session, sleep=sleep)], cache=Cache(":memory:"))
    ind = classify("185.220.101.5")
    first = enricher.enrich(ind)
    second = enricher.enrich(ind)
    assert len(session.calls) == 1
    assert not first.results[0].cached and second.results[0].cached
    assert second.results[0].malicious == 2


def test_errors_are_not_cached(no_sleep):
    _, sleep = no_sleep
    session = FakeSession(FakeResponse(401), FakeResponse(200, vt_payload()))
    enricher = Enricher([VirusTotal("K", session=session, sleep=sleep)], cache=Cache(":memory:"))
    ind = classify("8.8.8.8")
    assert not enricher.enrich(ind).results[0].ok
    assert enricher.enrich(ind).results[0].ok
    assert len(session.calls) == 2


def test_enricher_skips_unsupported_provider(no_sleep):
    from ioc_enricher.providers import AbuseIPDB
    _, sleep = no_sleep
    session = FakeSession()
    enricher = Enricher([AbuseIPDB("K", session=session, sleep=sleep)])
    result = enricher.enrich(classify("example.com"))
    assert result.results == [] and result.verdict.label == "UNKNOWN"
    assert session.calls == []


def test_ratelimiter_spaces_requests():
    clock, slept = Clock(), []
    rl = RateLimiter(4, clock=clock, sleep=slept.append)  # 15 s odstępu
    assert rl.wait() == 0
    clock.now += 5
    assert rl.wait() == pytest.approx(10)
    assert slept == [pytest.approx(10)]


def test_ratelimiter_no_wait_after_gap():
    clock, slept = Clock(), []
    rl = RateLimiter(4, clock=clock, sleep=slept.append)
    rl.wait()
    clock.now += 20
    assert rl.wait() == 0 and slept == []


def test_ratelimiter_rejects_bad_rate():
    with pytest.raises(ValueError):
        RateLimiter(0)

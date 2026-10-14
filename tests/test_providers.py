import base64

import requests

from ioc_enricher.indicators import classify
from ioc_enricher.providers import AbuseIPDB, VirusTotal

from conftest import FakeResponse, FakeSession, abuse_payload, vt_payload


def make_vt(session, sleep):
    return VirusTotal("KEY", session=session, sleep=sleep)


def test_vt_ip_parsing(no_sleep):
    _, sleep = no_sleep
    s = FakeSession(FakeResponse(200, vt_payload(malicious=4, suspicious=1, country="RU",
                                                 as_owner="Evil AS", reputation=-3)))
    r = make_vt(s, sleep).lookup(classify("185.220.101.5"))
    assert r.ok and (r.malicious, r.suspicious, r.total_engines) == (4, 1, 75)
    assert r.details["country"] == "RU" and r.details["reputation"] == -3
    assert s.calls[0]["url"].endswith("/ip_addresses/185.220.101.5")
    assert s.calls[0]["headers"]["x-apikey"] == "KEY"


def test_vt_endpoints_per_type(no_sleep):
    _, sleep = no_sleep
    vt = make_vt(FakeSession(), sleep)
    assert vt._endpoint(classify("example.com")).endswith("/domains/example.com")
    assert vt._endpoint(classify("a" * 64)).endswith("/files/" + "a" * 64)
    url_ind = classify("http://evil.com/a?b=1")
    ident = base64.urlsafe_b64encode(url_ind.value.encode()).decode().rstrip("=")
    assert vt._endpoint(url_ind).endswith("/urls/" + ident)
    assert "=" not in vt._endpoint(url_ind)


def test_vt_404_is_not_found(no_sleep):
    _, sleep = no_sleep
    r = make_vt(FakeSession(FakeResponse(404)), sleep).lookup(classify("a" * 64))
    assert r.not_found and r.ok and not r.has_data


def test_vt_bad_key(no_sleep):
    _, sleep = no_sleep
    r = make_vt(FakeSession(FakeResponse(401)), sleep).lookup(classify("8.8.8.8"))
    assert not r.ok and "klucz" in r.error


def test_vt_retries_on_429_then_succeeds(no_sleep):
    slept, sleep = no_sleep
    s = FakeSession(FakeResponse(429, headers={"Retry-After": "7"}),
                    FakeResponse(200, vt_payload()))
    r = make_vt(s, sleep).lookup(classify("8.8.8.8"))
    assert r.ok and len(s.calls) == 2
    assert slept == [7.0]


def test_vt_gives_up_after_retries(no_sleep):
    slept, sleep = no_sleep
    s = FakeSession(*[FakeResponse(503) for _ in range(3)])
    r = make_vt(s, sleep).lookup(classify("8.8.8.8"))
    assert not r.ok and "503" in r.error and len(s.calls) == 3


def test_vt_network_error(no_sleep):
    _, sleep = no_sleep
    s = FakeSession(*[requests.ConnectionError("boom") for _ in range(3)])
    r = make_vt(s, sleep).lookup(classify("8.8.8.8"))
    assert not r.ok and "połączenia" in r.error


def test_vt_malformed_json(no_sleep):
    _, sleep = no_sleep
    r = make_vt(FakeSession(FakeResponse(200, {"unexpected": 1})), sleep).lookup(classify("8.8.8.8"))
    assert not r.ok and "format" in r.error


def test_abuseipdb_parsing(no_sleep):
    _, sleep = no_sleep
    s = FakeSession(FakeResponse(200, abuse_payload(87, 120, isTor=True, usageType="Data Center")))
    r = AbuseIPDB("K", session=s, sleep=sleep).lookup(classify("185.220.101.5"))
    assert r.abuse_confidence == 87
    assert r.details["total_reports"] == 120 and r.details["is_tor"] is True
    assert s.calls[0]["params"]["ipAddress"] == "185.220.101.5"
    assert s.calls[0]["headers"]["Key"] == "K"


def test_support_matrix():
    ip, dom, h = classify("8.8.8.8"), classify("example.com"), classify("a" * 64)
    vt, ab = VirusTotal("k"), AbuseIPDB("k")
    assert vt.supports(ip) and vt.supports(dom) and vt.supports(h)
    assert ab.supports(ip) and not ab.supports(dom) and not ab.supports(h)

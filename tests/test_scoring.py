from ioc_enricher.indicators import classify
from ioc_enricher.models import ProviderResult
from ioc_enricher.scoring import score

IP = classify("185.220.101.5")


def vt(mal=0, sus=0, total=70, **details):
    return ProviderResult("virustotal", malicious=mal, suspicious=sus,
                          total_engines=total, details=details)


def ab(conf=0, **details):
    return ProviderResult("abuseipdb", abuse_confidence=conf, details=details)


def test_clean():
    v = score(IP, [vt(), ab(0)])
    assert (v.label, v.score) == ("CLEAN", 0)


def test_low_risk_single_engine():
    v = score(IP, [vt(sus=1)])
    assert v.label == "LOW RISK" and v.score == 2


def test_suspicious_band():
    v = score(IP, [vt(mal=3)])  # 18 + abuse 0
    assert v.label == "LOW RISK"
    v = score(IP, [vt(mal=5), ab(10)])  # 30 + 4
    assert v.label == "SUSPICIOUS" and v.score == 34


def test_malicious_combined():
    v = score(IP, [vt(mal=12), ab(100)])  # 60 + 40
    assert v.label == "MALICIOUS" and v.score == 100


def test_vt_component_capped():
    assert score(IP, [vt(mal=50)]).score == 60


def test_tor_and_negative_reputation_bonus():
    v = score(IP, [vt(reputation=-10), ab(50, is_tor=True)])
    assert v.score == 5 + 20 + 10
    assert any("Tor" in r for r in v.reasons)


def test_score_never_exceeds_100():
    assert score(IP, [vt(mal=50, reputation=-5), ab(100, is_tor=True)]).score == 100


def test_unknown_when_nothing_usable():
    results = [ProviderResult("virustotal", not_found=True),
               ProviderResult("abuseipdb", ok=False, error="HTTP 429")]
    v = score(IP, results)
    assert v.label == "UNKNOWN" and v.score == 0
    assert any("429" in r for r in v.reasons)


def test_unknown_when_no_results():
    assert score(IP, []).label == "UNKNOWN"


def test_error_provider_ignored_when_other_has_data():
    v = score(IP, [ProviderResult("abuseipdb", ok=False, error="x"), vt(mal=12)])
    assert v.label == "SUSPICIOUS" and v.score == 60

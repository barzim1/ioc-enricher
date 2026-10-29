import pytest

from ioc_enricher.indicators import (
    DEFAULT_ALLOWLIST, IOCType, classify, extract, is_allowlisted, load_allowlist, parse_list, refang,
)

SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


@pytest.mark.parametrize("raw,expected", [
    ("hxxps://evil[.]com/a", "https://evil.com/a"),
    ("1[.]2[.]3[.]4", "1.2.3.4"),
    ("evil(.)com", "evil.com"),
    ("hxxp[://]evil.com", "http://evil.com"),
])
def test_refang(raw, expected):
    assert refang(raw) == expected


@pytest.mark.parametrize("raw,kind", [
    ("8.8.8.8", IOCType.IPV4),
    ("2001:4860:4860::8888", IOCType.IPV6),
    ("Example.COM", IOCType.DOMAIN),
    ("https://example.com/path?q=1", IOCType.URL),
    ("hxxp://evil[.]com/x", IOCType.URL),
    (MD5.upper(), IOCType.MD5),
    (SHA1, IOCType.SHA1),
    (SHA256, IOCType.SHA256),
])
def test_classify_types(raw, kind):
    assert classify(raw).type is kind


@pytest.mark.parametrize("raw", ["", "not an ioc", "999.1.1.1", "evil.exe", "abc", "ftp:///nohost"])
def test_classify_rejects(raw):
    assert classify(raw) is None


def test_classify_normalizes_case():
    assert classify("Example.COM").value == "example.com"
    assert classify(MD5.upper()).value == MD5


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1"])
def test_private_ips_flagged(ip):
    assert classify(ip).is_private


def test_public_ip_not_private():
    assert not classify("8.8.8.8").is_private


def test_extract_from_log_line():
    text = (
        f"Oct 14 10:01 sshd: Failed password from 185.220.101.5 port 22 "
        f"user=root host=evil[.]example.org "
        f"url=hxxp://bad[.]site/payload.exe sha256={SHA256} "
        f"internal=10.1.1.1 file=run.ps1 mail=user@corp.example.com"
    )
    values = {i.value for i in extract(text)}
    assert "185.220.101.5" in values
    assert "evil.example.org" in values
    assert "http://bad.site/payload.exe" in values
    assert SHA256 in values
    assert "10.1.1.1" not in values          # prywatne pomijane
    assert "run.ps1" not in values           # rozszerzenie pliku, nie domena
    assert "corp.example.com" in values      # domena nadawcy to wskaźnik (kluczowa przy phishingu)
    assert "user" not in values              # część lokalna adresu nigdy
    assert "bad.site" not in values          # domena z URL nie jest dublowana


def test_extract_email_local_part_is_not_a_domain():
    # regresja: `john.smith@corp.com` dawało "domenę" john.smith, wysyłaną potem do VirusTotala
    found = extract("login by john.smith@corp.example.com, sender anna.nowak@evil-support.com")
    values = {i.value for i in found}
    assert values == {"corp.example.com", "evil-support.com"}


def test_extract_can_skip_email_domains():
    assert extract("a.b@evil-support.com", email_domains=False) == []


def test_extract_ipv6():
    found = extract("conn from 2a00:1450:4001:81b::200e and [2606:4700::1111]:443")
    assert {(i.value, i.type) for i in found} == {
        ("2a00:1450:4001:81b::200e", IOCType.IPV6), ("2606:4700::1111", IOCType.IPV6),
    }


def test_extract_ipv6_private_flagged():
    (loopback,) = extract("::1", include_private=True)
    assert loopback.is_private


@pytest.mark.parametrize("text", [
    "at 2026-03-11T10:30:05 done",         # godzina
    "mac aa:bb:cc:dd:ee:ff seen",          # MAC
    "eui 00:1a:2b:ff:fe:3c:4d:5e seen",    # EUI-64: poprawna składnia IPv6, ale zakres zarezerwowany
    "std::vector and Foo:: bar",           # kod, nie adres
])
def test_extract_ipv6_false_positives(text):
    assert extract(text) == []


def test_url_host_is_lowercased_but_path_is_not():
    # ten sam URL zapisany inaczej nie może zużywać dwóch zapytań/wpisów w cache
    assert classify("HTTP://Bad.Site/Payload?X=1").value == "http://bad.site/Payload?X=1"
    assert classify("http://User:Pass@Bad.Site:8080/a").value == "http://User:Pass@bad.site:8080/a"
    assert classify("http://bad.site/a") == classify("http://BAD.SITE/a")


@pytest.mark.parametrize("domain,expected", [
    ("google.com", True),                 # wpis dokładny
    ("mail.google.com", False),           # wpis dokładny nie obejmuje subdomen
    ("docs.google.com", False),           # na tym hostuje się phishing
    ("login.microsoftonline.com", True),  # wildcard
    ("microsoftonline.com", True),        # wildcard obejmuje też apex
    ("evilmicrosoftonline.com", False),   # granica etykiety, nie sufiks tekstu
    ("microsoftonline.com.evil.example", False),
    ("EXAMPLE.org.", False),
])
def test_default_allowlist(domain, expected):
    assert is_allowlisted(domain, DEFAULT_ALLOWLIST) is expected


def test_load_allowlist_validates_entries():
    assert load_allowlist(["# firma", "", "*.Corp.example.com  # nasza", "intranet.local"]) == [
        "*.corp.example.com", "intranet.local",
    ]
    with pytest.raises(ValueError):
        load_allowlist(["https://corp.example.com"])


def test_extract_include_private_and_dedup():
    found = extract("10.1.1.1 and 10.1.1.1 and 8.8.8.8", include_private=True)
    assert [i.value for i in found] == ["10.1.1.1", "8.8.8.8"]


def test_hash_lengths_not_confused():
    found = extract(f"{SHA256} {SHA1} {MD5}")
    assert {i.type for i in found} == {IOCType.SHA256, IOCType.SHA1, IOCType.MD5}


def test_parse_list_skips_comments_and_blank():
    lines = ["# komentarz", "", "8.8.8.8  # dns", "8.8.8.8", "example.com"]
    assert [i.value for i in parse_list(lines)] == ["8.8.8.8", "example.com"]


def test_parse_list_rejects_garbage():
    with pytest.raises(ValueError):
        parse_list(["8.8.8.8", "garbage line"])

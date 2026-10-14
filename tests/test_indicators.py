import pytest

from ioc_enricher.indicators import IOCType, classify, extract, parse_list, refang

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
    assert "corp.example.com" not in values  # domena z adresu e-mail pomijana
    assert "bad.site" not in values          # domena z URL nie jest dublowana


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

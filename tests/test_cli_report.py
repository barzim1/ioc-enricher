import json

from ioc_enricher import cli

from conftest import FakeResponse, FakeSession, abuse_payload, vt_payload

SHA256 = "a" * 64


def run(argv, session, monkeypatch, tmp_path, capsys, keys=True):
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    if keys:
        monkeypatch.setenv("VT_API_KEY", "vt")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab")
    monkeypatch.chdir(tmp_path)  # żeby load_dotenv nie czytał prawdziwego .env
    code = cli.main(["--cache-path", str(tmp_path / "c.sqlite"), "--vt-rate", "6000", "-q", *argv],
                    session=session)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_single_ip_markdown(monkeypatch, tmp_path, capsys):
    s = FakeSession(FakeResponse(200, vt_payload(malicious=12, country="RU")),
                    FakeResponse(200, abuse_payload(100, 500)))
    code, out, _ = run(["185.220.101.5"], s, monkeypatch, tmp_path, capsys)
    assert code == 0
    assert "MALICIOUS" in out and "185.220.101.5" in out and "| 12/0 |" in out and "100%" in out


def test_legacy_flags_still_work(monkeypatch, tmp_path, capsys):
    s = FakeSession(FakeResponse(200, vt_payload()), FakeResponse(200, abuse_payload(0)),
                    FakeResponse(404))
    code, out, _ = run(["-i", "8.8.8.8", "-H", SHA256], s, monkeypatch, tmp_path, capsys)
    assert code == 0 and "CLEAN" in out and "UNKNOWN" in out


def test_json_output_sorted_by_risk(monkeypatch, tmp_path, capsys):
    s = FakeSession(FakeResponse(200, vt_payload()),            # 8.8.8.8 vt
                    FakeResponse(200, abuse_payload(0)),        # 8.8.8.8 abuse
                    FakeResponse(200, vt_payload(malicious=12)),   # 185.220.101.5 vt
                    FakeResponse(200, abuse_payload(100, 9)))      # 185.220.101.5 abuse
    code, out, _ = run(["--format", "json", "8.8.8.8", "185.220.101.5"], s, monkeypatch, tmp_path, capsys)
    data = json.loads(out)
    assert [d["indicator"] for d in data] == ["185.220.101.5", "8.8.8.8"]
    assert data[0]["verdict"] == "MALICIOUS" and data[0]["results"][0]["provider"] == "virustotal"


def test_csv_output(monkeypatch, tmp_path, capsys):
    s = FakeSession(FakeResponse(200, vt_payload(malicious=1)))
    code, out, _ = run(["--format", "csv", "--providers", "virustotal", "example.com"],
                       s, monkeypatch, tmp_path, capsys)
    lines = out.strip().splitlines()
    assert lines[0].startswith("indicator,type,verdict") and "example.com" in lines[1]


def test_fail_on_threshold(monkeypatch, tmp_path, capsys):
    s = FakeSession(FakeResponse(200, vt_payload(malicious=12)), FakeResponse(200, abuse_payload(100)))
    code, _, _ = run(["--fail-on", "malicious", "185.220.101.5"], s, monkeypatch, tmp_path, capsys)
    assert code == cli.EXIT_THRESHOLD


def test_private_ip_skipped(monkeypatch, tmp_path, capsys):
    s = FakeSession()
    code, out, err = run(["10.0.0.5"], s, monkeypatch, tmp_path, capsys)
    assert code == cli.EXIT_ERROR and s.calls == []


def test_extract_mode(monkeypatch, tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("Failed login from 185.220.101.5 internal 10.0.0.9\n")
    s = FakeSession(FakeResponse(200, vt_payload()), FakeResponse(200, abuse_payload(0)))
    code, out, _ = run(["-x", str(log)], s, monkeypatch, tmp_path, capsys)
    assert code == 0 and "185.220.101.5" in out and "10.0.0.9" not in out


def _extract_run(tmp_path, monkeypatch, capsys, extra=()):
    log = tmp_path / "mail.log"
    log.write_text("sender anna.nowak@evil-support.com via login.microsoftonline.com and corp.example.com\n")
    s = FakeSession(*(FakeResponse(200, vt_payload()) for _ in range(5)))
    code, out, err = run([*extra, "--providers", "virustotal", "-x", str(log)], s, monkeypatch, tmp_path, capsys)
    return code, out, err, s


def test_extract_skips_allowlisted_domains_and_says_so(monkeypatch, tmp_path, capsys):
    code, out, err, s = _extract_run(tmp_path, monkeypatch, capsys)
    queried = [c["url"].rsplit("/", 1)[-1] for c in s.calls]
    assert code == 0 and sorted(queried) == ["corp.example.com", "evil-support.com"]
    assert "anna.nowak" not in out and "login.microsoftonline.com" not in out
    assert "Pominięto 1 domen z allowlisty" in err and "login.microsoftonline.com" in err


def test_custom_allowlist_file(monkeypatch, tmp_path, capsys):
    (tmp_path / "allow.txt").write_text("# nasza firma\n*.example.com\n")
    code, out, err, s = _extract_run(tmp_path, monkeypatch, capsys, ["--allowlist", str(tmp_path / "allow.txt")])
    assert [c["url"].rsplit("/", 1)[-1] for c in s.calls] == ["evil-support.com"]


def test_no_allowlist_checks_everything(monkeypatch, tmp_path, capsys):
    code, out, err, s = _extract_run(tmp_path, monkeypatch, capsys, ["--no-allowlist"])
    assert len(s.calls) == 3 and "allowlisty" not in err


def test_no_email_domains(monkeypatch, tmp_path, capsys):
    code, out, err, s = _extract_run(tmp_path, monkeypatch, capsys, ["--no-email-domains"])
    assert [c["url"].rsplit("/", 1)[-1] for c in s.calls] == ["corp.example.com"]


def test_explicit_indicator_ignores_allowlist(monkeypatch, tmp_path, capsys):
    s = FakeSession(FakeResponse(200, vt_payload()))
    code, out, _ = run(["--providers", "virustotal", "login.microsoftonline.com"], s, monkeypatch, tmp_path, capsys)
    assert code == 0 and len(s.calls) == 1


def test_bad_allowlist_entry_is_error(monkeypatch, tmp_path, capsys):
    (tmp_path / "allow.txt").write_text("https://corp.example.com\n")
    log = tmp_path / "a.log"
    log.write_text("evil.example.org\n")
    code, _, err = run(["--allowlist", str(tmp_path / "allow.txt"), "-x", str(log)],
                       FakeSession(), monkeypatch, tmp_path, capsys)
    assert code == cli.EXIT_ERROR and "Nieprawidłowy wpis" in err


def test_file_list_and_output_file(monkeypatch, tmp_path, capsys):
    lst = tmp_path / "iocs.txt"
    lst.write_text("# lista\nexample.com\n")
    outfile = tmp_path / "report.md"
    s = FakeSession(FakeResponse(200, vt_payload()))
    code, out, _ = run(["-f", str(lst), "-o", str(outfile)], s, monkeypatch, tmp_path, capsys)
    assert code == 0 and out == "" and "example.com" in outfile.read_text()


def test_invalid_indicator_is_error(monkeypatch, tmp_path, capsys):
    code, _, err = run(["not an ioc"], FakeSession(), monkeypatch, tmp_path, capsys)
    assert code == cli.EXIT_ERROR and "Nierozpoznane" in err


def test_missing_keys_is_error(monkeypatch, tmp_path, capsys):
    code, _, err = run(["8.8.8.8"], FakeSession(), monkeypatch, tmp_path, capsys, keys=False)
    assert code == cli.EXIT_ERROR and "Brak skonfigurowanych" in err


def test_no_args_is_error(monkeypatch, tmp_path, capsys):
    code, _, _ = run([], FakeSession(), monkeypatch, tmp_path, capsys)
    assert code == cli.EXIT_ERROR


def test_cache_second_run_makes_no_calls(monkeypatch, tmp_path, capsys):
    s = FakeSession(FakeResponse(200, vt_payload(malicious=1)), FakeResponse(200, abuse_payload(5)))
    run(["185.220.101.5"], s, monkeypatch, tmp_path, capsys)
    s2 = FakeSession()
    code, out, _ = run(["185.220.101.5"], s2, monkeypatch, tmp_path, capsys)
    assert code == 0 and s2.calls == [] and "(cache)" in out

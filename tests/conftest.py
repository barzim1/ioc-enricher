import pytest


class FakeResponse:
    def __init__(self, status=200, payload=None, headers=None):
        self.status_code = status
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Zwraca kolejno zakolejkowane odpowiedzi i zapisuje wywołania."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def vt_payload(malicious=0, suspicious=0, harmless=60, undetected=10, **attrs):
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                "harmless": harmless, "undetected": undetected},
        **attrs,
    }}}


def abuse_payload(confidence=0, reports=0, **extra):
    return {"data": {"abuseConfidenceScore": confidence, "totalReports": reports,
                     "countryCode": "RU", "isp": "Example ISP", **extra}}


@pytest.fixture
def no_sleep():
    slept = []
    return slept, slept.append

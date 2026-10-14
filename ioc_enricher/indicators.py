"""Rozpoznawanie, normalizacja (refang) i ekstrakcja wskaźników IoC."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, List, Optional
from urllib.parse import urlparse


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

    @property
    def is_ip(self) -> bool:
        return self in (IOCType.IPV4, IOCType.IPV6)

    @property
    def is_hash(self) -> bool:
        return self in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)


@dataclass(frozen=True)
class Indicator:
    value: str
    type: IOCType
    is_private: bool = False

    def __str__(self) -> str:
        return self.value


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)
_HASH_LENGTHS = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}

# Rozszerzenia plików, które regex domeny łapie jako "TLD" (evil.exe, run.sh...).
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bin", "bat", "cmd", "ps1", "sh", "py", "js", "vbs",
    "txt", "log", "ini", "conf", "cfg", "tmp", "json", "xml", "csv", "md",
    "yml", "yaml", "zip", "rar", "gz", "tar", "iso", "doc", "docx", "xls",
    "xlsx", "pdf", "png", "jpg", "jpeg", "gif", "lnk", "msi", "evtx", "pcap",
}


def refang(value: str) -> str:
    """Zamienia zdefangowany zapis (hxxp, [.], [:]) na normalny."""
    v = value.strip().strip("<>\"'")
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    for fanged, plain in (
        ("[://]", "://"), ("[.]", "."), ("(.)", "."), ("{.}", "."),
        ("[dot]", "."), ("(dot)", "."), ("[:]", ":"),
    ):
        v = re.sub(re.escape(fanged), plain, v, flags=re.IGNORECASE)
    return v


def classify(raw: str) -> Optional[Indicator]:
    """Zwraca Indicator albo None, jeśli wartość nie wygląda na żaden znany typ."""
    v = refang(raw)
    if not v:
        return None

    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in _HASH_LENGTHS:
        return Indicator(v.lower(), _HASH_LENGTHS[len(v)])

    try:
        ip = ipaddress.ip_address(v)
        kind = IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
        private = (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        )
        return Indicator(str(ip), kind, is_private=private)
    except ValueError:
        pass

    if re.match(r"^[a-z][a-z0-9+.-]*://", v, flags=re.IGNORECASE):
        try:
            parsed = urlparse(v)
        except ValueError:
            return None
        if parsed.scheme.lower() in ("http", "https", "ftp") and parsed.netloc:
            return Indicator(v, IOCType.URL)
        return None

    lowered = v.lower().rstrip(".")
    if _DOMAIN_RE.match(lowered) and lowered.rsplit(".", 1)[-1] not in _FILE_EXTENSIONS:
        return Indicator(lowered, IOCType.DOMAIN)

    return None


_URL_RE = re.compile(
    r"(?:https?|hxxps?|ftp)(?:://|\[://\])(?:\[\.\]|\(\.\)|[^\s<>\"'\]\)])+", re.IGNORECASE
)
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:\d{1,3}(?:\[\.\]|\(\.\)|\.)){3}\d{1,3}(?![\d.]*\d)",
)
_HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_DOMAIN_IN_TEXT_RE = re.compile(
    r"(?<![\w@./-])(?:[a-z0-9-]{1,63}(?:\[\.\]|\(\.\)|\.))+[a-z]{2,63}(?![\w-])",
    re.IGNORECASE,
)


def extract(text: str, include_private: bool = False) -> List[Indicator]:
    """Wyciąga IoC z dowolnego tekstu (log, mail, ticket). Zachowuje kolejność, usuwa duplikaty."""
    found: List[Indicator] = []
    seen = set()

    def add(candidate: Optional[Indicator]) -> None:
        if candidate is None or candidate in seen:
            return
        if candidate.is_private and not include_private:
            return
        seen.add(candidate)
        found.append(candidate)

    remaining = text
    for match in _URL_RE.finditer(text):
        add(classify(match.group(0).rstrip(".,;")))
    remaining = _URL_RE.sub(" ", remaining)

    for match in _HASH_RE.finditer(remaining):
        add(classify(match.group(0)))
    remaining = _HASH_RE.sub(" ", remaining)

    for match in _IPV4_RE.finditer(remaining):
        add(classify(match.group(0)))
    remaining = _IPV4_RE.sub(" ", remaining)

    for match in _DOMAIN_IN_TEXT_RE.finditer(remaining):
        add(classify(match.group(0)))

    return found


def parse_list(lines: Iterable[str]) -> List[Indicator]:
    """Wczytuje listę 'jeden IoC na linię'; puste linie i komentarze (#) są pomijane."""
    out: List[Indicator] = []
    seen = set()
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        ind = classify(line)
        if ind is None:
            raise ValueError(f"Nierozpoznany wskaźnik: {line!r}")
        if ind not in seen:
            seen.add(ind)
            out.append(ind)
    return out

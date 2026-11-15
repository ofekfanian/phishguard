"""Looks up when a domain was registered, using RDAP (the successor of WHOIS).

A domain registered last week that looks like a bank is far more suspicious
than one that has existed for years. The lookup is passive: it asks the
domain registry, never the suspicious site itself.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import date, datetime

import httpx

log = logging.getLogger("phishguard.enrich")

# IANA's directory of which RDAP server answers for each top-level domain.
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


def parse_bootstrap(data: dict) -> dict[str, str]:
    """Map each TLD to the base URL of its RDAP server."""
    servers: dict[str, str] = {}
    for service in data.get("services", []):
        try:
            tlds, urls = service[0], service[1]
            base = next(u for u in urls if u.startswith("https://"))
        except (IndexError, TypeError, StopIteration):
            continue
        for tld in tlds:
            servers[tld.lower()] = base if base.endswith("/") else base + "/"
    return servers


def registration_date(rdap: dict) -> date | None:
    """The registration date from an RDAP domain response, if present."""
    events = rdap.get("events") if isinstance(rdap, dict) else None
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            try:
                return datetime.fromisoformat(str(event.get("eventDate")).replace("Z", "+00:00")).date()
            except ValueError:
                return None
    return None


class RdapClient:
    """Finds registration dates. Returns None whenever the answer is unknown."""

    def __init__(self, max_concurrent: int = 2, timeout: float = 15):
        self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                         headers={"User-Agent": "phishguard-ct-monitor"})
        self._limit = asyncio.Semaphore(max_concurrent)  # be polite to registries
        self._servers: dict[str, str] | None = None

    async def registered_on(self, domain: str) -> date | None:
        async with self._limit:
            try:
                if self._servers is None:
                    r = await self._client.get(BOOTSTRAP_URL)
                    self._servers = parse_bootstrap(r.raise_for_status().json())
                base = self._servers.get(domain.rsplit(".", 1)[-1])
                if base is None:  # this TLD has no RDAP server (e.g. .il, .de)
                    return None
                r = await self._client.get(base + "domain/" + domain)
                if r.status_code == 404:
                    return None
                return registration_date(r.raise_for_status().json())
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("RDAP lookup failed for %s: %s", domain, str(exc) or type(exc).__name__)
                return None

    async def close(self) -> None:
        await self._client.aclose()

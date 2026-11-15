"""Where domains come from.

Every source is an async generator that yields hostnames one by one, so the
rest of the system does not care whether they are live or simulated.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
from collections.abc import AsyncIterator

import websockets

log = logging.getLogger("phishguard.sources")


def parse_certstream_message(raw: str | bytes) -> list[str]:
    """Extract hostnames from one CertStream message. Never raises."""
    try:
        msg = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(msg, dict):
        return []

    kind = msg.get("message_type")
    if kind == "dns_entries":  # the lightweight "domains-only" stream
        domains = msg.get("data")
    elif kind == "certificate_update":  # the full stream
        data = msg.get("data")
        leaf = data.get("leaf_cert") if isinstance(data, dict) else None
        domains = leaf.get("all_domains") if isinstance(leaf, dict) else None
    else:
        return []

    if not isinstance(domains, list):
        return []
    return [d for d in domains if isinstance(d, str)]


async def certstream_source(url: str) -> AsyncIterator[str]:
    """Live feed of every new HTTPS certificate, from a CertStream server.

    Reconnects forever with exponential backoff: the stream is expected to drop.
    """
    backoff = 1
    while True:
        try:
            async with websockets.connect(url, max_size=2**23) as ws:
                log.info("Connected to CertStream at %s", url)
                backoff = 1
                async for raw in ws:
                    for domain in parse_certstream_message(raw):
                        yield domain
        except (OSError, websockets.WebSocketException) as exc:
            log.warning("CertStream connection lost (%s). Retrying in %ss", exc, backoff)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)


_WORDS = ["shop", "blog", "cloud", "pizza", "studio", "garden", "dev", "photo", "travel",
          "music", "coffee", "tech", "yoga", "books", "design", "market", "news", "games"]
_NAMES = ["yossi", "dana", "noa", "avi", "tamar", "omer", "maya", "eitan", "shira", "ron"]
_TLDS = ["com", "co.il", "net", "org", "io", "app", "dev", "de", "fr", "co.uk"]
_SUBS = ["", "", "", "www.", "mail.", "api.", "cdn.", "*."]

_FAKES = [
    "{b}-secure-login.xyz", "{b}-verify.com", "secure-{b}.online", "{b}.co.il.verify-account.top",
    "{b}-account-update.info", "login-{b}.click", "{b}-support.live", "my{b}online.com",
    "{b}-billing.site", "auth.{b}-service.icu",
]
_FAKE_BRANDS = ["leumi", "bankhapoalim", "discountbank", "mizrahi", "israelpost", "paypal",
                "paypa1", "paypol", "microsofft", "rnicrosoft", "1eumi", "hapoa1im", "office365"]


def _random_legit() -> str:
    name = random.choice(_NAMES) + "-" + random.choice(_WORDS) if random.random() < 0.5 \
        else random.choice(_WORDS) + str(random.randint(1, 9999))
    return f"{random.choice(_SUBS)}{name}.{random.choice(_TLDS)}"


def _random_fake() -> str:
    return random.choice(_FAKES).format(b=random.choice(_FAKE_BRANDS))


async def demo_source(rate: float = 20.0, fake_ratio: float = 0.03) -> AsyncIterator[str]:
    """Simulated feed for development and demos: mostly noise, a few fakes."""
    while True:
        yield _random_fake() if random.random() < fake_ratio else _random_legit()
        await asyncio.sleep(1 / rate)

"""Connects a source to the scorer and the database."""
from __future__ import annotations

import logging
import time
from collections import OrderedDict
from collections.abc import AsyncIterator

from .scorer import ScoreResult, score_domain
from .store import Store

log = logging.getLogger("phishguard.pipeline")

# The same domain shows up many times (renewals, several certificate logs).
SEEN_CACHE_SIZE = 200_000


class Pipeline:
    def __init__(self, store: Store, threshold: int, source_name: str):
        self.store = store
        self.threshold = threshold
        self.source_name = source_name
        self.processed = 0
        self.started_at = time.time()
        self._seen: OrderedDict[str, None] = OrderedDict()
        # One site often gets certificates for hundreds of subdomains: report it once.
        self._flagged: OrderedDict[str, None] = OrderedDict()

    def handle(self, domain: str) -> ScoreResult | None:
        """Score one domain and save it if suspicious. None means 'seen before'."""
        if domain in self._seen:
            self._seen.move_to_end(domain)
            return None
        self._seen[domain] = None
        if len(self._seen) > SEEN_CACHE_SIZE:
            self._seen.popitem(last=False)

        self.processed += 1
        result = score_domain(domain)
        if result.score >= self.threshold and result.registered_domain not in self._flagged:
            self._flagged[result.registered_domain] = None
            if len(self._flagged) > SEEN_CACHE_SIZE:
                self._flagged.popitem(last=False)
            if self.store.save(result, self.source_name):
                log.info("DETECTED %s score=%s brand=%s", result.domain, result.score, result.brand)
        return result

    async def run(self, source: AsyncIterator[str]) -> None:
        async for domain in source:
            try:
                self.handle(domain)
            except Exception:  # one bad domain must never stop the stream
                log.exception("Failed to process %r", domain)

    def stats(self) -> dict:
        uptime = max(time.time() - self.started_at, 0.001)
        return {
            "source": self.source_name,
            "processed": self.processed,
            "uptime_seconds": round(uptime),
            "domains_per_second": round(self.processed / uptime, 1),
            "threshold": self.threshold,
        }

"""Connects a source to the scorer and the database."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import date

from .scorer import ScoreResult, apply_domain_age, score_domain
from .store import Store

log = logging.getLogger("phishguard.pipeline")

# The same domain shows up many times (renewals, several certificate logs).
SEEN_CACHE_SIZE = 200_000
# Domains this close to the threshold get an age lookup, which may push a
# brand-new domain over it.
AGE_BONUS = 15

AgeLookup = Callable[[str], Awaitable[date | None]]


class Pipeline:
    def __init__(self, store: Store, threshold: int, source_name: str,
                 age_lookup: AgeLookup | None = None):
        self.store = store
        self.threshold = threshold
        self.source_name = source_name
        self.age_lookup = age_lookup
        self.processed = 0
        self.started_at = time.time()
        self._seen: OrderedDict[str, None] = OrderedDict()
        # One site often gets certificates for hundreds of subdomains: judge it once.
        self._judged: OrderedDict[str, None] = OrderedDict()
        self._lookups: set[asyncio.Task] = set()

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
        candidate_at = self.threshold - AGE_BONUS if self.age_lookup else self.threshold
        if result.score >= candidate_at and result.registered_domain not in self._judged:
            self._judged[result.registered_domain] = None
            if len(self._judged) > SEEN_CACHE_SIZE:
                self._judged.popitem(last=False)
            if self.age_lookup:
                task = asyncio.create_task(self._lookup_age_and_save(result))
                self._lookups.add(task)
                task.add_done_callback(self._lookups.discard)
            else:
                self._save(result, None)
        return result

    async def _lookup_age_and_save(self, result: ScoreResult) -> None:
        try:
            registered_on = await self.age_lookup(result.registered_domain)
        except Exception:
            log.exception("Age lookup failed for %s", result.registered_domain)
            registered_on = None
        self._save(apply_domain_age(result, registered_on), registered_on)

    def _save(self, result: ScoreResult, registered_on: date | None) -> None:
        if result.score < self.threshold:
            log.info("Below threshold after checks: %s score=%s", result.domain, result.score)
        elif self.store.save(result, self.source_name, registered_on):
            log.info("DETECTED %s score=%s brand=%s", result.domain, result.score, result.brand)

    async def drain(self) -> None:
        """Wait for age lookups that are still in flight."""
        while self._lookups:
            await asyncio.gather(*self._lookups, return_exceptions=True)

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

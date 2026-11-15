"""Reads Certificate Transparency logs directly.

Every publicly trusted HTTPS certificate must be recorded in public CT logs.
Each log is an append-only list: we remember how far we have read, ask the log
for its current size, and download whatever was added since.

Two generations of logs exist and both are supported:
- RFC 6962 logs: a JSON API (get-sth, get-entries).
- Tiled logs (static-ct-api): static files, 256 entries per "data tile".
  Let's Encrypt, the CA behind most phishing sites, only writes to these.
"""
from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

log = logging.getLogger("phishguard.ct")

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
POLL_SECONDS = 5
BATCH = 256
TILE = 256  # entries per data tile in a tiled log
# If we fall this far behind, skip ahead: this is a live monitor, not an archive.
MAX_LAG = 20_000
HEADERS = {"User-Agent": "phishguard-ct-monitor"}


def domains_from_entry(leaf_input: str, extra_data: str) -> list[str]:
    """Extract the hostnames from one log entry. Never raises."""
    try:
        leaf = base64.b64decode(leaf_input)
        # MerkleTreeLeaf: version(1) type(1) timestamp(8) entry_type(2) ...
        entry_type = int.from_bytes(leaf[10:12], "big")
        if entry_type == 0:  # a final certificate, stored in the leaf itself
            data = leaf[12:]
        elif entry_type == 1:  # a pre-certificate, stored in extra_data
            data = base64.b64decode(extra_data)
        else:
            return []
        return _der_domains(_read_block(data, 0, 3)[0])
    except Exception:
        return []


def _read_block(data: bytes, offset: int, size_bytes: int) -> tuple[bytes, int]:
    """Read a length-prefixed block. Returns the block and the offset after it."""
    start = offset + size_bytes
    if start > len(data):
        raise ValueError("truncated")
    end = start + int.from_bytes(data[offset:start], "big")
    if end > len(data):
        raise ValueError("truncated")
    return data[start:end], end


def _der_domains(der: bytes) -> list[str]:
    try:
        return _cert_domains(x509.load_der_x509_certificate(der))
    except Exception:
        return []


def tile_path(index: int) -> str:
    """Path of a data tile: 1234067 -> 'x001/x234/067'."""
    parts = []
    while True:
        parts.append(f"{index % 1000:03d}")
        index //= 1000
        if index == 0:
            break
    parts.reverse()
    return "/".join(["x" + p for p in parts[:-1]] + [parts[-1]])


def domains_from_tile(tile: bytes) -> list[list[str]]:
    """Hostnames of every entry in a data tile, one list per entry.

    Stops at the first malformed entry instead of raising.
    """
    entries: list[list[str]] = []
    offset = 0
    try:
        while offset < len(tile):
            offset += 8  # timestamp
            entry_type = int.from_bytes(tile[offset:offset + 2], "big")
            offset += 2
            if entry_type == 0:  # final certificate
                der, offset = _read_block(tile, offset, 3)
                _, offset = _read_block(tile, offset, 2)  # extensions
            elif entry_type == 1:  # pre-certificate
                offset += 32  # issuer key hash
                _, offset = _read_block(tile, offset, 3)  # TBS certificate
                _, offset = _read_block(tile, offset, 2)  # extensions
                der, offset = _read_block(tile, offset, 3)
            else:
                break
            _, offset = _read_block(tile, offset, 2)  # chain fingerprints
            entries.append(_der_domains(der))
    except ValueError:
        pass
    return entries


def _cert_domains(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    if not names:
        names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                 if isinstance(a.value, str)]
    return names


def pick_logs(log_list: dict, now: datetime | None = None, tiled: bool = False) -> list[str]:
    """URLs of the logs that are in use and accept certificates expiring now."""
    now = now or datetime.now(timezone.utc)
    urls = []
    for operator in log_list.get("operators", []):
        for entry in operator.get("tiled_logs" if tiled else "logs", []):
            if "usable" not in entry.get("state", {}):
                continue
            interval = entry.get("temporal_interval", {})
            try:
                start = datetime.fromisoformat(interval["start_inclusive"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(interval["end_exclusive"].replace("Z", "+00:00"))
                url = entry["monitoring_url" if tiled else "url"]
            except (KeyError, ValueError):
                continue
            if start <= now < end:
                urls.append(url if url.endswith("/") else url + "/")
    return urls


async def _follow_tiled_log(client: httpx.AsyncClient, url: str, queue: asyncio.Queue[str]) -> None:
    """Follow one tiled log forever, pushing new hostnames into the queue."""
    position: int | None = None
    backoff = POLL_SECONDS
    while True:
        try:
            checkpoint = (await client.get(url + "checkpoint")).raise_for_status().text
            size = int(checkpoint.split("\n")[1])  # line 1: log name, line 2: size
            if position is None:
                position = size
                log.info("Following %s from entry %s", url, size)
            if size - position > MAX_LAG:
                log.warning("%s: %s entries behind, skipping ahead", url, size - position)
                position = size - MAX_LAG

            while position < size:
                tile = position // TILE
                width = min(size - tile * TILE, TILE)
                path = "tile/data/" + tile_path(tile) + ("" if width == TILE else f".p/{width}")
                data = (await client.get(url + path)).raise_for_status().content
                entries = domains_from_tile(data)
                if len(entries) != width:
                    raise ValueError(f"tile {tile}: expected {width} entries, parsed {len(entries)}")
                for names in entries[position - tile * TILE:]:
                    for domain in names:
                        await queue.put(domain)
                position = tile * TILE + width
            backoff = POLL_SECONDS
        except httpx.HTTPStatusError as exc:
            backoff = min(backoff * 2, 120)
            log.warning("%s: HTTP %s. Retrying in %ss", url, exc.response.status_code, backoff)
        except (httpx.HTTPError, IndexError, ValueError) as exc:
            backoff = min(backoff * 2, 120)
            log.warning("%s: %s. Retrying in %ss", url, str(exc) or type(exc).__name__, backoff)
        await asyncio.sleep(backoff)


async def _follow_log(client: httpx.AsyncClient, url: str, queue: asyncio.Queue[str]) -> None:
    """Follow one log forever, pushing new hostnames into the queue."""
    position: int | None = None
    backoff = POLL_SECONDS
    batch = BATCH
    while True:
        try:
            sth = (await client.get(url + "ct/v1/get-sth")).raise_for_status().json()
            size = int(sth["tree_size"])
            if position is None:
                position = size  # start from "now"
                log.info("Following %s from entry %s", url, size)
            if size - position > MAX_LAG:
                log.warning("%s: %s entries behind, skipping ahead", url, size - position)
                position = size - MAX_LAG

            while position < size:
                end = min(position + batch, size) - 1
                r = await client.get(url + "ct/v1/get-entries", params={"start": position, "end": end})
                entries = r.raise_for_status().json()["entries"]
                if not entries:
                    break
                for entry in entries:
                    for domain in domains_from_entry(entry["leaf_input"], entry["extra_data"]):
                        await queue.put(domain)
                position += len(entries)
            backoff = POLL_SECONDS
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 400 and batch > 16:
                batch //= 2  # some logs only accept small ranges
            backoff = min(backoff * 2, 120)
            log.warning("%s: HTTP %s. Retrying in %ss (batch %s)", url, status, backoff, batch)
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            backoff = min(backoff * 2, 120)
            log.warning("%s: %s. Retrying in %ss", url, str(exc) or type(exc).__name__, backoff)
        await asyncio.sleep(backoff)


async def ct_source(log_urls: list[str] | None = None,
                    tiled_urls: list[str] | None = None) -> AsyncIterator[str]:
    """Live feed of hostnames from newly issued certificates.

    With no arguments, the logs to follow are discovered from the public log list.
    """
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=10_000)
    async with httpx.AsyncClient(timeout=20, headers=HEADERS) as client:
        while not log_urls and not tiled_urls:
            try:
                log_list = (await client.get(LOG_LIST_URL)).raise_for_status().json()
                log_urls, tiled_urls = pick_logs(log_list), pick_logs(log_list, tiled=True)
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("Could not load the CT log list (%s). Retrying", exc)
                await asyncio.sleep(10)
        tasks = [asyncio.create_task(_follow_log(client, u, queue)) for u in log_urls or []]
        tasks += [asyncio.create_task(_follow_tiled_log(client, u, queue)) for u in tiled_urls or []]
        try:
            while True:
                yield await queue.get()
        finally:
            for t in tasks:
                t.cancel()

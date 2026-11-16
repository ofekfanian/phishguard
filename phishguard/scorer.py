"""Scores how likely a domain is to be impersonating a protected brand.

The score is 0-100 and every point is explained by a human-readable reason,
so an analyst can see why a domain was flagged.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import date

import tldextract
from rapidfuzz.distance import Levenshtein

from .config import BRANDS, Brand

# Uses the public-suffix list bundled with tldextract (no network call),
# so "evil.co.il" is split into domain "evil" and suffix "co.il".
_extract = tldextract.TLDExtract(suffix_list_urls=())

_OFFICIAL = {d: b.name for b in BRANDS for d in b.official_domains}

# Non-Latin letters that look like Latin ones (Cyrillic and Greek).
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "ı": "i",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "κ": "k", "τ": "t",
}
_DIGITS_AS_L = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}
_DIGITS_AS_I = {**_DIGITS_AS_L, "1": "i"}
_LETTER_PAIRS = (("rn", "m"), ("vv", "w"))

PHISHING_WORDS = frozenset({
    "login", "signin", "secure", "security", "verify", "verification", "account",
    "update", "auth", "support", "confirm", "wallet", "bank", "online", "service",
    "alert", "payment", "invoice", "recover", "unlock", "billing", "password",
})
SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "online", "site", "live", "click", "icu", "shop", "info",
    "buzz", "cfd", "sbs", "rest", "cyou", "link", "support", "help", "vip",
})


@dataclass
class ScoreResult:
    domain: str
    registered_domain: str
    score: int = 0
    severity: str = "none"
    brand: str | None = None
    reasons: list[str] = field(default_factory=list)


def severity_for(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def apply_domain_age(result: ScoreResult, registered_on: date | None,
                     today: date | None = None) -> ScoreResult:
    """Adjust a score by how long the domain has existed.

    Phishing domains are usually days or weeks old. A domain that has been
    registered for years is much more likely to be a coincidence.
    """
    if registered_on is None or result.score == 0:
        return result
    days = ((today or date.today()) - registered_on).days
    if days < 0:
        return result
    if days <= 30:
        change, note = 15, f"Registered only {days} day(s) ago"
    elif days <= 365:
        change, note = 0, f"Registered {days} days ago"
    elif days <= 730:
        change, note = -10, "Registered more than a year ago"
    else:
        change, note = -20, f"Registered {days // 365} years ago"
    # Swapped characters are deliberate at any age, so age never lowers that score.
    if change < 0 and any(r.startswith("Lookalike characters") for r in result.reasons):
        change = 0
    score = max(0, min(100, result.score + change))
    return replace(result, score=score, severity=severity_for(score),
                   reasons=result.reasons + [f"{note} ({registered_on.isoformat()})"])


def score_domain(hostname: str) -> ScoreResult:
    host = hostname.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]

    ext = _extract(host)
    if not ext.domain or not ext.suffix:
        return ScoreResult(host, host, reasons=["Not a registrable domain"])

    registered = f"{ext.domain}.{ext.suffix}"
    if registered in _OFFICIAL:
        return ScoreResult(host, registered, brand=_OFFICIAL[registered],
                           reasons=[f"Official domain of {_OFFICIAL[registered]}"])

    domain_tokens = [t for t in _decode(ext.domain).split("-") if t]
    sub_tokens = [t for label in ext.subdomain.split(".") for t in _decode(label).split("-") if t]

    best: tuple[int, list[str], Brand] | None = None
    for brand in BRANDS:
        points, reasons = _brand_signals(brand, host, domain_tokens, sub_tokens)
        if points and (best is None or points > best[0]):
            best = (points, reasons, brand)

    # No brand involved: nothing to impersonate, so nothing to flag.
    if best is None:
        return ScoreResult(host, registered)

    points, reasons, brand = best
    extra_points, extra_reasons = _context_signals(host, ext.suffix, domain_tokens + sub_tokens)
    total = min(100, points + extra_points)
    return ScoreResult(host, registered, total, severity_for(total), brand.name, reasons + extra_reasons)


def _decode(label: str) -> str:
    """Turn a punycode label (xn--...) back into its real characters."""
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except UnicodeError:
        return label


def _skeletons(token: str) -> set[str]:
    """All the ways a token could be 'read' once lookalike characters are swapped."""
    base = "".join(_CONFUSABLES.get(c, c) for c in token)
    out = set()
    for digits in (_DIGITS_AS_L, _DIGITS_AS_I):
        s = "".join(digits.get(c, c) for c in base)
        out.add(s)
        for pair, letter in _LETTER_PAIRS:
            out.add(s.replace(pair, letter))
    # A lowercase "l" and an uppercase "I" look the same in most fonts.
    for s in list(out):
        out.add(s.replace("l", "i"))
        out.add(s.replace("i", "l"))
    return out


def _brand_signals(brand: Brand, host: str, domain_tokens: list[str],
                   sub_tokens: list[str]) -> tuple[int, list[str]]:
    """The strongest sign that this domain uses the brand's name."""
    tokens = domain_tokens + sub_tokens
    best, reason = 0, ""

    for kw in brand.keywords:
        points, why = 0, ""
        if kw in domain_tokens:
            points, why = 40, f"Brand name '{kw}' used in a domain the brand does not own"
        elif kw in sub_tokens:
            points, why = 40, f"Brand name '{kw}' used as a subdomain of an unrelated domain"
        elif len(kw) >= 5 and any(kw in t for t in tokens):
            points, why = 35, f"Brand name '{kw}' hidden inside a longer word"
        else:
            lookalike = next((t for t in tokens if any(kw in s for s in _skeletons(t))), None)
            if lookalike:
                points, why = 55, f"Lookalike characters: '{lookalike}' reads as '{kw}'"
            elif len(kw) >= 5:
                max_edits = 1 if len(kw) < 8 else 2
                for t in tokens:
                    edits = Levenshtein.distance(t, kw)
                    if len(t) >= 5 and 0 < edits <= max_edits:
                        # Below the threshold on its own: many real words are one
                        # or two letters away from a brand ("playpal", "microsport").
                        points, why = 45, f"Typosquatting: '{t}' is {edits} edit(s) away from '{kw}'"
                        break
        if points > best:
            best, reason = points, why

    if not best:
        return 0, []

    reasons = [reason]
    for official in brand.official_domains:
        if f".{official}." in f".{host}.":  # whole labels, not "theoutlook.com.ua"
            best += 20
            reasons.append(f"Embeds the real domain '{official}' to look legitimate")
            break
    return best, reasons


def _context_signals(host: str, suffix: str, tokens: list[str]) -> tuple[int, list[str]]:
    """Supporting evidence. Only counted when a brand is already involved."""
    points, reasons = 0, []

    words = sorted({w for w in PHISHING_WORDS for t in tokens if t == w or (len(w) >= 5 and w in t)})
    if words:
        points += min(25, 15 + 5 * (len(words) - 1))
        reasons.append(f"Phishing keywords: {', '.join(words)}")

    tld = suffix.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        points += 15
        reasons.append(f"TLD '.{tld}' is common in phishing campaigns")

    if any(label.startswith("xn--") for label in host.split(".")):
        points += 10
        reasons.append("Uses punycode (non-Latin characters)")

    if host.count("-") >= 3:
        points += 5
        reasons.append("Many hyphens")

    if host.count(".") >= 4:
        points += 5
        reasons.append("Deeply nested subdomains")

    return points, reasons

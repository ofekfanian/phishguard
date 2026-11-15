"""Settings and the list of brands we protect."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    # Words that identify the brand inside a domain name.
    keywords: tuple[str, ...]
    # Domains the brand really owns. These are never flagged.
    official_domains: tuple[str, ...]


BRANDS: tuple[Brand, ...] = (
    Brand("Bank Leumi", ("leumi",), ("leumi.co.il", "bankleumi.co.il", "leumi.com")),
    Brand("Bank Hapoalim", ("bankhapoalim", "hapoalim"), ("bankhapoalim.co.il", "bankhapoalim.com")),
    Brand("Discount Bank", ("discountbank",), ("discountbank.co.il", "discountbank.com")),
    Brand("Mizrahi Tefahot", ("mizrahi", "tefahot"), ("mizrahi-tefahot.co.il",)),
    Brand("Israel Post", ("israelpost",), ("israelpost.co.il",)),
    Brand("PayPal", ("paypal",), ("paypal.com", "paypal.me", "paypalobjects.com")),
    Brand(
        "Microsoft",
        ("microsoft", "office365", "outlook"),
        ("microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com",
         "microsoft-int.com", "microsoft.net", "microsoft.us", "microsoftazure.de", "outlook.cn",
         "office365.us", "microsoftonline.us", "microsoft365.com"),
    ),
)


def source() -> str:
    """Where domains come from: 'demo', 'ct', 'certstream' or 'none'."""
    return os.getenv("PHISHGUARD_SOURCE", "demo")


def ct_logs() -> list[str]:
    """Optional comma-separated RFC 6962 log URLs. Empty means: discover automatically."""
    return _url_list("PHISHGUARD_CT_LOGS")


def ct_tiled_logs() -> list[str]:
    """Optional comma-separated tiled log URLs. Empty means: discover automatically."""
    return _url_list("PHISHGUARD_CT_TILED_LOGS")


def _url_list(variable: str) -> list[str]:
    urls = [u.strip() for u in os.getenv(variable, "").split(",") if u.strip()]
    return [u if u.endswith("/") else u + "/" for u in urls]


def certstream_url() -> str:
    return os.getenv("PHISHGUARD_CERTSTREAM_URL", "ws://localhost:8080/domains-only")


def database_url() -> str:
    return os.getenv("PHISHGUARD_DB", "sqlite:///phishguard.db")


def threshold() -> int:
    """Minimum score for a domain to be saved as a detection."""
    return int(os.getenv("PHISHGUARD_THRESHOLD", "50"))


def enrich() -> bool:
    """Look up domain age for candidates. Off for the demo feed, whose domains are made up."""
    default = "0" if source() in ("demo", "none") else "1"
    return os.getenv("PHISHGUARD_ENRICH", default) == "1"

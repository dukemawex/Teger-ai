"""Brand reference data for impersonation checks.

Each brand maps a keyword (matched in hosts and text) to the registrable domains the
brand officially uses. The list is intentionally small and reviewable; extend it via
pull request. Matching official domains is not proof a page is safe.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]
    domains: frozenset[str]


BRANDS: tuple[Brand, ...] = (
    Brand("PayPal", ("paypal",), frozenset({"paypal.com", "paypal.me", "paypalobjects.com"})),
    Brand("Microsoft", ("microsoft", "office365", "outlook", "onedrive", "sharepoint"), frozenset({
        "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com",
        "sharepoint.com", "onedrive.com", "msn.com", "azure.com", "windows.net",
    })),
    Brand("Google", ("google", "gmail"), frozenset({
        "google.com", "gmail.com", "youtube.com", "googleusercontent.com", "gstatic.com", "goo.gl", "g.co",
    })),
    Brand("Apple", ("apple", "icloud"), frozenset({"apple.com", "icloud.com", "itunes.com", "me.com"})),
    Brand("Amazon", ("amazon",), frozenset({
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.in", "amazon.ca", "amazon.com.au",
        "amazonaws.com", "aws.amazon.com",
    })),
    Brand("Netflix", ("netflix",), frozenset({"netflix.com", "nflxext.com"})),
    Brand("Meta", ("facebook", "instagram", "whatsapp"), frozenset({
        "facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com", "whatsapp.net", "messenger.com",
    })),
    Brand("LinkedIn", ("linkedin",), frozenset({"linkedin.com", "lnkd.in"})),
    Brand("DocuSign", ("docusign",), frozenset({"docusign.com", "docusign.net"})),
    Brand("Dropbox", ("dropbox",), frozenset({"dropbox.com", "dropboxusercontent.com"})),
    Brand("DHL", ("dhl",), frozenset({"dhl.com", "dhl.de"})),
    Brand("Coinbase", ("coinbase",), frozenset({"coinbase.com"})),
    Brand("Binance", ("binance",), frozenset({"binance.com"})),
    Brand("Chase", ("chase",), frozenset({"chase.com", "jpmorganchase.com"})),
    Brand("Wells Fargo", ("wellsfargo",), frozenset({"wellsfargo.com"})),
    Brand("Bank of America", ("bankofamerica",), frozenset({"bankofamerica.com", "bofa.com"})),
    Brand("Slack", ("slack",), frozenset({"slack.com", "slack-edge.com"})),
)

OFFICIAL_DOMAINS: frozenset[str] = frozenset().union(*(b.domains for b in BRANDS))


def is_official_domain(registrable: str | None) -> bool:
    return bool(registrable) and registrable in OFFICIAL_DOMAINS

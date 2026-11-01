"""
SafeNet-AI Domain Reputation

Known-legitimate domains from the Tranco top 100k list
(backend/data/tranco_top100k.csv, see backend/data/README.md).

A popular registered domain lowers the risk score in risk_engine.
Platforms where anyone can publish content get NO reputation credit,
because a phishing page on site.weebly.com or a public S3 bucket would
otherwise inherit weebly.com's or amazonaws.com's rank:
1. Free hosting / site builders (FREE_HOSTING_DOMAINS)
2. URL shorteners (URL_SHORTENERS)
3. Cloud user-content domains (USER_CONTENT_DOMAINS)
"""

import csv
import os

from fast_feature_extractor import (
    FREE_HOSTING_DOMAINS,
    URL_SHORTENERS,
    is_ip_address,
    normalize_host,
    registered_domain
)


LIST_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data",
    "tranco_top100k.csv"
)

LIST_NAME = "Tranco top 100k (list ZJ8PG)"

# Registered domains that serve content uploaded by anyone
USER_CONTENT_DOMAINS = frozenset({
    "amazonaws.com", "cloudfront.net", "windows.net", "azurewebsites.net",
    "azureedge.net", "googleusercontent.com", "googleapis.com", "appspot.com",
    "sharepoint.com", "dropboxusercontent.com", "ngrok-free.app", "ngrok.io",
    "trycloudflare.com", "duckdns.org", "onrender.com", "repl.co",
})

_ranks = None


def _load():
    global _ranks

    if _ranks is None:
        with open(LIST_PATH, newline="", encoding="utf-8") as f:
            _ranks = {
                row["domain"].lower(): int(row["rank"])
                for row in csv.DictReader(f)
            }

    return _ranks


def lookup(url):
    """
    Return {"domain", "rank", "list"} if the URL's registered domain is
    on the popular-domain list and may receive reputation credit,
    otherwise None.
    """

    host = normalize_host(url)

    if not host or is_ip_address(host):
        return None

    domain = registered_domain(host)

    if (
        domain in FREE_HOSTING_DOMAINS
        or domain in USER_CONTENT_DOMAINS
        or domain in URL_SHORTENERS
        or host in URL_SHORTENERS
    ):
        return None

    ranks = _load()

    for candidate in (domain, host):
        if candidate in ranks:
            return {
                "domain": candidate,
                "rank": ranks[candidate],
                "list": LIST_NAME,
            }

    return None

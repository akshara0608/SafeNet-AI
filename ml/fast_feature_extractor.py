import math
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = (
    "login", "verify", "banking", "password",
    "signin", "account", "update", "secure",
    "confirm", "wallet", "credential", "authenticate"
)

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "shorturl.at"
})

SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "click", "work",
    "rest", "country", "gq", "tk"
})


def is_ip_address(hostname):
    """Return 1 if hostname is an IPv4 or IPv6 address, otherwise 0."""
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def calculate_entropy(text):
    """Calculate Shannon entropy in bits per character."""
    if not text:
        return 0.0

    length = len(text)
    frequencies = {}

    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1

    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def extract_fast_features(url):
    """
    Extract URL-only features for phishing detection.

    No DNS, WHOIS, SSL, or network requests are performed.

    Character-based URL features exclude the scheme, so HTTP
    and HTTPS versions of the same URL have identical values
    for those features.
    """

    if not isinstance(url, str):
        url = str(url)

    url = url.strip()

    # Parse the URL.
    parse_url = url if "://" in url else "//" + url

    try:
        parsed = urlparse(parse_url, scheme="https" if "://" not in url else "")
        hostname = (parsed.hostname or "").rstrip(".").lower()

        try:
            port = parsed.port
        except ValueError:
            port = None

    except ValueError:
        parsed = urlparse("")
        hostname = ""
        port = None

    scheme = parsed.scheme.lower()

    # Build the scheme-independent representation.
    scheme_free_url = parsed.netloc + parsed.path

    if parsed.query:
        scheme_free_url += "?" + parsed.query

    if parsed.fragment:
        scheme_free_url += "#" + parsed.fragment

    hostname_is_ip = is_ip_address(hostname)

    # Basic URL and hostname features.
    url_length = len(scheme_free_url)
    hostname_length = len(hostname)

    hostname_parts = hostname.split(".") if hostname else []

    subdomain_depth = (
        0 if hostname_is_ip
        else max(0, len(hostname_parts) - 2)
    )

    # Character counts.
    digit_count = 0
    letter_count = 0
    special_char_count = 0

    for char in scheme_free_url:
        if char.isdigit():
            digit_count += 1
        elif char.isalpha():
            letter_count += 1
        else:
            special_char_count += 1

    # Entropy.
    entropy = calculate_entropy(scheme_free_url)
    hostname_entropy = calculate_entropy(hostname)

    # Structural features.
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # Detect keywords without creating a separate lowercase URL.
    # Each keyword is counted at most once.
    suspicious_keyword_count = sum(
        keyword in scheme_free_url.lower()
        for keyword in SUSPICIOUS_KEYWORDS
    )

    # TLD analysis.
    tld = (
        hostname_parts[-1]
        if len(hostname_parts) > 1 and not hostname_is_ip
        else ""
    )

    return {
        # Original features
        "url_length": url_length,
        "hostname_length": hostname_length,
        "has_ip_address": hostname_is_ip,
        "subdomain_depth": subdomain_depth,
        "digit_count": digit_count,
        "letter_count": letter_count,
        "dot_count": scheme_free_url.count("."),
        "slash_count": scheme_free_url.count("/"),
        "hyphen_count": scheme_free_url.count("-"),
        "underscore_count": scheme_free_url.count("_"),
        "equals_count": scheme_free_url.count("="),
        "question_mark_count": scheme_free_url.count("?"),
        "ampersand_count": scheme_free_url.count("&"),
        "at_count": scheme_free_url.count("@"),
        "percent_count": scheme_free_url.count("%"),
        "special_char_count": special_char_count,
        "entropy": entropy,

        # Additional features
        "hostname_entropy": hostname_entropy,
        "suspicious_keyword_count": suspicious_keyword_count,
        "has_suspicious_keyword": int(suspicious_keyword_count > 0),
        "is_shortened_url": int(hostname in URL_SHORTENERS),
        "has_https": int(scheme == "https"),
        "has_http": int(scheme == "http"),
        "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "path_length": len(path),
        "query_length": len(query),
        "has_query": int(bool(query)),
        "has_fragment": int(bool(fragment)),
        "has_port": int(port is not None),
        "has_at_symbol_in_authority": int("@" in parsed.netloc),
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://secure-login.example.xyz/account?user=123",
        "http://192.168.1.1/login",
        "https://bit.ly/example",
    ]

    for url in test_urls:
        print(f"\nURL: {url}")

        features = extract_fast_features(url)

        for name, value in features.items():
            print(f"{name}: {value}")
```

import math
import ipaddress
from urllib.parse import urlparse


def is_ip_address(hostname):
    """Return 1 if hostname is an IPv4/IPv6 address, otherwise 0."""
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    length = len(text)
    frequencies = {}

    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_fast_features(url):
    """
    Extract URL-only features.

    IMPORTANT:
    - HTTP and HTTPS are treated identically.
    - The scheme (http:// or https://) is excluded from
      character-based URL features.
    - No WHOIS requests.
    - No DNS requests.
    - No SSL requests.
    - No Internet/network requests.
    """

    if not isinstance(url, str):
        url = str(url)

    url = url.strip()

    # ---------------------------------------------------------
    # Parse URL
    # ---------------------------------------------------------
    parse_url = url

    if "://" not in parse_url:
        parse_url = "http://" + parse_url

    parsed = urlparse(parse_url)

    hostname = parsed.hostname or ""
    hostname = hostname.rstrip(".")

    # ---------------------------------------------------------
    # Scheme-independent URL representation
    # ---------------------------------------------------------
    #
    # Example:
    #
    # https://www.google.com/search?q=test
    # http://www.google.com/search?q=test
    #
    # Both become:
    #
    # www.google.com/search?q=test
    #
    # Therefore HTTP vs HTTPS cannot affect the model.
    # ---------------------------------------------------------

    scheme_free_url = parsed.netloc + parsed.path

    if parsed.query:
        scheme_free_url += "?" + parsed.query

    if parsed.fragment:
        scheme_free_url += "#" + parsed.fragment

    # ---------------------------------------------------------
    # Basic URL components
    # ---------------------------------------------------------
    url_length = len(scheme_free_url)
    hostname_length = len(hostname)

    # ---------------------------------------------------------
    # Domain / IP
    # ---------------------------------------------------------
    has_ip_address = is_ip_address(hostname)

    hostname_parts = hostname.split(".") if hostname else []

    if has_ip_address:
        subdomain_depth = 0
    elif len(hostname_parts) > 2:
        subdomain_depth = len(hostname_parts) - 2
    else:
        subdomain_depth = 0

    # ---------------------------------------------------------
    # Character-based features
    # ---------------------------------------------------------
    digit_count = sum(char.isdigit() for char in scheme_free_url)

    letter_count = sum(char.isalpha() for char in scheme_free_url)

    dot_count = scheme_free_url.count(".")
    slash_count = scheme_free_url.count("/")
    hyphen_count = scheme_free_url.count("-")
    underscore_count = scheme_free_url.count("_")
    equals_count = scheme_free_url.count("=")
    question_mark_count = scheme_free_url.count("?")
    ampersand_count = scheme_free_url.count("&")
    at_count = scheme_free_url.count("@")
    percent_count = scheme_free_url.count("%")

    # ---------------------------------------------------------
    # Special characters
    # ---------------------------------------------------------
    special_char_count = sum(
        1 for char in scheme_free_url
        if not char.isalnum()
    )

    # ---------------------------------------------------------
    # Entropy
    # ---------------------------------------------------------
    entropy = calculate_entropy(scheme_free_url)

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "has_ip_address": has_ip_address,
        "subdomain_depth": subdomain_depth,
        "digit_count": digit_count,
        "letter_count": letter_count,
        "dot_count": dot_count,
        "slash_count": slash_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "equals_count": equals_count,
        "question_mark_count": question_mark_count,
        "ampersand_count": ampersand_count,
        "at_count": at_count,
        "percent_count": percent_count,
        "special_char_count": special_char_count,
        "entropy": entropy,
    }
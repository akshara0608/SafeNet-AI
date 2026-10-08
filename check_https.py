from urllib.parse import urlparse


def check_https(url):
    """
    Check whether the URL uses HTTPS.
    """

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    is_https = parsed.scheme.lower() == "https"

    return {
        "is_https": is_https,
        "protocol": parsed.scheme.lower()
    }


if __name__ == "__main__":

    test_urls = [
        "https://www.google.com",
        "http://www.google.com",
        "https://www.youtube.com",
        "http://www.youtube.com",
        "google.com"
    ]

    for url in test_urls:

        result = check_https(url)

        print("\nURL:", url)
        print("HTTPS:", result["is_https"])
        print("Protocol:", result["protocol"])
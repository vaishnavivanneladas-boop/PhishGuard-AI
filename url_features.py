"""URL-only feature extraction shared by training and live predictions."""

import ipaddress
import re
from urllib.parse import urlsplit


URL_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "CharContinuationRate",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]


def _longest_run(url: str, predicate) -> int:
    longest = current = 0
    for character in url:
        if predicate(character):
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def extract_url_features(url: str) -> dict[str, int | float]:
    """Return features in URL_FEATURES order, without accessing the webpage."""
    original_url = url.strip()
    if not original_url:
        raise ValueError("Enter a non-empty URL.")

    normalized_url = (
        original_url
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original_url)
        else f"http://{original_url}"
    )
    parsed = urlsplit(normalized_url)
    domain = parsed.hostname or ""
    if not domain:
        raise ValueError("The URL must contain a valid hostname.")

    length = len(normalized_url)
    letters = sum(character.isalpha() for character in normalized_url)
    digits = sum(character.isdigit() for character in normalized_url)
    special_characters = sum(
        not character.isalnum() for character in normalized_url
    )
    obfuscated_characters = normalized_url.count("%")
    labels = domain.rstrip(".").split(".")
    try:
        ipaddress.ip_address(domain)
        is_ip_address = 1
    except ValueError:
        is_ip_address = 0

    continuation_length = (
        _longest_run(normalized_url, str.isalpha)
        + _longest_run(normalized_url, str.isdigit)
        + _longest_run(normalized_url, lambda character: not character.isalnum())
    )

    features = {
        "URLLength": length,
        "DomainLength": len(domain),
        "IsDomainIP": is_ip_address,
        "CharContinuationRate": continuation_length / max(length, 1),
        "TLDLength": len(labels[-1]) if len(labels) > 1 else 0,
        "NoOfSubDomain": max(0, len(labels) - 2),
        "HasObfuscation": int("%" in normalized_url or "@" in normalized_url),
        "NoOfObfuscatedChar": obfuscated_characters,
        "ObfuscationRatio": obfuscated_characters / max(length, 1),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / max(length, 1),
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / max(length, 1),
        "NoOfEqualsInURL": normalized_url.count("="),
        "NoOfQMarkInURL": normalized_url.count("?"),
        "NoOfAmpersandInURL": normalized_url.count("&"),
        "NoOfOtherSpecialCharsInURL": special_characters,
        "SpacialCharRatioInURL": special_characters / max(length, 1),
        "IsHTTPS": int(parsed.scheme.lower() == "https"),
    }
    return {feature: features[feature] for feature in URL_FEATURES}

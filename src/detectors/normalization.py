"""Canonicalization helpers for adversarial text scanning."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
BASE64_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
HEX_TOKEN_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{32,}\b")
MAX_DECODED_CHARS = 4096
MAX_VARIANTS = 8

# Homoglyph / confusable folding. NFKC does NOT fold Cyrillic/Greek letters that
# are visually identical to Latin (e.g. Cyrillic 'о' U+043E vs Latin 'o'), so an
# attacker can write "Ignоre previous instructions" and bypass ASCII regex.
# We fold the most-abused confusables to their Latin lowercase skeleton before
# matching. Folding to lowercase is safe because detection regexes use IGNORECASE.
# Reference: Unicode TR39 confusables, IDN homograph attacks.
_CONFUSABLES = {
    # Cyrillic lowercase
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
    "ո": "n",
    "г": "r",
    "ь": "b",
    "к": "k",
    "м": "m",
    "н": "h",
    "т": "t",
    "в": "b",
    # Cyrillic uppercase -> latin lowercase (IGNORECASE regexes still match)
    "А": "a",
    "Е": "e",
    "О": "o",
    "Р": "p",
    "С": "c",
    "У": "y",
    "Х": "x",
    "І": "i",
    "Ј": "j",
    "Ѕ": "s",
    "К": "k",
    "М": "m",
    "Н": "h",
    "Т": "t",
    "В": "b",
    "Г": "r",
    # Greek
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ρ": "p",
    "ν": "v",
    "τ": "t",
    "ι": "i",
    "κ": "k",
    "υ": "u",
    "χ": "x",
    "Ο": "o",
    "Α": "a",
    "Ε": "e",
    "Ρ": "p",
    "Τ": "t",
    "Κ": "k",
    "Χ": "x",
    "Β": "b",
    "Η": "h",
    "Ι": "i",
    "Ν": "n",
    # Fullwidth latin handled by NFKC; mathematical alphanumerics are too.
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)


def fold_confusables(text: str) -> str:
    """Fold visually-confusable Cyrillic/Greek characters to a Latin skeleton."""
    return text.translate(_CONFUSABLE_TABLE)


def canonicalize_text(text: str) -> str:
    """Return a normalized text form for pattern matching.

    Order: NFKC (fold compatibility chars, fullwidth, ligatures) -> strip
    zero-width chars -> fold Cyrillic/Greek homoglyphs to Latin skeleton.
    """
    normalized = unicodedata.normalize("NFKC", text)
    normalized = ZERO_WIDTH_RE.sub("", normalized)
    normalized = fold_confusables(normalized)
    return normalized


def detection_variants(text: str) -> list[str]:
    """Return bounded decoded/normalized variants for evasion-resistant scanning."""
    variants: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        canonical = canonicalize_text(value)
        if canonical not in seen and len(variants) < MAX_VARIANTS:
            variants.append(canonical)
            seen.add(canonical)

    add(text)

    for token in BASE64_TOKEN_RE.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
            decoded_text = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _is_printable(decoded_text):
            add(decoded_text[:MAX_DECODED_CHARS])

    for token in HEX_TOKEN_RE.findall(text):
        hex_value = token[2:] if token.lower().startswith("0x") else token
        if len(hex_value) % 2:
            continue
        try:
            decoded_text = bytes.fromhex(hex_value).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_printable(decoded_text):
            add(decoded_text[:MAX_DECODED_CHARS])

    return variants


def _is_printable(value: str) -> bool:
    if not value:
        return False
    printable = sum(ch.isprintable() or ch.isspace() for ch in value)
    return printable / len(value) >= 0.9

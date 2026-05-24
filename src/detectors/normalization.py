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


def canonicalize_text(text: str) -> str:
    """Return a normalized text form for pattern matching."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = ZERO_WIDTH_RE.sub("", normalized)
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

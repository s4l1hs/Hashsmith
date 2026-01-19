import base64
import binascii
import re
from typing import List, Tuple

from ..algorithms.decoding import (
    decode_base58,
    decode_hex,
    decode_binary,
    decode_decimal,
    decode_octal,
    decode_base64,
    decode_base32,
    decode_base85,
    decode_base64url,
    decode_morse_code,
    decode_baconian,
    decode_polybius,
    decode_unicode_escaped,
    decode_url,
)
from ..algorithms.encoding import (
    encode_base58,
    encode_hex,
    encode_binary,
    encode_decimal,
    encode_octal,
    encode_base64,
    encode_base32,
    encode_base85,
    encode_base64url,
    encode_morse_code,
    encode_baconian,
    encode_polybius,
    encode_unicode_escaped,
    encode_url,
)
from ..algorithms.morse import REVERSE_MORSE


def _normalize_spaces(value: str) -> str:
    return " ".join(value.strip().split())


def _is_hex(value: str) -> bool:
    return bool(value) and all(ch in "0123456789abcdefABCDEF" for ch in value)


def detect_encoding_types(text: str) -> List[str]:
    value = text.strip()
    if not value:
        return []

    results: List[str] = []

    # Hex (strict, UTF-8 round-trip)
    if len(value) % 2 == 0 and _is_hex(value):
        try:
            decoded = decode_hex(value)
            if encode_hex(decoded).lower() == value.lower():
                results.append("hex")
        except Exception:
            pass

    # Binary (8-bit groups)
    normalized = _normalize_spaces(value)
    if re.fullmatch(r"[01]{8}( [01]{8})*", normalized):
        try:
            decoded = decode_binary(normalized)
            if _normalize_spaces(encode_binary(decoded)) == normalized:
                results.append("binary")
        except Exception:
            pass

    # Decimal (space-separated 0-255)
    if re.fullmatch(r"\d{1,3}( \d{1,3})*", normalized):
        try:
            decoded = decode_decimal(normalized)
            if _normalize_spaces(encode_decimal(decoded)) == normalized:
                results.append("decimal")
        except Exception:
            pass

    # Octal (space-separated 0-7)
    if re.fullmatch(r"[0-7]{1,3}( [0-7]{1,3})*", normalized):
        try:
            decoded = decode_octal(normalized)
            if _normalize_spaces(encode_octal(decoded)) == normalized:
                results.append("octal")
        except Exception:
            pass

    # Base64 (strict, padded)
    try:
        decoded = decode_base64(value)
        if encode_base64(decoded) == value:
            results.append("base64")
    except Exception:
        pass

    # Base64URL (unpadded, URL-safe)
    if "=" not in value and re.fullmatch(r"[A-Za-z0-9_-]+", value):
        try:
            decoded = decode_base64url(value)
            if encode_base64url(decoded) == value:
                results.append("base64url")
        except Exception:
            pass

    # Base32 (strict, padded)
    try:
        decoded = decode_base32(value)
        if encode_base32(decoded) == value.upper():
            results.append("base32")
    except Exception:
        pass

    # Base85 (strict round-trip)
    try:
        decoded = decode_base85(value)
        if encode_base85(decoded) == value:
            results.append("base85")
    except Exception:
        pass

    # Base58 (strict round-trip)
    try:
        decoded = decode_base58(value)
        if encode_base58(decoded) == value:
            results.append("base58")
    except Exception:
        pass

    # URL encoding (must include at least one valid %XX)
    if re.search(r"%[0-9A-Fa-f]{2}", value):
        try:
            decoded = decode_url(value)
            if encode_url(decoded) == value:
                results.append("url")
        except Exception:
            pass

    # Morse (tokens must be known)
    if re.fullmatch(r"[.\-/ ]+", normalized):
        tokens = normalized.split()
        if tokens and all(token in REVERSE_MORSE for token in tokens):
            try:
                decoded = decode_morse_code(normalized)
                if _normalize_spaces(encode_morse_code(decoded)) == normalized:
                    results.append("morse")
            except Exception:
                pass

    # Baconian (A/B tokens)
    if re.fullmatch(r"[ABab/ ]+", normalized):
        try:
            decoded = decode_baconian(normalized)
            if _normalize_spaces(encode_baconian(decoded).upper()) == normalized.upper():
                results.append("baconian")
        except Exception:
            pass

    # Polybius (1-5 pairs and / for spaces)
    if re.fullmatch(r"[1-5/ ]+", normalized):
        try:
            decoded = decode_polybius(normalized)
            if _normalize_spaces(encode_polybius(decoded)) == normalized:
                results.append("polybius")
        except Exception:
            pass

    # Unicode escaped (\uXXXX)
    if re.fullmatch(r"(?:\\u[0-9a-fA-F]{4})+", value):
        try:
            decoded = decode_unicode_escaped(value)
            if encode_unicode_escaped(decoded) == value.lower():
                results.append("unicode")
        except Exception:
            pass

    return results


def _weights_for_hex_length(length: int) -> List[Tuple[str, float]]:
    return {
        16: [("mysql323", 1.0)],
        32: [("md5", 0.7), ("ntlm", 0.2), ("md4", 0.1)],
        40: [("sha1", 0.85), ("mssql2000", 0.15)],
        56: [("sha224", 0.8), ("sha3_224", 0.2)],
        64: [("sha256", 0.7), ("sha3_256", 0.2), ("blake2s", 0.1)],
        96: [("sha384", 1.0)],
        128: [("sha512", 0.7), ("sha3_512", 0.2), ("blake2b", 0.1)],
    }.get(length, [])


def _normalize_percentages(items: List[Tuple[str, float]]) -> List[Tuple[str, int]]:
    if not items:
        return []
    total = sum(weight for _, weight in items) or 1.0
    raw = [(name, weight / total * 100.0) for name, weight in items]
    rounded = [(name, int(round(pct))) for name, pct in raw]
    diff = 100 - sum(pct for _, pct in rounded)
    if diff != 0:
        name, pct = rounded[0]
        rounded[0] = (name, pct + diff)
    return rounded


def detect_hash_probabilities(value: str, top: int = 3) -> List[Tuple[str, int]]:
    text = value.strip()
    if not text:
        return []

    if text.startswith(("$2a$", "$2b$", "$2y$")):
        return [("bcrypt", 100)]
    if text.startswith("$argon2"):
        return [("argon2", 100)]
    if text.startswith("scrypt$"):
        return [("scrypt", 100)]
    if text.lower().startswith("0x0100"):
        return _normalize_percentages([("mssql2005", 0.5), ("mssql2012", 0.5)])
    if text.startswith("md5") and len(text) == 35:
        return [("postgres", 100)]
    if text.startswith("*") and len(text) == 41:
        return [("mysql41", 100)]

    if not _is_hex(text):
        return []

    weights = _weights_for_hex_length(len(text))
    if not weights:
        return []

    weights = sorted(weights, key=lambda item: item[1], reverse=True)[:top]
    return _normalize_percentages(weights)

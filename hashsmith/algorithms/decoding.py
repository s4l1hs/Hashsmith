import base64
import binascii
from urllib.parse import unquote

from .morse import decode_morse


def decode_base64(text: str) -> str:
    try:
        return base64.b64decode(text.encode("utf-8"), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ValueError("Invalid Base64 format provided")


def decode_hex(text: str) -> str:
    try:
        return binascii.unhexlify(text.encode("utf-8")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ValueError("Invalid Hex format provided")


def decode_binary(text: str) -> str:
    bits = text.strip().split()
    try:
        return bytes(int(chunk, 2) for chunk in bits).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Invalid Binary format provided")


def decode_url(text: str) -> str:
    return unquote(text)


def decode_base32(text: str) -> str:
    try:
        return base64.b32decode(text.encode("utf-8"), casefold=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ValueError("Invalid Base32 format provided")


def decode_base85(text: str) -> str:
    try:
        return base64.a85decode(text.encode("utf-8")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise ValueError("Invalid Base85 format provided")


def decode_decimal(text: str) -> str:
    parts = text.strip().split()
    try:
        values = [int(p) for p in parts]
        if any(v < 0 or v > 255 for v in values):
            raise ValueError
        return bytes(values).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Invalid Decimal format provided")


def decode_octal(text: str) -> str:
    parts = text.strip().split()
    try:
        values = [int(p, 8) for p in parts]
        if any(v < 0 or v > 255 for v in values):
            raise ValueError
        return bytes(values).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Invalid Octal format provided")


def decode_caesar(text: str, shift: int) -> str:
    return encode_caesar(text, -shift)


def decode_rot13(text: str) -> str:
    return encode_caesar(text, 13)


def decode_morse_code(text: str) -> str:
    return decode_morse(text)


def decode_vigenere(text: str, key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vigenere key must be alphabetic")
    key = key.lower()
    result = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            if "a" <= ch <= "z":
                result.append(chr(((ord(ch) - 97 - shift) % 26) + 97))
            else:
                result.append(chr(((ord(ch) - 65 - shift) % 26) + 65))
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


def decode_xor(text: str, key: str) -> str:
    if not key:
        raise ValueError("XOR key is required")
    try:
        data = binascii.unhexlify(text.encode("utf-8"))
    except (binascii.Error, ValueError):
        raise ValueError("Invalid XOR hex format provided")
    key_bytes = key.encode("utf-8")
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid XOR output for UTF-8")


def decode_atbash(text: str) -> str:
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr(122 - (ord(ch) - 97)))
        elif "A" <= ch <= "Z":
            result.append(chr(90 - (ord(ch) - 65)))
        else:
            result.append(ch)
    return "".join(result)


def decode_baconian(text: str) -> str:
    tokens = text.strip().split()
    result = []
    for token in tokens:
        if token == "/":
            result.append(" ")
            continue
        if len(token) != 5 or any(ch not in "ABab" for ch in token):
            raise ValueError("Invalid Baconian format provided")
        value = 0
        for ch in token.upper():
            value = (value << 1) | (1 if ch == "B" else 0)
        if value < 0 or value > 25:
            raise ValueError("Invalid Baconian format provided")
        result.append(chr(65 + value))
    return "".join(result)


def decode_leet_speak(text: str) -> str:
    mapping = {
        "0": "O",
        "1": "I",
        "3": "E",
        "4": "A",
        "5": "S",
        "7": "T",
    }
    return "".join(mapping.get(ch, ch) for ch in text)


def decode_reverse(text: str) -> str:
    return text[::-1]


def encode_caesar(text: str, shift: int) -> str:
    shift = shift % 26
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr(((ord(ch) - 97 + shift) % 26) + 97))
        elif "A" <= ch <= "Z":
            result.append(chr(((ord(ch) - 65 + shift) % 26) + 65))
        else:
            result.append(ch)
    return "".join(result)

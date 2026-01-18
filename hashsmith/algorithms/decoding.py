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


def decode_caesar(text: str, shift: int) -> str:
    return encode_caesar(text, -shift)


def decode_rot13(text: str) -> str:
    return encode_caesar(text, 13)


def decode_morse_code(text: str) -> str:
    return decode_morse(text)


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

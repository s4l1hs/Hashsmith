import base64
import binascii
from urllib.parse import quote

from .morse import encode_morse


def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def encode_hex(text: str) -> str:
    return binascii.hexlify(text.encode("utf-8")).decode("utf-8")


def encode_binary(text: str) -> str:
    return " ".join(format(byte, "08b") for byte in text.encode("utf-8"))


def encode_url(text: str) -> str:
    return quote(text, safe="")


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


def encode_rot13(text: str) -> str:
    return encode_caesar(text, 13)


def encode_morse_code(text: str) -> str:
    return encode_morse(text)

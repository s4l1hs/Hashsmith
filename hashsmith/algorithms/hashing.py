import hashlib
from typing import Callable, Dict


HASH_FUNCS: Dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def hash_text(text: str, algorithm: str, salt: str = "", salt_mode: str = "prefix") -> str:
    algo = algorithm.lower()
    if algo not in HASH_FUNCS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    if salt:
        if salt_mode == "suffix":
            text = f"{text}{salt}"
        else:
            text = f"{salt}{text}"

    h = HASH_FUNCS[algo]()
    h.update(text.encode("utf-8"))
    return h.hexdigest()

import itertools
import string
import time
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

from .hashing import hash_text
from ..utils.metrics import RateCounter


@dataclass
class CrackResult:
    found: bool
    password: Optional[str]
    attempts: int
    elapsed: float
    rate: float


def dictionary_attack(
    target_hash: str,
    algorithm: str,
    words: Iterable[str],
    salt: str = "",
    salt_mode: str = "prefix",
) -> CrackResult:
    start = time.perf_counter()
    counter = RateCounter()
    attempts = 0

    for word in words:
        attempts += 1
        if hash_text(word, algorithm, salt, salt_mode) == target_hash:
            elapsed = time.perf_counter() - start
            rate = counter.rate(attempts)
            return CrackResult(True, word, attempts, elapsed, rate)
        if attempts % 1000 == 0:
            counter.rate(attempts)

    elapsed = time.perf_counter() - start
    rate = counter.rate(attempts)
    return CrackResult(False, None, attempts, elapsed, rate)


def brute_force(
    target_hash: str,
    algorithm: str,
    charset: str = string.ascii_lowercase + string.digits,
    min_len: int = 1,
    max_len: int = 4,
    salt: str = "",
    salt_mode: str = "prefix",
) -> CrackResult:
    start = time.perf_counter()
    counter = RateCounter()
    attempts = 0

    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            candidate = "".join(combo)
            if hash_text(candidate, algorithm, salt, salt_mode) == target_hash:
                elapsed = time.perf_counter() - start
                rate = counter.rate(attempts)
                return CrackResult(True, candidate, attempts, elapsed, rate)
            if attempts % 1000 == 0:
                counter.rate(attempts)

    elapsed = time.perf_counter() - start
    rate = counter.rate(attempts)
    return CrackResult(False, None, attempts, elapsed, rate)


def format_rate(rate: float) -> str:
    if rate >= 1_000_000:
        return f"{rate / 1_000_000:.2f} M/s"
    if rate >= 1_000:
        return f"{rate / 1_000:.2f} K/s"
    return f"{rate:.2f} /s"

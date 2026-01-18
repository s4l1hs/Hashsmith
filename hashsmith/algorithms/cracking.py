import itertools
import string
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple, List

try:
    import bcrypt  # type: ignore
except Exception:  # pragma: no cover
    bcrypt = None

from .hashing import hash_text
from ..utils.metrics import RateCounter


@dataclass
class CrackResult:
    found: bool
    password: Optional[str]
    attempts: int
    elapsed: float
    rate: float


def _dictionary_worker(words: List[str], target_hash: str, algorithm: str, salt: str, salt_mode: str) -> Tuple[Optional[str], int]:
    attempts = 0
    for word in words:
        attempts += 1
        if algorithm == "bcrypt":
            if bcrypt is None:
                continue
            if bcrypt.checkpw(word.encode("utf-8"), target_hash.encode("utf-8")):
                return word, attempts
        else:
            if hash_text(word, algorithm, salt, salt_mode) == target_hash:
                return word, attempts
    return None, attempts


def dictionary_attack(
    target_hash: str,
    algorithm: str,
    words: Iterable[str],
    salt: str = "",
    salt_mode: str = "prefix",
    workers: int = 1,
) -> CrackResult:
    start = time.perf_counter()
    counter = RateCounter()
    attempts = 0

    if algorithm == "bcrypt" and bcrypt is None:
        raise ValueError("bcrypt library is required for bcrypt cracking")

    if workers > 1:
        batch = []
        futures = []
        with ProcessPoolExecutor(max_workers=workers) as executor:
            for word in words:
                batch.append(word)
                if len(batch) >= 500:
                    futures.append(executor.submit(_dictionary_worker, batch, target_hash, algorithm, salt, salt_mode))
                    batch = []
            if batch:
                futures.append(executor.submit(_dictionary_worker, batch, target_hash, algorithm, salt, salt_mode))

            for future in as_completed(futures):
                found, count = future.result()
                attempts += count
                if found:
                    elapsed = time.perf_counter() - start
                    rate = counter.rate(attempts)
                    return CrackResult(True, found, attempts, elapsed, rate)
    else:
        for word in words:
            attempts += 1
            if algorithm == "bcrypt":
                if bcrypt.checkpw(word.encode("utf-8"), target_hash.encode("utf-8")):
                    elapsed = time.perf_counter() - start
                    rate = counter.rate(attempts)
                    return CrackResult(True, word, attempts, elapsed, rate)
            else:
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
            if algorithm == "bcrypt":
                if bcrypt is None:
                    raise ValueError("bcrypt library is required for bcrypt cracking")
                if bcrypt.checkpw(candidate.encode("utf-8"), target_hash.encode("utf-8")):
                    elapsed = time.perf_counter() - start
                    rate = counter.rate(attempts)
                    return CrackResult(True, candidate, attempts, elapsed, rate)
            elif hash_text(candidate, algorithm, salt, salt_mode) == target_hash:
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

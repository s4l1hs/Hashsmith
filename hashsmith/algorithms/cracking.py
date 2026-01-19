import hashlib
import itertools
import string
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple, List, Callable

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


def _parse_scrypt_hash(target_hash: str) -> Tuple[int, int, int, bytes, bytes]:
    parts = target_hash.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        raise ValueError("Invalid scrypt hash format")
    n = int(parts[1])
    r = int(parts[2])
    p = int(parts[3])
    salt = bytes.fromhex(parts[4])
    digest = bytes.fromhex(parts[5])
    return n, r, p, salt, digest


def _parse_mssql_2005_salt(target_hash: str) -> bytes:
    value = target_hash.strip()
    if not value.lower().startswith("0x0100") or len(value) < 6 + 8:
        raise ValueError("Invalid MSSQL 2005/2012 hash format")
    return bytes.fromhex(value[6:14])


def _dictionary_worker(words: List[str], target_hash: str, algorithm: str, salt: str, salt_mode: str) -> Tuple[Optional[str], int]:
    attempts = 0
    scrypt_params = None
    if algorithm == "scrypt":
        scrypt_params = _parse_scrypt_hash(target_hash)
    mssql_salt = None
    if algorithm in {"mssql2005", "mssql2012"}:
        mssql_salt = _parse_mssql_2005_salt(target_hash)
    hasher = None
    verify_mismatch = None
    invalid_hash = None
    if algorithm == "argon2":
        try:
            from argon2 import PasswordHasher  # type: ignore
            from argon2.exceptions import VerifyMismatchError, InvalidHash  # type: ignore
        except Exception:  # pragma: no cover
            return None, attempts
        hasher = PasswordHasher()
        verify_mismatch = VerifyMismatchError
        invalid_hash = InvalidHash
    for word in words:
        attempts += 1
        if algorithm == "bcrypt":
            if bcrypt is None:
                continue
            if bcrypt.checkpw(word.encode("utf-8"), target_hash.encode("utf-8")):
                return word, attempts
        elif algorithm == "argon2":
            try:
                hasher.verify(target_hash, word)
                return word, attempts
            except (verify_mismatch, invalid_hash):
                continue
            except Exception:
                continue
        elif algorithm == "scrypt":
            n, r, p, salt_bytes, digest = scrypt_params
            candidate = hashlib.scrypt(word.encode("utf-8"), salt=salt_bytes, n=n, r=r, p=p, dklen=len(digest))
            if candidate == digest:
                return word, attempts
        elif algorithm in {"mssql2005", "mssql2012"}:
            digest = hashlib.sha1(mssql_salt + word.encode("utf-16le")).hexdigest().upper()
            if target_hash.lower().startswith("0x0100") and target_hash[14:].upper() == digest:
                return word, attempts
        else:
            if hash_text(word, algorithm, salt, salt_mode) == target_hash:
                return word, attempts
    return None, attempts


def _bruteforce_worker(
    prefixes: List[str],
    target_hash: str,
    algorithm: str,
    charset: str,
    length: int,
    salt: str,
    salt_mode: str,
) -> Tuple[Optional[str], int]:
    attempts = 0
    scrypt_params = None
    if algorithm == "scrypt":
        scrypt_params = _parse_scrypt_hash(target_hash)
    mssql_salt = None
    if algorithm in {"mssql2005", "mssql2012"}:
        mssql_salt = _parse_mssql_2005_salt(target_hash)
    hasher = None
    verify_mismatch = None
    invalid_hash = None
    if algorithm == "argon2":
        try:
            from argon2 import PasswordHasher  # type: ignore
            from argon2.exceptions import VerifyMismatchError, InvalidHash  # type: ignore
        except Exception:  # pragma: no cover
            return None, attempts
        hasher = PasswordHasher()
        verify_mismatch = VerifyMismatchError
        invalid_hash = InvalidHash

    for prefix in prefixes:
        remaining = length - len(prefix)
        if remaining < 0:
            continue
        if remaining == 0:
            attempts += 1
            candidate = prefix
            if algorithm == "bcrypt":
                if bcrypt is None:
                    continue
                if bcrypt.checkpw(candidate.encode("utf-8"), target_hash.encode("utf-8")):
                    return candidate, attempts
            elif algorithm == "argon2":
                try:
                    hasher.verify(target_hash, candidate)
                    return candidate, attempts
                except (verify_mismatch, invalid_hash):
                    continue
                except Exception:
                    continue
            elif algorithm == "scrypt":
                n, r, p, salt_bytes, digest = scrypt_params
                value = hashlib.scrypt(candidate.encode("utf-8"), salt=salt_bytes, n=n, r=r, p=p, dklen=len(digest))
                if value == digest:
                    return candidate, attempts
            elif algorithm in {"mssql2005", "mssql2012"}:
                digest = hashlib.sha1(mssql_salt + candidate.encode("utf-16le")).hexdigest().upper()
                if target_hash.lower().startswith("0x0100") and target_hash[14:].upper() == digest:
                    return candidate, attempts
            else:
                if hash_text(candidate, algorithm, salt, salt_mode) == target_hash:
                    return candidate, attempts
            continue

        for combo in itertools.product(charset, repeat=remaining):
            attempts += 1
            candidate = prefix + "".join(combo)
            if algorithm == "bcrypt":
                if bcrypt is None:
                    continue
                if bcrypt.checkpw(candidate.encode("utf-8"), target_hash.encode("utf-8")):
                    return candidate, attempts
            elif algorithm == "argon2":
                try:
                    hasher.verify(target_hash, candidate)
                    return candidate, attempts
                except (verify_mismatch, invalid_hash):
                    continue
                except Exception:
                    continue
            elif algorithm == "scrypt":
                n, r, p, salt_bytes, digest = scrypt_params
                value = hashlib.scrypt(candidate.encode("utf-8"), salt=salt_bytes, n=n, r=r, p=p, dklen=len(digest))
                if value == digest:
                    return candidate, attempts
            elif algorithm in {"mssql2005", "mssql2012"}:
                digest = hashlib.sha1(mssql_salt + candidate.encode("utf-16le")).hexdigest().upper()
                if target_hash.lower().startswith("0x0100") and target_hash[14:].upper() == digest:
                    return candidate, attempts
            else:
                if hash_text(candidate, algorithm, salt, salt_mode) == target_hash:
                    return candidate, attempts
    return None, attempts


def dictionary_attack(
    target_hash: str,
    algorithm: str,
    words: Iterable[str],
    salt: str = "",
    salt_mode: str = "prefix",
    workers: int = 1,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> CrackResult:
    start = time.perf_counter()
    counter = RateCounter()
    attempts = 0

    if algorithm == "bcrypt" and bcrypt is None:
        raise ValueError("bcrypt library is required for bcrypt cracking")
    if algorithm == "argon2":
        try:
            from argon2 import PasswordHasher  # type: ignore
            from argon2.exceptions import VerifyMismatchError, InvalidHash  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise ValueError("argon2-cffi library is required for argon2 cracking") from exc
        argon2_verify = (PasswordHasher(), VerifyMismatchError, InvalidHash)
    else:
        argon2_verify = None

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
                if progress_callback:
                    progress_callback(count)
                if found:
                    elapsed = time.perf_counter() - start
                    rate = counter.rate(attempts)
                    return CrackResult(True, found, attempts, elapsed, rate)
    else:
        scrypt_params = None
        if algorithm == "scrypt":
            scrypt_params = _parse_scrypt_hash(target_hash)
        mssql_salt = None
        if algorithm in {"mssql2005", "mssql2012"}:
            mssql_salt = _parse_mssql_2005_salt(target_hash)
        for word in words:
            attempts += 1
            if progress_callback:
                progress_callback(1)
            if algorithm == "bcrypt":
                if bcrypt.checkpw(word.encode("utf-8"), target_hash.encode("utf-8")):
                    elapsed = time.perf_counter() - start
                    rate = counter.rate(attempts)
                    return CrackResult(True, word, attempts, elapsed, rate)
            elif algorithm == "argon2":
                hasher, verify_mismatch, invalid_hash = argon2_verify
                try:
                    hasher.verify(target_hash, word)
                    elapsed = time.perf_counter() - start
                    rate = counter.rate(attempts)
                    return CrackResult(True, word, attempts, elapsed, rate)
                except (verify_mismatch, invalid_hash):
                    pass
            elif algorithm == "scrypt":
                n, r, p, salt_bytes, digest = scrypt_params
                candidate = hashlib.scrypt(word.encode("utf-8"), salt=salt_bytes, n=n, r=r, p=p, dklen=len(digest))
                if candidate == digest:
                    elapsed = time.perf_counter() - start
                    rate = counter.rate(attempts)
                    return CrackResult(True, word, attempts, elapsed, rate)
            elif algorithm in {"mssql2005", "mssql2012"}:
                digest = hashlib.sha1(mssql_salt + word.encode("utf-16le")).hexdigest().upper()
                if target_hash.lower().startswith("0x0100") and target_hash[14:].upper() == digest:
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
    workers: int = 1,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> CrackResult:
    start = time.perf_counter()
    counter = RateCounter()
    attempts = 0
    if algorithm == "bcrypt" and bcrypt is None:
        raise ValueError("bcrypt library is required for bcrypt cracking")
    if algorithm == "argon2":
        try:
            from argon2 import PasswordHasher  # type: ignore
            from argon2.exceptions import VerifyMismatchError, InvalidHash  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise ValueError("argon2-cffi library is required for argon2 cracking") from exc
        argon2_verify = (PasswordHasher(), VerifyMismatchError, InvalidHash)
    else:
        argon2_verify = None

    scrypt_params = None
    if algorithm == "scrypt":
        scrypt_params = _parse_scrypt_hash(target_hash)

    mssql_salt = None
    if algorithm in {"mssql2005", "mssql2012"}:
        mssql_salt = _parse_mssql_2005_salt(target_hash)

    if workers > 1:
        prefixes = list(charset)
        futures = []
        with ProcessPoolExecutor(max_workers=workers) as executor:
            for length in range(min_len, max_len + 1):
                batch: List[str] = []
                for prefix in prefixes:
                    batch.append(prefix)
                    if len(batch) >= 50:
                        futures.append(
                            executor.submit(
                                _bruteforce_worker,
                                batch,
                                target_hash,
                                algorithm,
                                charset,
                                length,
                                salt,
                                salt_mode,
                            )
                        )
                        batch = []
                if batch:
                    futures.append(
                        executor.submit(
                            _bruteforce_worker,
                            batch,
                            target_hash,
                            algorithm,
                            charset,
                            length,
                            salt,
                            salt_mode,
                        )
                    )

            for future in as_completed(futures):
                found, count = future.result()
                attempts += count
                if progress_callback:
                    progress_callback(count)
                if found:
                    elapsed = time.perf_counter() - start
                    rate = counter.rate(attempts)
                    return CrackResult(True, found, attempts, elapsed, rate)
                if attempts % 1000 == 0:
                    counter.rate(attempts)
    else:
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                attempts += 1
                if progress_callback:
                    progress_callback(1)
                candidate = "".join(combo)
                if algorithm == "bcrypt":
                    if bcrypt is None:
                        raise ValueError("bcrypt library is required for bcrypt cracking")
                    if bcrypt.checkpw(candidate.encode("utf-8"), target_hash.encode("utf-8")):
                        elapsed = time.perf_counter() - start
                        rate = counter.rate(attempts)
                        return CrackResult(True, candidate, attempts, elapsed, rate)
                elif algorithm == "argon2":
                    hasher, verify_mismatch, invalid_hash = argon2_verify
                    try:
                        hasher.verify(target_hash, candidate)
                        elapsed = time.perf_counter() - start
                        rate = counter.rate(attempts)
                        return CrackResult(True, candidate, attempts, elapsed, rate)
                    except (verify_mismatch, invalid_hash):
                        pass
                elif algorithm == "scrypt":
                    n, r, p, salt_bytes, digest = scrypt_params
                    value = hashlib.scrypt(candidate.encode("utf-8"), salt=salt_bytes, n=n, r=r, p=p, dklen=len(digest))
                    if value == digest:
                        elapsed = time.perf_counter() - start
                        rate = counter.rate(attempts)
                        return CrackResult(True, candidate, attempts, elapsed, rate)
                elif algorithm in {"mssql2005", "mssql2012"}:
                    digest = hashlib.sha1(mssql_salt + candidate.encode("utf-16le")).hexdigest().upper()
                    if target_hash.lower().startswith("0x0100") and target_hash[14:].upper() == digest:
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

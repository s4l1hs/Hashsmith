from pathlib import Path
from typing import Iterable


def iter_wordlist(path: str) -> Iterable[str]:
    file_path = Path(path).expanduser().resolve()
    with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.strip()
            if word:
                yield word

from pathlib import Path
from typing import Optional


def read_text_from_file(path: str) -> str:
    file_path = Path(path).expanduser().resolve()
    if not file_path.exists():
        raise ValueError(f"File not found: {path}")
    if file_path.is_dir():
        raise ValueError(f"Expected a file but got a directory: {path}")
    try:
        return file_path.read_text(encoding="utf-8")
    except PermissionError:
        raise ValueError(f"Permission denied for file: {path}")
    except IsADirectoryError:
        raise ValueError(f"Expected a file but got a directory: {path}")


def write_text_to_file(path: str, content: str) -> None:
    file_path = Path(path).expanduser().resolve()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")


def resolve_input(text: Optional[str], file_path: Optional[str]) -> str:
    if text:
        return text
    if file_path:
        return read_text_from_file(file_path)
    raise ValueError("Provide --text or --file")

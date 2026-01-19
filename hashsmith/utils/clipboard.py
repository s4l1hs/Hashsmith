import os
import shutil
import subprocess
import sys
from typing import Sequence, Union


def _run_copy(command: Union[str, Sequence[str]], text: str, shell: bool = False) -> bool:
    try:
        subprocess.run(
            command,
            input=text,
            text=True,
            check=True,
            shell=shell,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False


def copy_to_clipboard(text: str) -> bool:
    content = text or ""
    if sys.platform == "darwin":
        return _run_copy(["pbcopy"], content)
    if os.name == "nt":
        return _run_copy("clip", content, shell=True)

    if shutil.which("wl-copy"):
        return _run_copy(["wl-copy"], content)
    if shutil.which("xclip"):
        return _run_copy(["xclip", "-selection", "clipboard"], content)
    if shutil.which("xsel"):
        return _run_copy(["xsel", "--clipboard", "--input"], content)
    return False

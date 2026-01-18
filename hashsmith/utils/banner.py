from rich.console import Console
from rich.panel import Panel
from rich.text import Text


ASCII_ART = r"""
 _   _           _     ____            _ _   _     
| | | | __ _ ___| |__ / ___| _ __ ___ (_) |_| |__  
| |_| |/ _` / __| '_ \\___ \| '_ ` _ \| | __| '_ \ 
|  _  | (_| \__ \ | | |___) | | | | | | | |_| | | |
|_| |_|\__,_|___/_| |_|____/|_| |_| |_|_|\__|_| |_|
"""


def render_banner(console: Console, accent: str = "cyan") -> None:
    title = Text("Hashsmith", style=f"bold {accent}")
    subtitle = Text("Modular CLI for encoding, decoding, hashing, cracking", style="dim")
    art = Text(ASCII_ART, style=f"{accent}")
    content = Text.assemble(art, "\n", title, "\n", subtitle)
    console.print(Panel(content, border_style=accent))

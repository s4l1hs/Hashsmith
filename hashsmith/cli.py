import argparse
from typing import Optional

from rich.console import Console
from rich.prompt import IntPrompt, Prompt
from rich.text import Text

from .algorithms.cracking import brute_force, dictionary_attack, format_rate
from .algorithms.decoding import (
    decode_base64,
    decode_binary,
    decode_caesar,
    decode_hex,
    decode_morse_code,
    decode_rot13,
    decode_url,
)
from .algorithms.encoding import (
    encode_base64,
    encode_binary,
    encode_caesar,
    encode_hex,
    encode_morse_code,
    encode_rot13,
    encode_url,
)
from .algorithms.hashing import hash_text
from .utils.banner import render_banner
from .utils.io import read_text_from_file, resolve_input, write_text_to_file
from .utils.wordlist import iter_wordlist
from pathlib import Path


THEMES = {
    "cyan": "cyan",
    "green": "green",
    "magenta": "magenta",
    "blue": "blue",
    "yellow": "yellow",
    "red": "red",
    "white": "white",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashsmith",
        description="Hashsmith CLI for encoding, decoding, hashing, and cracking.",
    )
    parser.add_argument("--no-banner", action="store_true", help="Disable banner")
    parser.add_argument("--theme", choices=list(THEMES.keys()), default="cyan", help="Accent color")

    subparsers = parser.add_subparsers(dest="command")

    encode_parser = subparsers.add_parser("encode", help="Encode text")
    encode_parser.add_argument("--type", required=True, choices=[
        "base64", "hex", "binary", "morse", "url", "caesar", "rot13"
    ])
    encode_parser.add_argument("--text", help="Text input")
    encode_parser.add_argument("--file", help="Read input from file")
    encode_parser.add_argument("--shift", type=int, default=3, help="Shift for Caesar")
    encode_parser.add_argument("--out", help="Write output to file")

    decode_parser = subparsers.add_parser("decode", help="Decode text")
    decode_parser.add_argument("--type", required=True, choices=[
        "base64", "hex", "binary", "morse", "url", "caesar", "rot13"
    ])
    decode_parser.add_argument("--text", help="Text input")
    decode_parser.add_argument("--file", help="Read input from file")
    decode_parser.add_argument("--shift", type=int, default=3, help="Shift for Caesar")
    decode_parser.add_argument("--out", help="Write output to file")

    hash_parser = subparsers.add_parser("hash", help="Hash text")
    hash_parser.add_argument("--type", required=True, choices=[
        "md5", "sha1", "sha256", "sha512"
    ])
    hash_parser.add_argument("--text", help="Text input")
    hash_parser.add_argument("--file", help="Read input from file")
    hash_parser.add_argument("--salt", default="", help="Salt value")
    hash_parser.add_argument("--salt-mode", default="prefix", choices=["prefix", "suffix"])
    hash_parser.add_argument("--out", help="Write output to file")

    crack_parser = subparsers.add_parser("crack", help="Crack hash")
    crack_parser.add_argument("--type", required=True, choices=[
        "md5", "sha1", "sha256", "sha512"
    ])
    crack_parser.add_argument("--hash", required=True, dest="target_hash")
    crack_parser.add_argument("--mode", required=True, choices=["dict", "brute"])
    crack_parser.add_argument("--wordlist", help="Wordlist path for dictionary attack")
    crack_parser.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789")
    crack_parser.add_argument("--min-len", type=int, default=1)
    crack_parser.add_argument("--max-len", type=int, default=4)
    crack_parser.add_argument("--salt", default="")
    crack_parser.add_argument("--salt-mode", default="prefix", choices=["prefix", "suffix"])

    subparsers.add_parser("interactive", help="Guided interactive mode")

    return parser


def handle_encode(args: argparse.Namespace, console: Console) -> str:
    text = resolve_input(args.text, args.file)
    if args.type == "base64":
        return encode_base64(text)
    if args.type == "hex":
        return encode_hex(text)
    if args.type == "binary":
        return encode_binary(text)
    if args.type == "morse":
        return encode_morse_code(text)
    if args.type == "url":
        return encode_url(text)
    if args.type == "caesar":
        return encode_caesar(text, args.shift)
    if args.type == "rot13":
        return encode_rot13(text)
    raise ValueError("Unsupported encode type")


def handle_decode(args: argparse.Namespace, console: Console) -> str:
    text = resolve_input(args.text, args.file)
    if args.type == "base64":
        return decode_base64(text)
    if args.type == "hex":
        return decode_hex(text)
    if args.type == "binary":
        return decode_binary(text)
    if args.type == "morse":
        return decode_morse_code(text)
    if args.type == "url":
        return decode_url(text)
    if args.type == "caesar":
        return decode_caesar(text, args.shift)
    if args.type == "rot13":
        return decode_rot13(text)
    raise ValueError("Unsupported decode type")


def handle_hash(args: argparse.Namespace, console: Console) -> str:
    text = resolve_input(args.text, args.file)
    return hash_text(text, args.type, args.salt, args.salt_mode)


def is_hex_string(value: str) -> bool:
    if not value:
        return False
    value = value.strip()
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def handle_crack(args: argparse.Namespace, console: Console, accent: str = "cyan") -> int:
    if args.mode == "dict":
        if not args.wordlist:
            console.print("[red]--wordlist is required for dict mode[/red]")
            return 2
        result = dictionary_attack(
            args.target_hash,
            args.type,
            iter_wordlist(args.wordlist),
            args.salt,
            args.salt_mode,
        )
    else:
        result = brute_force(
            args.target_hash,
            args.type,
            charset=args.charset,
            min_len=args.min_len,
            max_len=args.max_len,
            salt=args.salt,
            salt_mode=args.salt_mode,
        )

    if result.found:
        console.print(f"[green]Found:[/green] {result.password}")
    else:
        console.print("[yellow]Not found[/yellow]")

    console.print(
        Text(
            f"Attempts: {result.attempts} | Elapsed: {result.elapsed:.2f}s | Rate: {format_rate(result.rate)}",
            style=accent,
        )
    )
    return 0


def output_result(result: str, out: Optional[str], console: Console) -> None:
    if out:
        write_text_to_file(out, result)
        console.print(f"[green]Saved to {out}[/green]")
    else:
        console.print(result)


def interactive_mode(console: Console, accent: str) -> None:
    console.print(f"[bold {accent}]Interactive mode[/bold {accent}]")

    class BackAction(Exception):
        pass

    def maybe_exit(value: str) -> None:
        if value.strip().lower() in {"bye", "exit", "q", "quit"}:
            console.print(f"[bold {accent}]Goodbye[/bold {accent}]")
            raise SystemExit(0)

    def ask_text(label: str, default: Optional[str] = None) -> str:
        value = Prompt.ask(label, default=default)
        maybe_exit(value)
        return value

    def ask_int(label: str, default: int) -> int:
        attempts = 0
        while attempts < 3:
            value = Prompt.ask(label, default=str(default))
            maybe_exit(value)
            try:
                return int(value)
            except ValueError:
                attempts += 1
                console.print("[red]Invalid number.[/red] Please try again.")
        console.print("[red]Too many invalid attempts. Exiting.[/red]")
        raise SystemExit(2)

    def choose_option(label: str, options: list[str], default_index: int = 1) -> str:
        attempts = 0
        while attempts < 3:
            console.print(f"\n{label}:")
            console.print(f"  [{accent}]0[/{accent}]) Back")
            for idx, option in enumerate(options, start=1):
                console.print(f"  [{accent}]{idx}[/{accent}]) {option}")
            console.print(f"  [{accent}]q[/{accent}]) Quit")
            raw = ask_text("Select option", default=str(default_index)).strip().lower()
            if raw == "0":
                raise BackAction()
            maybe_exit(raw)
            try:
                choice = int(raw)
            except ValueError:
                attempts += 1
                console.print("[red]Invalid selection.[/red] Please try again.")
                continue
            if 1 <= choice <= len(options):
                return options[choice - 1]
            attempts += 1
            console.print("[red]Invalid selection.[/red] Please try again.")
        console.print("[red]Too many invalid attempts. Exiting.[/red]")
        raise SystemExit(2)

    def ask_yes_no(label: str, default: bool = False) -> bool:
        attempts = 0
        default_str = "y" if default else "n"
        while attempts < 3:
            value = ask_text(f"{label} (y/n)", default=default_str)
            normalized = value.strip().lower()
            if normalized in {"y", "yes"}:
                return True
            if normalized in {"n", "no"}:
                return False
            attempts += 1
            console.print("[red]Invalid input.[/red] Use y/n (or yes/no).")
        console.print("[red]Too many invalid attempts. Exiting.[/red]")
        raise SystemExit(2)

    # Helper: get input either text or file (reusable)
    def _get_interactive_input(prompt_label: str) -> tuple[Optional[str], Optional[str]]:
        while True:
            choice = choose_option(prompt_label, ["enter custom text", "use file"], default_index=1)
            if choice == "enter custom text":
                txt = ask_text("Enter text", default="Hashsmith_Sample")
                return txt, None
            if choice == "use file":
                fp = ask_text("File path")
                try:
                    content = read_text_from_file(fp)
                except ValueError as exc:
                    console.print(f"[bold red]Error:[/bold red] {exc}")
                    continue
                return content, None

    def _get_interactive_output() -> Optional[str]:
        if ask_yes_no("Save output to file?", default=False):
            out_choice = choose_option("Output path", ["use default output.txt", "enter custom path"], default_index=1)
            return "output.txt" if out_choice.startswith("use default") else ask_text("Output file path")
        return None

    actions = ["encode", "decode", "hash", "crack", "set-theme"]
    while True:
        try:
            action = choose_option("Choose action", actions, default_index=1)

            if action == "set-theme":
                theme_keys = list(THEMES.keys())
                selected = choose_option("Select theme", theme_keys, default_index=1)
                accent = THEMES.get(selected, "cyan")
                render_banner(console, accent)
                console.print(f"Theme set to [bold {accent}]{selected}[/bold {accent}]")
                continue

            if action in {"encode", "decode", "hash"}:
                out_path = _get_interactive_output()

                if action == "encode":
                    enc_options = ["base64", "hex", "binary", "morse", "url", "caesar", "rot13"]
                    enc_type = choose_option("Encoding type", enc_options, default_index=1)
                    shift = ask_int("Caesar shift", default=3) if enc_type == "caesar" else 3
                    text, file_path = _get_interactive_input("Input source")
                    args = argparse.Namespace(type=enc_type, text=text or None, file=file_path, shift=shift)
                    try:
                        result = handle_encode(args, console)
                        output_result(result, out_path, console)
                        return
                    except ValueError as exc:
                        console.print(f"[bold red]Error:[/bold red] {exc}")
                        continue

                if action == "decode":
                    dec_options = ["base64", "hex", "binary", "morse", "url", "caesar", "rot13"]
                    dec_type = choose_option("Decoding type", dec_options, default_index=1)
                    shift = ask_int("Caesar shift", default=3) if dec_type == "caesar" else 3
                    text, file_path = _get_interactive_input("Input source")
                    args = argparse.Namespace(type=dec_type, text=text or None, file=file_path, shift=shift)
                    try:
                        result = handle_decode(args, console)
                        output_result(result, out_path, console)
                        return
                    except ValueError as exc:
                        console.print(f"[bold red]Error:[/bold red] {exc}")
                        continue

                hash_options = ["md5", "sha1", "sha256", "sha512"]
                hash_type = choose_option("Hash type", hash_options, default_index=3)
                text, file_path = _get_interactive_input("Input source")
                salt = ""
                if ask_yes_no("Use salt?", default=False):
                    salt = ask_text("Salt value")
                salt_mode = choose_option("Salt mode", ["prefix", "suffix"], default_index=1) if salt else "prefix"
                args = argparse.Namespace(type=hash_type, text=text or None, file=file_path, salt=salt, salt_mode=salt_mode)
                try:
                    result = handle_hash(args, console)
                    output_result(result, out_path, console)
                    return
                except ValueError as exc:
                    console.print(f"[bold red]Error:[/bold red] {exc}")
                    continue

            crack_type = choose_option("Hash type", ["md5", "sha1", "sha256", "sha512"], default_index=1)
            mode = choose_option("Mode", ["dict", "brute"], default_index=1)
            while True:
                target_hash = ask_text("Target hash")
                if not is_hex_string(target_hash):
                    console.print("[bold red]Error:[/bold red] Hash must be hexadecimal (0-9, a-f).")
                    continue
                break
            # Auto-detect hash type by length
            detected = None
            l = len(target_hash.strip())
            if l == 32:
                detected = "md5"
            elif l == 40:
                detected = "sha1"
            elif l == 64:
                detected = "sha256"
            elif l == 128:
                detected = "sha512"
            if detected:
                if ask_yes_no(f"Detected: {detected.upper()}. Use this?", default=True):
                    crack_type = detected
                else:
                    crack_type = choose_option("Hash type", ["md5", "sha1", "sha256", "sha512"], default_index=1)
            else:
                crack_type = choose_option("Hash type", ["md5", "sha1", "sha256", "sha512"], default_index=1)
            salt = ""
            if ask_yes_no("Use salt?", default=False):
                salt = ask_text("Salt value")
            salt_mode = choose_option("Salt mode", ["prefix", "suffix"], default_index=1) if salt else "prefix"

            if mode == "dict":
                wordlist_choice = choose_option("Wordlist", ["use default wordlists/common.txt", "enter custom path"], default_index=1)
                wordlist = "wordlists/common.txt" if wordlist_choice.startswith("use default") else ask_text("Wordlist path")
                args = argparse.Namespace(
                    type=crack_type,
                    target_hash=target_hash,
                    mode=mode,
                    wordlist=wordlist,
                    charset="",
                    min_len=1,
                    max_len=4,
                    salt=salt,
                    salt_mode=salt_mode,
                )
                raise SystemExit(handle_crack(args, console, accent))

            charset_choice = choose_option("Charset", ["use default [a-z0-9]", "enter custom"], default_index=1)
            charset = "abcdefghijklmnopqrstuvwxyz0123456789" if charset_choice.startswith("use default") else ask_text("Charset")
            min_len = ask_int("Min length", default=1)
            max_len = ask_int("Max length", default=4)
            args = argparse.Namespace(
                type=crack_type,
                target_hash=target_hash,
                mode=mode,
                wordlist=None,
                charset=charset,
                min_len=min_len,
                max_len=max_len,
                salt=salt,
                salt_mode=salt_mode,
            )
            raise SystemExit(handle_crack(args, console, accent))
        except BackAction:
            continue


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    console = Console()

    accent = THEMES.get(args.theme, "cyan")

    try:
        if args.command is None:
            if not args.no_banner:
                render_banner(console, accent)
            interactive_mode(console, accent)
        elif args.command == "interactive":
            if not args.no_banner:
                render_banner(console, accent)
            interactive_mode(console, accent)
        elif args.command == "encode":
            if not args.no_banner:
                render_banner(console, accent)
            try:
                result = handle_encode(args, console)
                output_result(result, args.out, console)
            except ValueError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                raise SystemExit(2)
        elif args.command == "decode":
            if not args.no_banner:
                render_banner(console, accent)
            try:
                result = handle_decode(args, console)
                output_result(result, args.out, console)
            except ValueError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                raise SystemExit(2)
        elif args.command == "hash":
            if not args.no_banner:
                render_banner(console, accent)
            try:
                result = handle_hash(args, console)
                output_result(result, args.out, console)
            except ValueError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                raise SystemExit(2)
        elif args.command == "crack":
            if not args.no_banner:
                render_banner(console, accent)
            if not is_hex_string(args.target_hash):
                console.print("[bold red]Error:[/bold red] Hash must be hexadecimal (0-9, a-f).")
                raise SystemExit(2)
            raise SystemExit(handle_crack(args, console, accent))
        else:
            parser.print_help()
    except KeyboardInterrupt:
        console.print(f"\n[bold {accent}]Goodbye[/bold {accent}]")
        raise SystemExit(0)
    except Exception:
        console.print("[bold red]Error:[/bold red] An unexpected error occurred. Please report this issue.")
        raise SystemExit(1)

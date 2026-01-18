import argparse
from typing import Optional

from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt
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
from .utils.io import resolve_input, write_text_to_file
from .utils.wordlist import iter_wordlist


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashsmith",
        description="Hashsmith CLI for encoding, decoding, hashing, and cracking.",
    )
    parser.add_argument("--no-banner", action="store_true", help="Disable banner")

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


def handle_hash(args: argparse.Namespace) -> str:
    text = resolve_input(args.text, args.file)
    return hash_text(text, args.type, args.salt, args.salt_mode)


def handle_crack(args: argparse.Namespace, console: Console) -> int:
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
            style="cyan",
        )
    )
    return 0


def output_result(result: str, out: Optional[str], console: Console) -> None:
    if out:
        write_text_to_file(out, result)
        console.print(f"[green]Saved to {out}[/green]")
    else:
        console.print(result)


def interactive_mode(console: Console) -> None:
    console.print("[bold cyan]Interactive mode[/bold cyan]")
    def choose_option(label: str, options: list[str], default_index: int = 1) -> str:
        console.print(f"\n{label}:")
        for idx, option in enumerate(options, start=1):
            console.print(f"  [cyan]{idx}[/cyan]) {option}")
        choice = IntPrompt.ask("Select option", default=default_index)
        if choice < 1 or choice > len(options):
            console.print("[red]Invalid selection[/red]")
            raise SystemExit(2)
        return options[choice - 1]

    actions = ["encode", "decode", "hash", "crack"]
    action = choose_option("Choose action", actions, default_index=1)

    if action in {"encode", "decode", "hash"}:
        text = Prompt.ask("Text (leave empty to use file)", default="")
        file_path = None
        if not text:
            file_path = Prompt.ask("File path")

        out_path = None
        if Confirm.ask("Save output to file?", default=False):
            out_path = Prompt.ask("Output file path")

        if action == "encode":
            enc_options = ["base64", "hex", "binary", "morse", "url", "caesar", "rot13"]
            enc_type = choose_option("Encoding type", enc_options, default_index=1)
            shift = IntPrompt.ask("Caesar shift", default=3) if enc_type == "caesar" else 3
            args = argparse.Namespace(type=enc_type, text=text or None, file=file_path, shift=shift)
            result = handle_encode(args, console)
            output_result(result, out_path, console)
            return

        if action == "decode":
            dec_options = ["base64", "hex", "binary", "morse", "url", "caesar", "rot13"]
            dec_type = choose_option("Decoding type", dec_options, default_index=1)
            shift = IntPrompt.ask("Caesar shift", default=3) if dec_type == "caesar" else 3
            args = argparse.Namespace(type=dec_type, text=text or None, file=file_path, shift=shift)
            result = handle_decode(args, console)
            output_result(result, out_path, console)
            return

        hash_options = ["md5", "sha1", "sha256", "sha512"]
        hash_type = choose_option("Hash type", hash_options, default_index=3)
        salt = Prompt.ask("Salt (optional)", default="")
        salt_mode = choose_option("Salt mode", ["prefix", "suffix"], default_index=1)
        args = argparse.Namespace(type=hash_type, text=text or None, file=file_path, salt=salt, salt_mode=salt_mode)
        result = handle_hash(args)
        output_result(result, out_path, console)
        return

    crack_type = choose_option("Hash type", ["md5", "sha1", "sha256", "sha512"], default_index=1)
    target_hash = Prompt.ask("Target hash")
    mode = choose_option("Mode", ["dict", "brute"], default_index=1)
    salt = Prompt.ask("Salt (optional)", default="")
    salt_mode = choose_option("Salt mode", ["prefix", "suffix"], default_index=1)

    if mode == "dict":
        wordlist = Prompt.ask("Wordlist path", default="wordlists/common.txt")
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
        raise SystemExit(handle_crack(args, console))

    charset = Prompt.ask("Charset", default="abcdefghijklmnopqrstuvwxyz0123456789")
    min_len = IntPrompt.ask("Min length", default=1)
    max_len = IntPrompt.ask("Max length", default=4)
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
    raise SystemExit(handle_crack(args, console))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    console = Console()

    if not args.no_banner:
        render_banner(console)

    if args.command is None:
        interactive_mode(console)
    elif args.command == "interactive":
        interactive_mode(console)
    elif args.command == "encode":
        result = handle_encode(args, console)
        output_result(result, args.out, console)
    elif args.command == "decode":
        result = handle_decode(args, console)
        output_result(result, args.out, console)
    elif args.command == "hash":
        result = handle_hash(args)
        output_result(result, args.out, console)
    elif args.command == "crack":
        raise SystemExit(handle_crack(args, console))
    else:
        parser.print_help()

# Hashsmith
Hashsmith is a modular, terminal-based Swiss Army knife for encoding, decoding, hashing, and password cracking. Built for security enthusiasts 🛠️🔐

## Features
- Encoding/Decoding: Base64, Hex, Binary, Morse, URL, Caesar, ROT13
- Hashing: MD5, SHA-1, SHA-256, SHA-512
- Cracking: Dictionary attack and basic brute-force
- File input/output support
- Optional salt support for hashing and cracking

## Installation
1. Create a virtual environment (optional)
2. Install dependencies:

```
pip install -r requirements.txt
```

## Usage
Run via module:

```
python -m hashsmith --help
```

### Encode
```
python -m hashsmith encode --type base64 --text "hello"
python -m hashsmith encode --type caesar --shift 5 --file input.txt --out output.txt
```

### Decode
```
python -m hashsmith decode --type base64 --text "aGVsbG8="
python -m hashsmith decode --type morse --text ".... . .-.. .-.. ---"
```

### Hash
```
python -m hashsmith hash --type sha256 --text "hello"
python -m hashsmith hash --type md5 --text "secret" --salt "pepper" --salt-mode suffix
```

### Crack
```
python -m hashsmith crack --type md5 --hash 5f4dcc3b5aa765d61d8327deb882cf99 --mode dict --wordlist wordlists/common.txt
python -m hashsmith crack --type sha1 --hash 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed --mode brute --min-len 1 --max-len 4
```

## Notes
- Dictionary cracking uses the provided wordlist file.
- Brute-force is intentionally small by default; adjust `--min-len` and `--max-len` carefully.

## Roadmap
- Multithreading for cracking
- Additional encodings and hash types
- Better progress indicators

# Password Generator

A secure CLI password generator with HaveIBeenPwned breach checking, k-anonymity privacy preservation, and auto-clearing clipboard support.

## Features

- **Cryptographically secure generation** — uses Python's `secrets` module (CSPRNG), not `random`
- **k-anonymity breach checking** — only the first 5 chars of the SHA-1 hash are sent to the HIBP API; the full hash never leaves the machine
- **Entropy calculation + crack-time estimate** — shows how long the password would take to brute-force
- **Auto-clearing clipboard** — password is wiped from the clipboard after a configurable delay
- **In-memory wiping** — password variable is deleted and garbage-collected after use
- **URL allowlist + HTTPS enforcement** — HIBP endpoint is validated before any outbound request
- **Rate limiting** — enforces a minimum interval between API calls
- **Ambiguous character exclusion** — optionally strip visually confusing chars (`0`, `O`, `l`, `1`, `I`)
- **Two modes** — interactive prompt-based mode, and a scriptable CLI flag mode

## Installation

```bash
git clone <repo-url>
cd PythonProjects
pip install -r requirements.txt
cp .env.example .env
```

## Usage

### Interactive mode

```bash
python3 PasswordGenerator.py
```

Prompts you for letter/symbol/number counts and walks you through the options.

### CLI mode

```bash
# Generate one 14-char password and copy to clipboard
python3 PasswordGenerator.py --letters 10 --symbols 2 --numbers 2

# Show password on screen, skip breach check
python3 PasswordGenerator.py -l 10 -s 2 -n 2 --show --no-breach-check

# Generate 5 passwords at once (auto-prints all, no clipboard copy)
python3 PasswordGenerator.py -l 8 -n 2 --count 5

# Exclude ambiguous characters
python3 PasswordGenerator.py -l 12 -s 2 -n 2 --no-ambiguous
```

### Flags

| Flag | Short | Description |
|---|---|---|
| `--letters N` | `-l N` | Number of letters |
| `--symbols N` | `-s N` | Number of symbols |
| `--numbers N` | `-n N` | Number of numbers |
| `--count N` | `-c N` | Generate N passwords (default: 1) |
| `--show` | | Print password to stdout |
| `--no-ambiguous` | | Exclude `0 O l 1 I` |
| `--no-breach-check` | | Skip HIBP API call |
| `--no-clipboard` | | Don't copy to clipboard |
| `--help` | `-h` | Show help |

## Configuration

All thresholds and URLs are driven by `.env` (see `.env.example` for defaults):

| Variable | Purpose |
|---|---|
| `HIBP_URL` | Base URL for HIBP range API |
| `HIBP_ALLOWED_DOMAIN` | Allowlisted domain for URL validation |
| `HIBP_TIMEOUT_SECONDS` | Socket timeout for HIBP requests |
| `STRONG_MIN_LENGTH` / `STRONG_MIN_SYMBOLS` / `STRONG_MIN_NUMBERS` | Thresholds for "Strong" rating |
| `MEDIUM_MIN_LENGTH` | Threshold for "Medium" rating |
| `MIN_PASSWORD_LENGTH` | Minimum total character count accepted |
| `GUESSES_PER_SECOND` | Assumed attacker speed for crack-time display |
| `AMBIGUOUS_CHARS` | Characters stripped when `--no-ambiguous` is set |
| `CLIPBOARD_CLEAR_SECONDS` | Auto-clear delay for clipboard |

## Running tests

```bash
python3 -m pytest tests/
```

## Security design notes

- **Why `secrets` over `random`** — `random` is seeded from predictable state and is not suitable for security-sensitive output. `secrets` pulls from `/dev/urandom` (or the OS equivalent) and is designed for cryptographic use.
- **Why k-anonymity** — the HIBP range API lets us check if a password has been breached without ever sending the full hash. We send only the first 5 hex chars of the SHA-1 hash; HIBP returns all hash suffixes matching that prefix, and we match locally.
- **Why rate limiting** — protects both the user's IP and the HIBP service from accidental request floods.
- **Why in-memory wiping** — Python doesn't guarantee prompt garbage collection, so we explicitly `del` the password and call `gc.collect()` to reduce the window during which the plaintext sits in memory.

## License

MIT — see [LICENSE](LICENSE).

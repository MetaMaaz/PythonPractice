import argparse
import secrets
import string
import hashlib
import math
import time
import urllib.request
import subprocess
import platform
import os
import gc
import threading
import logging
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    filename="password_generator.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def get_int_input(prompt):
    while True:
        print(prompt)
        value = input().strip()
        try:
            num = int(value)
            if num < 0:
                print("Please enter a non-negative number.")
                logger.warning("User entered negative number")
                continue
            return num
        except ValueError:
            print("Invalid input. Please enter a whole number.")
            logger.warning("User entered non-integer input")


def validate_hibp_url(url):
    allowed_domain = os.getenv("HIBP_ALLOWED_DOMAIN", "api.pwnedpasswords.com")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        logger.error("HIBP URL uses %s instead of https", parsed.scheme)
        return False
    if parsed.hostname != allowed_domain:
        logger.error("HIBP URL domain %s not in allowlist", parsed.hostname)
        return False
    return True


_last_hibp_call = 0.0


def check_hibp(password):
    global _last_hibp_call

    # Rate limit: minimum 1.5 seconds between API calls
    elapsed = time.time() - _last_hibp_call
    min_interval = 1.5
    if elapsed < min_interval:
        wait = min_interval - elapsed
        logger.info("Rate limiting: waiting %.1f seconds before HIBP call", wait)
        time.sleep(wait)

    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    base_url = os.getenv("HIBP_URL")
    url = f"{base_url}/{prefix}"

    if not validate_hibp_url(url):
        logger.error("HIBP URL validation failed, skipping breach check")
        return None

    timeout = int(os.getenv("HIBP_TIMEOUT_SECONDS", 5))
    try:
        _last_hibp_call = time.time()
        with urllib.request.urlopen(url, timeout=timeout) as response:
            hashes = response.read().decode()
        for line in hashes.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                logger.info("Password found in breaches")
                return int(count)
        logger.info("Password not found in any breaches")
        return 0
    except Exception as e:
        logger.error("HIBP API request failed: %s", e)
        return None


def clear_clipboard_after(seconds):
    def _clear():
        os_name = platform.system()
        try:
            if os_name == "Darwin":
                subprocess.run("pbcopy", input=b"", check=True)
            elif os_name == "Windows":
                subprocess.run("clip", input=b"", check=True)
            elif os_name == "Linux":
                subprocess.run(["xclip", "-selection", "clipboard"],
                               input=b"", check=True)
            logger.info("Clipboard cleared after %d seconds", seconds)
        except Exception as e:
            logger.error("Failed to clear clipboard: %s", e)

    timer = threading.Timer(seconds, _clear)
    timer.daemon = True
    timer.start()


def copy_to_clipboard(text):
    os_name = platform.system()
    clear_seconds = int(os.getenv("CLIPBOARD_CLEAR_SECONDS", 30))
    try:
        if os_name == "Darwin":
            subprocess.run("pbcopy", input=text.encode(), check=True)
        elif os_name == "Windows":
            subprocess.run("clip", input=text.encode(), check=True)
        elif os_name == "Linux":
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=text.encode(), check=True)
        else:
            print(f"Clipboard not supported on {os_name}")
            logger.warning("Unsupported OS for clipboard: %s", os_name)
            return
        print(f"Password copied to clipboard! (auto-clears in {clear_seconds}s)")
        logger.info("Password copied to clipboard on %s", os_name)
        clear_clipboard_after(clear_seconds)
    except Exception as e:
        print(f"Could not copy to clipboard on {os_name}")
        logger.error("Clipboard copy failed: %s", e)


def generate_password(nr_letters, nr_symbols, nr_numbers, exclude_ambiguous=False):
    letters = string.ascii_letters
    symbols = string.punctuation
    numbers = string.digits

    if exclude_ambiguous:
        ambiguous = os.getenv("AMBIGUOUS_CHARS", "0OolI1")
        letters = "".join(c for c in letters if c not in ambiguous)
        symbols = "".join(c for c in symbols if c not in ambiguous)
        numbers = "".join(c for c in numbers if c not in ambiguous)
        logger.info("Excluding ambiguous characters")

    password_list = []
    for pool, count in [(letters, nr_letters), (symbols, nr_symbols), (numbers, nr_numbers)]:
        password_list += [secrets.choice(pool) for _ in range(count)]

    # secrets module doesn't have shuffle, use SystemRandom (OS-level entropy)
    sysrand = secrets.SystemRandom()
    sysrand.shuffle(password_list)
    logger.info("Password generated successfully")
    return "".join(password_list)


def get_strength(nr_letters, nr_symbols, nr_numbers):
    strong_len = int(os.getenv("STRONG_MIN_LENGTH", 12))
    strong_sym = int(os.getenv("STRONG_MIN_SYMBOLS", 2))
    strong_num = int(os.getenv("STRONG_MIN_NUMBERS", 2))
    medium_len = int(os.getenv("MEDIUM_MIN_LENGTH", 8))

    length = nr_letters + nr_symbols + nr_numbers
    if length >= strong_len and nr_symbols >= strong_sym and nr_numbers >= strong_num:
        return "Strong"
    elif length >= medium_len and (nr_symbols >= 1 or nr_numbers >= 1):
        return "Medium"
    else:
        return "Weak"


def calculate_entropy(length, nr_letters, nr_symbols, nr_numbers, exclude_ambiguous=False):
    pool_size = 0
    ambiguous = os.getenv("AMBIGUOUS_CHARS", "0OolI1") if exclude_ambiguous else ""

    if nr_letters > 0:
        pool_size += len([c for c in string.ascii_letters if c not in ambiguous])
    if nr_symbols > 0:
        pool_size += len([c for c in string.punctuation if c not in ambiguous])
    if nr_numbers > 0:
        pool_size += len([c for c in string.digits if c not in ambiguous])

    if pool_size == 0 or length == 0:
        return 0.0
    return length * math.log2(pool_size)


def time_to_crack(entropy_bits):
    guesses_per_sec = int(os.getenv("GUESSES_PER_SECOND", 1_000_000_000))
    total_combinations = 2 ** entropy_bits
    seconds = total_combinations / guesses_per_sec

    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 31_536_000:
        return f"{seconds / 86400:.1f} days"
    elif seconds < 31_536_000 * 1000:
        return f"{seconds / 31_536_000:.1f} years"
    else:
        return f"{seconds / 31_536_000:,.0f} years"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Secure password generator with HIBP breach checking"
    )
    parser.add_argument("--letters", "-l", type=int, default=None, metavar="N",
                        help="number of letters (default: prompt)")
    parser.add_argument("--symbols", "-s", type=int, default=None, metavar="N",
                        help="number of symbols (default: prompt)")
    parser.add_argument("--numbers", "-n", type=int, default=None, metavar="N",
                        help="number of numbers (default: prompt)")
    parser.add_argument("--no-ambiguous", action="store_true",
                        help="exclude ambiguous characters (0, O, l, 1, I)")
    parser.add_argument("--no-breach-check", action="store_true",
                        help="skip HaveIBeenPwned breach check")
    parser.add_argument("--no-clipboard", action="store_true",
                        help="do not copy password to clipboard")
    parser.add_argument("--show", action="store_true",
                        help="print password to stdout")
    parser.add_argument("--count", "-c", type=int, default=1, metavar="N",
                        help="number of passwords to generate (default: 1)")
    return parser.parse_args()


def _process_one_password(args, nr_letters, nr_symbols, nr_numbers, total):
    password = generate_password(nr_letters, nr_symbols, nr_numbers, args.no_ambiguous)
    strength = get_strength(nr_letters, nr_symbols, nr_numbers)
    entropy = calculate_entropy(total, nr_letters, nr_symbols, nr_numbers, args.no_ambiguous)
    crack_time = time_to_crack(entropy)

    if args.show or args.count > 1:
        print(f"Password: {password}")
    print(f"Strength: {strength} | Entropy: {entropy:.1f} bits | Crack time: {crack_time}")
    logger.info("CLI: Strength=%s, Entropy=%.1f bits, Crack time=%s", strength, entropy, crack_time)

    if not args.no_breach_check:
        breach_count = check_hibp(password)
        if breach_count is None:
            print("Could not reach HaveIBeenPwned — skipping breach check.")
        elif breach_count > 0:
            print(f"Warning: appeared in {breach_count} data breaches.")
        else:
            print("Not found in any known breaches.")

    if not args.no_clipboard and args.count == 1:
        copy_to_clipboard(password)

    del password
    gc.collect()


def run_cli(args):
    min_length = int(os.getenv("MIN_PASSWORD_LENGTH", 4))
    nr_letters = args.letters or 0
    nr_symbols = args.symbols or 0
    nr_numbers = args.numbers or 0
    total = nr_letters + nr_symbols + nr_numbers

    if total == 0:
        print("Error: specify at least one of --letters, --symbols, --numbers.")
        return
    if total < min_length:
        print(f"Error: password must be at least {min_length} characters.")
        return

    for _ in range(args.count):
        _process_one_password(args, nr_letters, nr_symbols, nr_numbers, total)


if __name__ == "__main__":
    args = parse_args()
    cli_mode = any(x is not None for x in [args.letters, args.symbols, args.numbers])

    if cli_mode:
        run_cli(args)
    else:
        print("Welcome to the Password Generator!")

        min_length = int(os.getenv("MIN_PASSWORD_LENGTH", 4))

        while True:
            nr_letters = get_int_input("How many letters would you like in your password?")
            nr_symbols = get_int_input("How many symbols would you like?")
            nr_numbers = get_int_input("How many numbers would you like?")

            total = nr_letters + nr_symbols + nr_numbers
            if total == 0:
                print("Password must have at least 1 character. Try again.")
                logger.warning("User requested 0-length password")
                continue
            if total < min_length:
                print(f"Password must be at least {min_length} characters. Try again.")
                logger.warning("User requested password below minimum length")
                continue

            exclude_input = input("Exclude ambiguous characters (0, O, l, 1, I)? (yes/no): ").strip().lower()
            exclude_ambiguous = exclude_input == "yes"

            password = generate_password(nr_letters, nr_symbols, nr_numbers, exclude_ambiguous)
            strength = get_strength(nr_letters, nr_symbols, nr_numbers)
            length = nr_letters + nr_symbols + nr_numbers
            entropy = calculate_entropy(length, nr_letters, nr_symbols, nr_numbers, exclude_ambiguous)
            crack_time = time_to_crack(entropy)

            show_input = input("Show password on screen? (yes/no): ").strip().lower()
            if show_input == "yes":
                print(f"\nYour password is: {password}")
            else:
                print("\nPassword hidden — it will be copied to clipboard.")

            print(f"Password strength: {strength}")
            print(f"Entropy: {entropy:.1f} bits")
            print(f"Estimated time to crack: {crack_time}")
            logger.info("Strength=%s, Entropy=%.1f bits, Crack time=%s", strength, entropy, crack_time)

            breach_count = check_hibp(password)
            if breach_count is None:
                print("Could not reach HaveIBeenPwned — skipping breach check.")
                copy_to_clipboard(password)
            elif breach_count > 0:
                print(f"Warning: This password has appeared in {breach_count} data breaches.")
                answer = input("Do you still want to copy it to clipboard? (yes/no): ").strip().lower()
                if answer == "yes":
                    copy_to_clipboard(password)
            else:
                print("This password has not appeared in any known breaches.")
                copy_to_clipboard(password)

            del password
            gc.collect()

            again = input("\nGenerate another password? (yes/no): ").strip().lower()
            if again != "yes":
                print("Goodbye!")
                logger.info("User exited the program")
                break

import random
import string
import hashlib
import urllib.request
import subprocess
import platform


def check_hibp(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        with urllib.request.urlopen(url) as response:
            hashes = response.read().decode()
        for line in hashes.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0
    except Exception:
        return None


def copy_to_clipboard(text):
    os_name = platform.system()
    try:
        if os_name == "Darwin":
            subprocess.run("pbcopy", input=text.encode(), check=True)
        elif os_name == "Windows":
            subprocess.run("clip", input=text.encode(), check=True)
        elif os_name == "Linux":
            subprocess.run("xclip -selection clipboard", input=text.encode(), shell=True, check=True)
        else:
            print(f"Clipboard not supported on {os_name}")
            return
        print("Password copied to clipboard!")
    except Exception:
        print(f"Could not copy to clipboard on {os_name}")


print("Welcome to the Password Generator!")
print("How many letters would you like in your password?")
nr_letters = int(input())
print("How many symbols would you like?")
nr_symbols = int(input())
print("How many numbers would you like?")
nr_numbers = int(input())

letters = string.ascii_letters
symbols = string.punctuation
numbers = string.digits

password_list = []
for pool, count in [(letters, nr_letters), (symbols, nr_symbols), (numbers, nr_numbers)]:
    password_list += random.choices(pool, k=count)

random.shuffle(password_list)
password = "".join(password_list)

length = nr_letters + nr_symbols + nr_numbers
if length >= 12 and nr_symbols >= 2 and nr_numbers >= 2:
    strength = "Strong"
elif length >= 8 and (nr_symbols >= 1 or nr_numbers >= 1):
    strength = "Medium"
else:
    strength = "Weak"

print(f"\nYour password is: {password}")
print(f"Password strength: {strength}")

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

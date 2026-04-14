import random
import string

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
password_list += random.choices(letters, k=nr_letters)
password_list += random.choices(symbols, k=nr_symbols)
password_list += random.choices(numbers, k=nr_numbers)

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

import secrets
import math

print("Welcome to the entopy-bit password generator!\n")
NUM_VAL_OF_ENTROPY = int(input("What number of entropy bits would you like?: "))
exclude_ambiguous = input("Exclude ambiguous characters? This increases randomness. (y/n): ").lower() == 'y'

MIN_ENTROPY_BITS = NUM_VAL_OF_ENTROPY
MIN_LENGTH = 12
COMMON_PASSWORDS = {
    'password', '123456', '12345678', '123456789', 'qwerty',
    'abc123', 'letmein', 'admin', 'welcome', 'password1'
}

# Expanded character sets with ambiguous characters marked
ALL_LETTERS = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'q',
    'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z'
]
AMBIGUOUS_LETTERS = {'l', 'I', 'O', 'i', 'o'}

NUMBERS = ['2', '3', '4', '5', '6', '7', '8', '9']
AMBIGUOUS_NUMBERS = {'0', '1'}

SYMBOLS = ['!', '#', '$', '%', '&', '*', '+', '@', '^', '~', '-', '_', '=', '?', '.', ',', ';', ':', '<', '>']
AMBIGUOUS_SYMBOLS = {'(', ')', '{', '}', '[', ']', '/', '\\', '`', "'", '"'}


def get_entropy(nr_letters, nr_symbols, nr_numbers, letter_set, number_set, symbol_set):
    total_chars = nr_letters + nr_symbols + nr_numbers
    if total_chars == 0:
        return 0

    # Multinomial coefficient calculation using log gamma
    log_multinomial = (math.lgamma(total_chars + 1)
                       - math.lgamma(nr_letters + 1)
                       - math.lgamma(nr_symbols + 1)
                       - math.lgamma(nr_numbers + 1)) / math.log(2)

    # Individual character possibilities
    log_choices = (nr_letters * math.log2(len(letter_set))
                   + nr_symbols * math.log2(len(symbol_set))
                   + nr_numbers * math.log2(len(number_set)))

    return log_multinomial + log_choices


def is_insecure(password):
    # Check against common passwords
    if password.lower() in COMMON_PASSWORDS:
        return True

    # Check for sequential patterns
    sequential = any(
        ord(password[i + 1]) - ord(password[i]) == 1
        for i in range(len(password) - 1)
    )

    # Check for repeated characters
    repeats = any(
        password[i] == password[i + 1] == password[i + 2]
        for i in range(len(password) - 2)
    )

    return sequential or repeats

letters = ALL_LETTERS if exclude_ambiguous else ALL_LETTERS + list(AMBIGUOUS_LETTERS)
numbers = NUMBERS if exclude_ambiguous else NUMBERS + list(AMBIGUOUS_NUMBERS)
symbols = SYMBOLS if exclude_ambiguous else SYMBOLS + list(AMBIGUOUS_SYMBOLS)

while True:
    try:
        nr_letters = int(input("How many letters? (min 4): "))
        nr_symbols = int(input("How many symbols? (min 2): "))
        nr_numbers = int(input("How many numbers? (min 2): "))

        if nr_letters < 4 or nr_symbols < 2 or nr_numbers < 2:
            print("Minimum requirements not met. Please try again.")
            continue

        total = nr_letters + nr_symbols + nr_numbers
        if total < MIN_LENGTH:
            print(f"Minimum total length is {MIN_LENGTH}. Please try again.")
            continue

        break
    except ValueError:
        print("Please enter valid numbers.")

attempts = 0
while True:
    password_chars = (
            [secrets.choice(letters) for _ in range(nr_letters)]
            + [secrets.choice(symbols) for _ in range(nr_symbols)]
            + [secrets.choice(numbers) for _ in range(nr_numbers)]
    )
    secrets.SystemRandom().shuffle(password_chars)
    password = ''.join(password_chars)

    # Calculate entropy
    entropy = get_entropy(nr_letters, nr_symbols, nr_numbers, letters, numbers, symbols)

    if (entropy >= MIN_ENTROPY_BITS
            and not is_insecure(password)
            and not any(word in password.lower() for word in COMMON_PASSWORDS)):
        break

    attempts += 1
    if attempts > 100:
        print("Warning: Having difficulty generating a secure password!")
        print("Consider increasing length or character diversity.")
        break

print(f"\nGenerated Password: {password}")
print(f"Security Analysis:")
print(f"- Entropy: {entropy:.1f} bits ({'Secure' if entropy >= MIN_ENTROPY_BITS else 'Weak'})")
print(f"- Length: {len(password)} characters")
print(f"- Character types: {nr_letters} letters, {nr_symbols} symbols, {nr_numbers} numbers")

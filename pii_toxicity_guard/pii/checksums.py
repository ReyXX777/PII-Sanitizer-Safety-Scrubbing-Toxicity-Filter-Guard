"""Checksum helpers used to reduce structured-identifier false positives."""
import re


def digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn_valid(value: str) -> bool:
    """Return whether a digit sequence passes the Luhn checksum.

    This is a format plausibility check, not proof that a card is real or active.
    """
    digits = digits_only(value)
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0

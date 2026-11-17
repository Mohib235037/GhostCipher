from __future__ import annotations
import math
from collections import Counter
from .common import english_score

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MORSE = dict(
    zip(
        ALPHABET + "0123456789",
        ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --.. ----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----.".split(),
    )
)


def caesar(text, shift, alphabet=ALPHABET):
    if not alphabet.isascii():
        raise ValueError("Alphabet must contain distinct ASCII letters.")
    alphabet = alphabet.upper()
    if (
        len(alphabet) < 2
        or len(set(alphabet)) != len(alphabet)
        or not alphabet.isalpha()
    ):
        raise ValueError("Alphabet must contain distinct ASCII letters.")

    def transform(c):
        if not c.isascii() or c.upper() not in alphabet:
            return c
        out = alphabet[(alphabet.index(c.upper()) + shift) % len(alphabet)]
        return out.lower() if c.islower() else out

    return "".join(map(transform, text))


def atbash(text):
    return "".join(
        (
            chr((155 if c.isupper() else 219) - ord(c))
            if c.isascii() and c.isalpha()
            else c
        )
        for c in text
    )


def vigenere(text, key, decrypt=True):
    if not key or not key.isascii() or not key.isalpha():
        raise ValueError("Vigenère key must contain ASCII letters only.")
    out, j = [], 0
    for c in text:
        if c.isascii() and c.isalpha():
            shift = ord(key[j % len(key)].upper()) - 65
            out.append(caesar(c, -shift if decrypt else shift))
            j += 1
        else:
            out.append(c)
    return "".join(out)


def affine(text, a, b, decrypt=True):
    if math.gcd(a, 26) != 1:
        raise ValueError(
            "Affine a must be coprime to 26: 1,3,5,7,9,11,15,17,19,21,23,25."
        )
    out = []
    for c in text:
        if c.isascii() and c.isalpha():
            x = ord(c.upper()) - 65
            y = pow(a, -1, 26) * (x - b) % 26 if decrypt else (a * x + b) % 26
            out.append(chr(y + (65 if c.isupper() else 97)))
        else:
            out.append(c)
    return "".join(out)


def rail(text, rails, decrypt=True):
    if not 2 <= rails <= 50:
        raise ValueError("Rail count must be between 2 and 50.")
    path = [
        min(i % (2 * rails - 2), 2 * rails - 2 - i % (2 * rails - 2))
        for i in range(len(text))
    ]
    if not decrypt:
        return "".join(
            text[i] for r in range(rails) for i, p in enumerate(path) if p == r
        )
    slots, pos = {}, 0
    for r in range(rails):
        for i, p in enumerate(path):
            if p == r:
                slots[i], pos = text[pos], pos + 1
    return "".join(slots[i] for i in range(len(text)))


def morse(text, encode=False):
    if encode:
        return " / ".join(
            " ".join(MORSE[c] for c in word.upper()) for word in text.split()
        )
    reverse = {v: k for k, v in MORSE.items()}
    return " ".join(
        "".join(reverse[token] for token in word.split())
        for word in text.strip().split("/")
    )


def bacon(text, encode=False):
    if encode:
        if any(c.upper() not in ALPHABET for c in text if not c.isspace()):
            raise ValueError(
                "Bacon encoding accepts letters and spaces only (26-letter variant)."
            )
        return " ".join(
            format(ALPHABET.index(c.upper()), "05b").translate(
                str.maketrans("01", "AB")
            )
            for c in text
            if not c.isspace()
        )
    compact = "".join(text.split()).upper()
    if not compact or set(compact) - set("AB") or len(compact) % 5:
        raise ValueError("Bacon data needs A/B groups of five.")
    values = [
        int(compact[i : i + 5].translate(str.maketrans("AB", "01")), 2)
        for i in range(0, len(compact), 5)
    ]
    if max(values) > 25:
        raise ValueError("Invalid 26-letter Bacon group.")
    return "".join(ALPHABET[i] for i in values)


def frequency(text):
    letters = [c.upper() for c in text if c.isascii() and c.isalpha()]
    n = len(letters)
    counts = Counter(letters)
    ic = sum(x * (x - 1) for x in counts.values()) / (n * (n - 1)) if n > 1 else 0
    return {
        "letters": n,
        "index_of_coincidence": round(ic, 5),
        "frequencies": dict(counts.most_common()),
        "note": "English often has IC near 0.067; short samples are unreliable. Frequency is a clue, not a solved substitution.",
    }


ENGLISH = [
    0.082,
    0.015,
    0.028,
    0.043,
    0.127,
    0.022,
    0.020,
    0.061,
    0.070,
    0.0015,
    0.0077,
    0.040,
    0.024,
    0.067,
    0.075,
    0.019,
    0.00095,
    0.060,
    0.063,
    0.091,
    0.028,
    0.0098,
    0.024,
    0.0015,
    0.020,
    0.00074,
]


def recover_vigenere(text, budget, max_key=16):
    letters = "".join(c.upper() for c in text if c.isascii() and c.isalpha())[:20000]
    if len(letters) < 20:
        raise ValueError("Use at least 20 letters; 100 or more usually works better.")
    results = []
    for length in range(1, min(max_key, len(letters) // 5) + 1):
        budget.check()
        key = ""
        for col in range(length):
            group = letters[col::length]

            def chi(shift):
                counts = Counter(caesar(group, -shift))
                return sum(
                    (counts[c] - len(group) * p) ** 2 / (len(group) * p)
                    for c, p in zip(ALPHABET, ENGLISH)
                )

            key += ALPHABET[min(range(26), key=chi)]
        plain = vigenere(text, key)
        results.append(
            {
                "key": key,
                "length": length,
                "score": round(english_score(plain.encode()), 3),
                "plaintext": plain,
            }
        )
    return sorted(results, key=lambda x: x["score"], reverse=True)

import hashlib
import hmac
import re
from Crypto.Hash import MD4

ALGORITHMS = [
    "MD5",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "NTLM",
]


def identify(text):
    text = text.strip()
    out = []
    if re.fullmatch(r"[0-9a-fA-F]+", text):
        choices = {
            32: ["MD5", "NTLM / MD4"],
            40: ["SHA-1"],
            56: ["SHA-224", "SHA3-224"],
            64: ["SHA-256", "SHA3-256"],
            96: ["SHA-384", "SHA3-384"],
            128: ["SHA-512", "SHA3-512"],
        }.get(len(text), [])
        out = [
            {
                "format": s,
                "confidence": "Possible",
                "reason": f"{len(text)} hexadecimal characters; length alone cannot identify a hash.",
            }
            for s in choices
        ]
    if re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", text):
        out.append(
            {
                "format": "bcrypt",
                "confidence": "Strong format match",
                "reason": "Recognized bcrypt modular-crypt structure; not decrypted.",
            }
        )
    if text.startswith(("pbkdf2_sha256$", "pbkdf2_sha1$", "$pbkdf2-")):
        out.append(
            {
                "format": "PBKDF2",
                "confidence": "Possible",
                "reason": "Recognized prefix; iterations, salt and digest must be parsed for the particular implementation.",
            }
        )
    if text.startswith(("$argon2id$", "$argon2i$", "$scrypt$", "$6$", "$5$")):
        out.append(
            {
                "format": "Password hash container",
                "confidence": "Possible",
                "reason": "Recognized prefix; this tool identifies the container only.",
            }
        )
    return out


def digest(text, algorithm):
    if algorithm == "NTLM":
        return MD4.new(text.encode("utf-16le")).hexdigest()
    name = algorithm.lower().replace("-", "")
    if algorithm.startswith("SHA3-"):
        name = algorithm.lower().replace("-", "_")
    if algorithm not in ALGORITHMS:
        raise ValueError("Unsupported hash algorithm.")
    return hashlib.new(name, text.encode("utf-8")).hexdigest()


def compare(text, target, algorithm):
    expected = digest(text, algorithm)
    target = target.strip().lower()
    if len(target) != len(expected) or not re.fullmatch(r"[0-9a-f]+", target):
        raise ValueError(
            f"{algorithm} needs a {len(expected)}-digit hexadecimal digest."
        )
    return hmac.compare_digest(expected, target)


def dictionary_check(target, algorithm, words, budget):
    if len(words) > 10000:
        raise ValueError("Wordlist limit: 10,000 entries.")
    tested = 0
    for word in words:
        budget.check()
        if len(word.encode("utf-8")) > 1024:
            raise ValueError("Wordlist entry exceeds 1024 bytes.")
        tested += 1
        if compare(word, target, algorithm):
            return {
                "matched": True,
                "candidate": word,
                "tested": tested,
                "note": "Exact digest match; this was a local dictionary comparison.",
            }
    return {
        "matched": False,
        "tested": tested,
        "note": "No matching candidate in the supplied list. Hashes are not decrypted.",
    }

from __future__ import annotations
import json
import math
from . import classical, encodings, hashes
from .common import Budget, Limits, entropy, integer, parse_bytes, report, view
from .crypto import extended_gcd, factor_small, inspect_key, rsa_solve, symmetric
from .engine import analyze
from .files import analyze_file
from .xor import xor, single_byte, key_lengths, repeating_candidates


def json_object(text):
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError('Enter a JSON object, for example {"a":17,"m":3120}.')
    return value


def execute(kind, values, limits=None, cancel=None, progress=None):
    limits = (limits or Limits()).validate()
    budget = Budget(limits, cancel)
    # Bound all fields before parsing JSON or invoking any library.
    fields = {
        k: v
        for k, v in values.items()
        if k
        not in (
            "operation",
            "encoding",
            "method",
            "algorithm",
            "mode",
            "padding",
            "key_encoding",
            "name",
        )
    }
    if (kind == "xor" and values.get("encoding") == "Raw file") or (
        kind == "rsa" and values.get("raw_bytes") is not None
    ):
        fields.pop(
            "text", None
        )  # A raw-file preview is not a second copy of the input.
    size = sum(
        (
            len(v.encode("utf-8"))
            if isinstance(v, str)
            else len(v) if isinstance(v, bytes) else 0
        )
        for v in fields.values()
    )
    if size > limits.input_bytes:
        raise ValueError("Combined input fields exceed the configured byte limit.")
    budget.check()
    text = values.get("text", "")
    op = values.get("operation", "")
    if kind == "auto":
        return analyze(values["data"], limits, cancel, progress)
    if kind == "file":
        return analyze_file(values["data"], budget, values.get("name", "input"))
    if kind == "encoding":
        name = values["method"]
        if op == "Decode":
            result = encodings.decode(name, text)
        else:
            result = encodings.encode(
                name, parse_bytes(text, values["encoding"])
            ).encode()
        return report(
            name + " " + op.lower(),
            result,
            [op + " using " + name],
            "This is a reversible representation or simple transformation. A successful operation is not evidence that secure encryption was broken.",
        )
    if kind == "classical":
        key = values.get("key", "")
        alphabet = values.get("alphabet", classical.ALPHABET)
        if op == "Caesar brute force":
            from .common import english_score

            out = []
            for s in range(len(alphabet)):
                budget.check()
                plain = classical.caesar(text, -s, alphabet)
                out.append(
                    {
                        "shift": -s,
                        "plaintext": plain,
                        "score": round(english_score(plain.encode()), 3),
                    }
                )
            return report(
                op,
                json.dumps(
                    sorted(out, key=lambda x: x["score"], reverse=True), indent=2
                ),
                [
                    "Try each shift.",
                    "Rank by English readability; short samples are ambiguous.",
                ],
                "Scores are heuristics, not probabilities.",
            )
        if op.startswith("Caesar"):
            result = classical.caesar(text, integer(values.get("shift", "3")), alphabet)
        elif op == "ROT13":
            result = classical.caesar(text, 13)
        elif op == "Atbash":
            result = classical.atbash(text)
        elif op.startswith("Vigenère"):
            if op == "Vigenère recover":
                return report(
                    op,
                    json.dumps(classical.recover_vigenere(text, budget), indent=2),
                    [
                        "Try key lengths 1–16.",
                        "Score each column with English letter frequencies.",
                        "Rank candidate messages.",
                    ],
                    "Heuristic recovery can fail on short, non-English, compressed or unusual messages.",
                )
            result = classical.vigenere(text, key, op.endswith("decrypt"))
        elif op.startswith("Affine"):
            if op == "Affine brute force":
                from .common import english_score

                out = []
                for a in range(26):
                    if math.gcd(a, 26) != 1:
                        continue
                    for b in range(26):
                        budget.check()
                        plain = classical.affine(text, a, b)
                        out.append(
                            {
                                "a": a,
                                "b": b,
                                "plaintext": plain,
                                "score": round(english_score(plain.encode()), 3),
                            }
                        )
                return report(
                    op,
                    json.dumps(
                        sorted(out, key=lambda x: x["score"], reverse=True)[:30],
                        indent=2,
                    ),
                    [
                        "Try 312 valid (a,b) keys.",
                        "Show the 30 highest readability scores.",
                    ],
                    "Readability is not proof of the correct key.",
                )
            result = classical.affine(
                text, integer(values["a"]), integer(values["b"]), op.endswith("decrypt")
            )
        elif op.startswith("Rail Fence"):
            result = classical.rail(
                text, integer(values["rails"]), op.endswith("decrypt")
            )
        elif op.startswith("Morse"):
            result = classical.morse(text, op.endswith("encode"))
        elif op.startswith("Bacon"):
            result = classical.bacon(text, op.endswith("encode"))
        elif op == "Frequency analysis":
            return report(
                op,
                json.dumps(classical.frequency(text), indent=2),
                ["Count ASCII letters and compute index of coincidence."],
                "This describes patterns; it does not automatically solve a general substitution cipher.",
            )
        elif op == "Reverse":
            result = text[::-1]
        else:
            raise ValueError("Choose a supported classical operation.")
        return report(
            op,
            result,
            [op + " with supplied parameters."],
            "Check spaces, alphabet and key conventions against your challenge.",
        )
    if kind == "xor":
        data = (
            values.get("raw_bytes")
            if values["encoding"] == "Raw file"
            else parse_bytes(text, values["encoding"])
        )
        if data is None:
            raise ValueError("Open a raw input file first.")
        if op == "Known key":
            key = parse_bytes(values["key"], values["key_encoding"])
            result = xor(data, key)
            return report(
                "XOR with supplied key",
                result,
                ["Repeat key bytes to match input length.", "XOR matching bytes."],
                "XOR reverses itself with the same key.",
                key_hex=key.hex(),
            )
        if len(data) > 32768:
            raise ValueError(
                "XOR recovery is limited to 32 KiB. Known-key XOR supports the configured input limit."
            )
        if op == "Single-byte brute force":
            out = [
                {"key_hex": f"{k:02x}", "score": round(s, 3), "plaintext": view(p)}
                for s, k, p in single_byte(data, budget, 20)
            ]
        elif op == "Repeating-key recovery":
            out = repeating_candidates(data, budget)
        elif op == "Key-length estimates":
            out = [
                {"length": s, "normalized_distance": round(d, 3)}
                for d, s in key_lengths(data)
            ]
        elif op == "Known-plaintext hint":
            hint = parse_bytes(values["hint"], "UTF-8")
            offset = integer(values["offset"])
            if not hint or offset < 0 or offset + len(hint) > len(data):
                raise ValueError("Hint and offset must fit inside the input.")
            segment = bytes(
                a ^ b for a, b in zip(data[offset : offset + len(hint)], hint)
            )
            return report(
                "Possible key segment",
                segment,
                ["ciphertext segment XOR known plaintext = key segment."],
                "This reveals only a key segment at the chosen offset, not necessarily the entire repeating key.",
                key_segment_hex=segment.hex(),
            )
        else:
            raise ValueError("Choose an XOR operation.")
        return report(
            op,
            json.dumps(out, indent=2),
            [
                "Use byte frequencies or normalized Hamming distance.",
                "Inspect multiple candidates.",
            ],
            "These estimates assume natural-language plaintext. A random one-time pad is not recoverable by this method.",
        )
    if kind == "hash":
        algorithm = values["algorithm"]
        target = values["target"]
        if op == "Identify":
            return report(
                "Possible hash formats",
                json.dumps(hashes.identify(text), indent=2),
                ["Compare lengths and recognized prefixes."],
                "A matching length does not identify a unique hash. Hashes are not decrypted.",
            )
        if op == "Generate":
            return report(
                algorithm + " digest",
                hashes.digest(text, algorithm),
                ["Hash the exact UTF-8 input, including whitespace."],
                "NTLM uses UTF-16LE; other listed algorithms use UTF-8.",
            )
        if op == "Compare":
            return report(
                "Candidate comparison",
                "MATCH" if hashes.compare(text, target, algorithm) else "NO MATCH",
                ["Hash candidate and compare the complete digest."],
                "Exact comparison with the supplied algorithm.",
            )
        if op == "Local dictionary check":
            if not values.get("wordlist_supplied"):
                raise ValueError(
                    "Use Open wordlist to explicitly supply a local UTF-8 wordlist (max 10,000 lines)."
                )
            return report(
                "Local dictionary comparison",
                json.dumps(
                    hashes.dictionary_check(
                        target, algorithm, values["wordlist"].splitlines(), budget
                    ),
                    indent=2,
                ),
                ["Test only entries in the explicitly supplied wordlist."],
                "No generated guesses, remote service or unbounded cracking.",
            )
    if kind == "rsa":
        if op == "Inspect PEM / DER":
            return report(
                "Key inspection",
                json.dumps(
                    inspect_key(values.get("raw_bytes") or text.encode()), indent=2
                ),
                ["Parse supported unencrypted RSA/ECC key material."],
                "Container inspection does not recover unknown private keys.",
            )
        return rsa_solve(op, json_object(text), budget)
    if kind == "symmetric":
        return symmetric(
            values["algorithm"],
            values["mode"],
            op,
            parse_bytes(text, values["encoding"]),
            parse_bytes(values["key"], values["key_encoding"]),
            parse_bytes(values["iv"], "Hex"),
            parse_bytes(values["tag"], "Hex"),
            parse_bytes(values["aad"], "UTF-8"),
            values["padding"],
        )
    if kind == "advanced":
        if op == "Entropy":
            return report(
                "Byte entropy",
                f'{entropy(parse_bytes(text,values["encoding"])):.6f} bits per byte',
                ["Count byte probabilities, then compute −Σ p log₂(p)."],
                "High entropy may be compressed or encrypted data. It does not identify a cipher.",
            )
        if op == "Frequency":
            return report(
                "Frequency analysis",
                json.dumps(classical.frequency(text), indent=2),
                ["Count letters."],
                "Descriptive analysis only.",
            )
        params = json_object(text)

        def num(key):
            n = integer(params[key])
            if abs(n).bit_length() > 4096:
                raise ValueError("Math integer limit: 4096 bits.")
            return n

        if op == "GCD":
            result = math.gcd(num("a"), num("b"))
        elif op == "Extended GCD":
            g, x, y = extended_gcd(num("a"), num("b"))
            result = {"gcd": g, "x": x, "y": y, "identity": "a*x + b*y = gcd"}
        elif op == "Modular inverse":
            m = num("m")
            if m <= 1:
                raise ValueError("Modulus must be greater than one.")
            result = pow(num("a"), -1, m)
        elif op == "Modular power":
            m = num("m")
            if m <= 1:
                raise ValueError("Modulus must be greater than one.")
            result = pow(num("a"), num("e"), m)
        elif op == "CRT":
            from sympy.ntheory.modular import crt

            moduli = [integer(x) for x in params["moduli"]]
            rem = [integer(x) for x in params["remainders"]]
            if (
                not 1 <= len(moduli) <= 32
                or len(moduli) != len(rem)
                or any(m <= 1 or m.bit_length() > 512 for m in moduli)
                or any(abs(r).bit_length() > 4096 for r in rem)
            ):
                raise ValueError(
                    "Use matching lists of 1–32 positive moduli >1, up to 512 bits each."
                )
            if any(
                math.gcd(a, b) != 1
                for i, a in enumerate(moduli)
                for b in moduli[i + 1 :]
            ):
                raise ValueError("This CRT helper requires pairwise coprime moduli.")
            value, mod = crt(moduli, rem)
            result = {"solution": str(value), "modulus": str(mod)}
        elif op == "Prime test":
            from sympy import isprime

            n = num("n")
            result = {
                "prime_test_result": bool(isprime(n)),
                "note": "Deterministic for n < 2^64; SymPy probable-prime testing for larger n.",
            }
        elif op == "Factor small integer":
            result = factor_small(num("n"), budget)
        elif op in ("LCG generate", "LCG recover"):
            m = num("m")
            if m <= 1:
                raise ValueError("LCG modulus must be greater than one.")
            if op == "LCG recover":
                outputs = [integer(x) for x in params["outputs"]]
                if not 3 <= len(outputs) <= 1000 or any(
                    not 0 <= x < m for x in outputs
                ):
                    raise ValueError("Supply 3–1000 consecutive outputs in [0,m).")
                a = (
                    (outputs[2] - outputs[1]) * pow(outputs[1] - outputs[0], -1, m)
                ) % m
                b = (outputs[1] - a * outputs[0]) % m
                result = {
                    "a": str(a),
                    "b": str(b),
                    "verified": all(
                        (a * x + b) % m == y for x, y in zip(outputs, outputs[1:])
                    ),
                }
            else:
                a, b, seed, count = num("a"), num("b"), num("seed"), num("count")
                if not 1 <= count <= 1000:
                    raise ValueError("LCG count must be 1–1000.")
                result = []
                for _ in range(count):
                    budget.check()
                    seed = (a * seed + b) % m
                    result.append(seed)
        else:
            raise ValueError("Choose a supported math operation.")
        return report(
            op,
            json.dumps(result, indent=2),
            ["Parse exact integers (decimal or 0x-prefixed hex).", "Apply " + op + "."],
            "A mathematical result is not proof that an unrelated ciphertext can be decrypted.",
        )
    raise ValueError("Choose a supported operation.")

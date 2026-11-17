from __future__ import annotations
import math
from Crypto.Cipher import AES, DES, DES3
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from .common import integer, report


def extended_gcd(a, b):
    old_r, r, old_s, s, old_t, t = a, b, 1, 0, 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    if old_r < 0:
        return -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def factor_small(n, budget):
    from sympy import isprime

    if not 2 <= n < 2**48:
        raise ValueError(
            "Educational factorization is restricted to integers below 2^48. Supply known p and q for larger RSA."
        )
    remainder = n
    factors = {}
    divisor = 2
    while divisor * divisor <= remainder and divisor <= 1_000_000:
        if divisor % 257 == 0 or divisor == 2:
            budget.check()
        while remainder % divisor == 0:
            factors[divisor] = factors.get(divisor, 0) + 1
            remainder //= divisor
        divisor = 3 if divisor == 2 else divisor + 2
    budget.check()
    if remainder > 1:
        if isprime(remainder):
            factors[remainder] = factors.get(remainder, 0) + 1
        else:
            return {
                "factors": factors,
                "unfactored": remainder,
                "complete": False,
                "note": "Trial-division cap reached. No claim of complete factorization.",
            }
    return {
        "factors": factors,
        "unfactored": 1,
        "complete": True,
        "note": "Trial division with a one-million divisor cap.",
    }


def inspect_key(data):
    if len(data) > 65536:
        raise ValueError("Key inspection limit is 64 KiB.")
    try:
        key = RSA.import_key(data)
        return {
            "type": (
                "RSA private key"
                if key.has_private()
                else "RSA public key / certificate"
            ),
            "bits": key.size_in_bits(),
            "n": str(key.n),
            "e": str(key.e),
            "note": "Parsed key material. No encryption was broken; OAEP/PKCS#1 padded messages need their exact scheme.",
        }
    except (ValueError, IndexError, TypeError):
        try:
            key = ECC.import_key(data)
            return {
                "type": "ECC key",
                "curve": key.curve,
                "private": key.has_private(),
                "note": "Identification only; discrete logarithms are not solved.",
            }
        except (ValueError, IndexError, TypeError):
            raise ValueError(
                "Could not parse an unencrypted supported RSA/ECC key or RSA certificate. Encrypted keys need a password; arbitrary certificates may only be recognized by signature."
            )


def rsa_solve(operation, params, budget):
    from sympy import integer_nthroot, isprime

    if not isinstance(params, dict):
        raise ValueError("RSA parameters must be a JSON object.")
    p = {
        k: integer(v)
        for k, v in params.items()
        if k in ("n", "e", "c", "p", "q", "d", "phi", "m", "e1", "e2", "c1", "c2")
        and str(v).strip()
    }
    if any(abs(v).bit_length() > 8192 for v in p.values()):
        raise ValueError("RSA integer limit: 8192 bits.")
    steps = []
    if operation == "Common modulus":
        n, e1, e2, c1, c2 = (p[k] for k in ("n", "e1", "e2", "c1", "c2"))
        if n < 3 or min(e1, e2) < 1 or not (0 <= c1 < n and 0 <= c2 < n):
            raise ValueError("Invalid common-modulus parameters.")
        g, a, b = extended_gcd(e1, e2)
        if g != 1:
            raise ValueError("This common-modulus helper needs coprime e1 and e2.")
        m = (pow(c1, a, n) * pow(c2, b, n)) % n
        steps = [
            f"{a}×e1 + {b}×e2 = 1",
            "Compute c1^a × c2^b mod n; negative powers use modular inverses.",
        ]
        return report(
            "Common modulus candidate",
            m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big"),
            steps,
            "Works only when both ciphertexts encrypt exactly the same unpadded message with the same modulus.",
            integer=str(m),
        )
    if operation == "Small exponent":
        c, e = p["c"], p["e"]
        if c < 0 or not 2 <= e <= 17:
            raise ValueError("Use nonnegative c and e between 2 and 17.")
        m, exact = integer_nthroot(c, e)
        if not exact:
            raise ValueError(
                "c is not an exact integer e-th power. The no-modular-wrap condition is not satisfied."
            )
        if "n" in p and (p["n"] <= c):
            raise ValueError("This helper requires c < n (no modular wrap).")
        return report(
            "Exact small-exponent candidate",
            int(m).to_bytes(max(1, (int(m).bit_length() + 7) // 8), "big"),
            [f"Compute exact integer {e}-th root of c.", f"Check m^{e} = c exactly."],
            "This is an unpadded, no-wrap exercise, not a general RSA attack.",
            integer=str(m),
        )
    if "p" in p and "q" in p:
        a, b = p["p"], p["q"]
        if a == b or a < 2 or b < 2 or not (isprime(a) and isprime(b)):
            raise ValueError("p and q must be distinct primes.")
        n = a * b
        if "n" in p and p["n"] != n:
            raise ValueError("Provided n does not equal p × q.")
        p["n"] = n
        p["phi"] = (a - 1) * (b - 1)
        steps += ["n = p × q", "phi = (p − 1) × (q − 1) for distinct primes."]
    n = p.get("n", 0)
    if n < 3:
        raise ValueError("Supply n, or both p and q.")
    if operation == "Factor / derive private key":
        if "phi" not in p:
            fac = factor_small(n, budget)
            if (
                not fac["complete"]
                or len(fac["factors"]) != 2
                or any(v != 1 for v in fac["factors"].values())
            ):
                return {
                    "title": "RSA factorization",
                    "output": str(fac),
                    "steps": steps,
                    "explanation": "This helper expects a modulus with two distinct prime factors.",
                    "flags": [],
                }
            a, b = fac["factors"]
            p["phi"] = (a - 1) * (b - 1)
            steps += [f"p = {a}; q = {b}", "phi = (p − 1) × (q − 1)"]
        if p["phi"] <= 1 or "e" not in p or p["e"] < 2:
            raise ValueError("Supply e >= 2 and a valid phi or known factors.")
        d = pow(p["e"], -1, p["phi"])
        steps.append("d = inverse(e, phi); this requires gcd(e, phi) = 1.")
        return report(
            "Educational RSA private exponent",
            f'n = {n}\nphi = {p["phi"]}\nd = {d}',
            steps,
            "If phi was entered directly, its correctness depends on your supplied information.",
        )
    if operation == "Encrypt":
        m, e = p["m"], p["e"]
        if not 0 <= m < n or e < 2:
            raise ValueError("Require 0 <= m < n and e >= 2.")
        return report(
            "Raw RSA ciphertext integer",
            str(pow(m, e, n)),
            steps + ["c = m^e mod n"],
            "Textbook RSA has no secure padding. Use this only for CTF exercises.",
        )
    if operation == "Decrypt":
        if "d" not in p:
            if "phi" not in p or "e" not in p or p["phi"] <= 1 or p["e"] < 2:
                raise ValueError(
                    "Supply d, or e and phi, or e with p and q. General RSA cannot be broken from n,e,c alone."
                )
            p["d"] = pow(p["e"], -1, p["phi"])
            steps.append("d = inverse(e, phi)")
        if not 0 <= p["c"] < n or p["d"] < 1:
            raise ValueError("Require 0 <= c < n and d > 0.")
        budget.check()
        m = pow(p["c"], p["d"], n)
        return report(
            "Raw RSA decryption candidate",
            m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big"),
            steps + ["m = c^d mod n", "Convert the integer to big-endian bytes."],
            "Raw RSA only. Padding is not removed. A wrong key can produce meaningless bytes.",
            integer=str(m),
        )
    raise ValueError("Unsupported RSA operation.")


def symmetric(
    algorithm, mode, operation, data, key, iv=b"", tag=b"", aad=b"", padding="PKCS7"
):
    if operation not in ("Encrypt", "Decrypt"):
        raise ValueError("Choose Encrypt or Decrypt.")
    if mode not in ("ECB", "CBC", "CTR", "GCM"):
        raise ValueError("Choose ECB, CBC, CTR, or GCM.")
    if padding not in ("None", "PKCS7"):
        raise ValueError("Choose None or PKCS7 padding.")
    module = {"AES": AES, "DES": DES, "3DES": DES3}[algorithm]
    if algorithm == "AES" and len(key) not in (16, 24, 32):
        raise ValueError("AES key needs 16, 24 or 32 bytes.")
    if algorithm == "DES" and len(key) != 8:
        raise ValueError("DES key needs 8 bytes.")
    if algorithm == "3DES" and len(key) not in (16, 24):
        raise ValueError("3DES key needs 16 or 24 bytes and cannot degenerate to DES.")
    if mode == "GCM" and algorithm != "AES":
        raise ValueError("GCM is available for AES only.")
    options = {}
    if mode == "CBC":
        if len(iv) != module.block_size:
            raise ValueError(f"CBC IV needs {module.block_size} bytes.")
        options["iv"] = iv
    if mode in ("CTR", "GCM"):
        if not iv:
            raise ValueError("Supply a nonce in the IV / nonce field.")
        if mode == "CTR" and len(iv) >= module.block_size:
            raise ValueError(
                "CTR nonce must be shorter than the block size; counter starts at zero."
            )
        options["nonce"] = iv
    cipher = module.new(key, getattr(module, "MODE_" + mode), **options)
    encrypt = operation == "Encrypt"
    if mode == "GCM":
        cipher.update(aad)
        if encrypt:
            result, tag = cipher.encrypt_and_digest(data)
        else:
            if len(tag) != 16:
                raise ValueError("This tool expects a 16-byte GCM authentication tag.")
            result = cipher.decrypt_and_verify(data, tag)
    else:
        if mode in ("CBC", "ECB"):
            if encrypt and padding == "PKCS7":
                data = pad(data, module.block_size)
            if len(data) % module.block_size:
                raise ValueError(
                    "Data must be block-aligned, or use PKCS7 padding on encryption."
                )
        result = cipher.encrypt(data) if encrypt else cipher.decrypt(data)
        if not encrypt and mode in ("CBC", "ECB") and padding == "PKCS7":
            result = unpad(result, module.block_size)
    explanation = (
        "GCM authentication verified before plaintext was returned."
        if mode == "GCM" and not encrypt
        else (
            "Encryption completed. Never reuse a CTR/GCM nonce with the same key."
            if encrypt
            else "Unauthenticated mode: readable output or valid padding does not prove integrity or the correct key."
        )
    )
    if algorithm != "AES":
        explanation += (
            " DES and 3DES are legacy algorithms, unsuitable for new security designs."
        )
    return report(
        f"{algorithm}-{mode} {operation.lower()}",
        result,
        [
            f"Use supplied {len(key)*8}-bit key and {mode} parameters.",
            (
                ("Generate GCM tag." if encrypt else "Verify GCM tag.")
                if mode == "GCM"
                else f'Padding: {padding if mode in ("ECB","CBC") else "not used"}.'
            ),
        ],
        explanation,
        ciphertext_hex=result.hex() if encrypt else "",
        tag_hex=tag.hex() if mode == "GCM" else "",
        authenticated=mode == "GCM" and not encrypt,
    )

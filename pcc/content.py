"""Original offline lessons and deterministic practice exercises."""

from __future__ import annotations
import base64
import hashlib
from . import encodings
from .classical import caesar, atbash, vigenere, affine, rail, morse, bacon
from .xor import xor


def lessons():
    rows = []

    def add(title, what, recognize, example, output, tool, why, mistakes, limit):
        rows.append(
            dict(
                title=title,
                what=what,
                recognize=recognize,
                example_input=example,
                example_output=output,
                tool=tool,
                why=why,
                mistakes=mistakes,
                limits=limit,
            )
        )

    for name in encodings.NAMES:
        plain = "HELLO" if name in ("Morse", "Bacon") else "PCCP{learn}"
        clues = {
            "Base64": "Letters, digits, + and /; often ends in =.",
            "URL-safe Base64": "Base64 using - and _ instead of + and /.",
            "Base32": "Mostly A–Z and 2–7; padding uses =.",
            "Hex": "Pairs of digits 0–9 and letters A–F.",
            "Binary": "Groups of eight 0/1 digits.",
            "Octal": "Groups of three digits from 0 to 7.",
            "ASCII decimal": "Space-separated integers between 0 and 255.",
            "Base58": "Letters and digits, excluding 0, O, I and l.",
            "Base85": "A dense mix of letters, numbers and punctuation.",
            "Ascii85": "ASCII punctuation; Adobe form may use <~ and ~>.",
            "URL encoding": "Percent followed by two hexadecimal digits, such as %7B.",
            "HTML entities": "References such as &#80; or &amp;.",
            "Unicode escapes": r"Escapes such as \u0050 or \x50.",
            "ROT13": "Letters shifted by thirteen; braces are unchanged.",
            "Atbash": "Alphabet reversed: A becomes Z.",
            "Morse": "Dots and dashes; spaces separate letters and / separates words.",
            "Bacon": "Groups of five A/B symbols. This app uses the 26-letter version.",
            "Reverse": "Characters written in the opposite order.",
        }
        add(
            name,
            f"{name} is a reversible representation or simple transformation of data.",
            clues[name],
            encodings.encode(name, plain.encode()),
            plain,
            "Encoding / Decoding → " + name,
            "The decoder applies the inverse mapping. No secret key is needed for this representation.",
            "Do not assume every matching alphabet is this encoding. Check the decoded bytes and challenge context.",
            "It cannot decrypt secure encryption. Some variants use different alphabets, separators or padding.",
        )
    add(
        "Caesar",
        "A substitution that shifts every letter by the same amount.",
        "Letter patterns and spaces remain.",
        "KHOOR",
        "HELLO",
        "Classical Ciphers → Caesar brute force",
        "There are only 26 standard shifts, so try all of them.",
        "A negative shift decrypts a positive shift. Short words can have several plausible answers.",
        "A custom alphabet needs the matching alphabet; this does not solve arbitrary substitution.",
    )
    add(
        "Vigenère",
        "A repeated keyword chooses a different Caesar shift for each letter.",
        "Long text may have periodic frequency patterns.",
        "LXFOPV EF RNHR",
        "ATTACK AT DAWN (key LEMON)",
        "Classical Ciphers → Vigenère decrypt / recover",
        "With the key, subtract each key letter. Recovery estimates key length and scores each column.",
        "This app advances the key on letters only. Check the challenge convention.",
        "Recovery needs a long natural-language sample and is heuristic; a one-time random key cannot be recovered this way.",
    )
    add(
        "Affine",
        "Letters follow y = a×x + b modulo 26.",
        "Letter frequencies are preserved but relabeled.",
        "IHHWVCSWFRCP",
        "AFFINECIPHER (a=5, b=8)",
        "Classical Ciphers → Affine decrypt / brute force",
        "If gcd(a,26)=1, a has an inverse and x = a⁻¹(y−b).",
        "Only twelve a values are invertible.",
        "Only standard 26-letter affine substitution is supported.",
    )
    add(
        "Rail Fence",
        "Letters follow a zigzag across rails, then each rail is read.",
        "The same letters occur in a changed order.",
        rail("HELLOWORLD", 3, False),
        "HELLOWORLD (3 rails)",
        "Classical Ciphers → Rail Fence decrypt",
        "Recreate the zigzag positions, place the rail text in them, and read the original order.",
        "Spaces count as characters here. The rail count and starting convention must match.",
        "Other transposition families use different layouts.",
    )
    add(
        "Substitution & transposition",
        "A substitution changes symbols; a transposition reorders them.",
        "Compare letter counts, repeated patterns and word lengths.",
        "ABBA CABB",
        "Pattern 0-1-1-0 / 2-0-1-1",
        "Classical Ciphers → Frequency analysis / Reverse",
        "A substitution preserves repeated-letter structure. A transposition preserves the complete letter counts.",
        "Frequency alone does not give a unique key. This app does not automatically solve arbitrary substitution.",
        "General substitution and columnar transposition require manual reasoning or an external specialized solver. Rail Fence and reverse are implemented.",
    )
    add(
        "XOR",
        "XOR flips a bit when the key bit is one.",
        "Ciphertext may be binary, hex or Base64. Repeated keys can create patterns.",
        "09 04 0d 0d 0e (hex), key 41 (hex)",
        "HELLO",
        "XOR Solver",
        "(message XOR key) XOR key = message. Single-byte keys have just 256 possibilities.",
        "Select the correct input and key encoding. A printable guess does not prove the key.",
        "Repeating-key recovery assumes English and enough data. A random one-time pad of message length is not recoverable without more information.",
    )
    add(
        "Hashes",
        "A hash maps data to a fixed-length digest; it is not reversible encryption.",
        "Lengths and prefixes suggest possible formats.",
        "5d41402abc4b2a76b9719d911017c592",
        "MD5 candidate; equals MD5 of hello",
        "Hash Analyzer",
        "Generate the digest of a supplied candidate and compare exact bytes. A dictionary tests only its supplied entries.",
        "MD5 and NTLM both have 32 hex characters. SHA-2 and SHA-3 lengths can also overlap.",
        "bcrypt and PBKDF2 are identified only. Dictionary checks support fast listed digests, are capped at 10,000 explicitly supplied lines, and have a time limit.",
    )
    add(
        "RSA",
        "RSA uses a public modulus n=p×q and exponent e.",
        "Challenges often give n, e and c, or a PEM key.",
        "p=61, q=53, e=17, c=2790",
        "m=65, byte A",
        "RSA Solver",
        "Known factors give phi=(p−1)(q−1); invert e to obtain d; compute c^d mod n.",
        "Raw integer output may contain padding. This module does not remove OAEP or PKCS#1 padding.",
        "Only small moduli below 2^48 are factored, with divisor/time caps. Strong general RSA cannot be broken automatically.",
    )
    add(
        "RSA common modulus & low exponent",
        "Special unpadded RSA mistakes can reveal a message.",
        "Same n and same message under coprime exponents; or c=m^e with no modular wrap.",
        "e=3, c=74088",
        "m=42 (exact cube root)",
        "RSA Solver → Small exponent / Common modulus",
        "Use Bézout coefficients for common modulus, or an exact integer root when c is a perfect e-th power.",
        "A small exponent alone is not enough. Messages and padding conditions must match.",
        "The common-modulus helper requires coprime exponents and invertible ciphertexts when negative powers are used; the root helper does not search wrapped powers.",
    )
    add(
        "AES & authenticated encryption",
        "AES uses a secret key and a block or stream-like mode.",
        "Need exact key, mode, nonce/IV, ciphertext and often a tag.",
        "AES-128 ECB: key 000102030405060708090a0b0c0d0e0f; input 00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
        "AES / DES Tools",
        "Correct parameters invert encryption. GCM also verifies an authentication tag before returning plaintext.",
        "An IV is not a key. CTR counter starts at zero here. PKCS7 applies only to ECB/CBC. Never reuse CTR/GCM nonces with one key.",
        "No AES key brute force is attempted. GCM uses a 16-byte tag in this app; wrong tags fail without returning plaintext. ECB/CBC/CTR do not authenticate data.",
    )
    add(
        "DES & 3DES",
        "Older block ciphers retained for educational interoperability.",
        "DES uses an 8-byte key; 3DES uses 16 or 24 bytes.",
        "DES key 133457799bbcdff1; ECB block 0123456789abcdef",
        "85e813540f0ab405",
        "AES / DES Tools → DES / 3DES",
        "A supplied key reverses the block operation. Mode and padding must also match.",
        "Do not choose legacy ciphers for a new design; degenerate 3DES keys are rejected.",
        "Supported modes are ECB, CBC and CTR. DES and 3DES are obsolete for modern protection.",
    )
    add(
        "Modular arithmetic & inverses",
        "Modulo keeps a remainder; an inverse undoes multiplication modulo m.",
        "Look for %, mod, congruences and large integers.",
        "a=17, m=3120",
        "inverse=2753",
        "Advanced Crypto → Modular inverse / GCD / Extended GCD",
        "The extended Euclidean algorithm finds x,y with ax+my=gcd(a,m). An inverse exists only when the gcd is 1.",
        "Integer division is not modular division. Check whether an inverse exists first.",
        "Inputs are capped; use exact integers rather than floating-point arithmetic.",
    )
    add(
        "Chinese Remainder Theorem",
        "CRT joins several modular conditions into one.",
        "The same unknown has remainders under several moduli.",
        "moduli=[3,5,7], remainders=[2,3,2]",
        "x=23 mod 105",
        "Advanced Crypto → CRT",
        "For pairwise coprime moduli, one residue class satisfies all the conditions.",
        "This helper requires pairwise coprime positive moduli.",
        "It solves congruences, not arbitrary encryption.",
    )
    add(
        "Primes & factorization",
        "Prime numbers have no positive divisors except 1 and themselves.",
        "RSA moduli are products of primes.",
        "3233",
        "61 × 53",
        "Advanced Crypto → Prime test / Factor small integer",
        "Trial division finds small factors; prime testing checks the remaining cofactor.",
        "A large unfactored cofactor is not proof of primality.",
        "Factorization is capped below 2^48 and one million trial divisors. Large prime tests use SymPy probable-prime methods and are identified as such.",
    )
    add(
        "Entropy & frequency",
        "Entropy measures byte variety; frequency counts symbols.",
        "High entropy can mean compressed, random or encrypted data.",
        "AAAA",
        "Byte entropy = 0 bits per byte",
        "Advanced Crypto → Entropy / Frequency",
        "Compute -sum(p×log2(p)) over byte counts. Compare letter patterns separately.",
        "Short inputs make entropy estimates unreliable. High entropy cannot name a cipher.",
        "This is descriptive analysis, not decryption.",
    )
    add(
        "Simple PRNG / LCG",
        "An LCG generates x_next = (a×x + b) mod m.",
        "A challenge gives recurrence parameters, seeds or consecutive outputs.",
        "a=5, b=1, m=16, seed=0, count=5",
        "1, 6, 15, 12, 13",
        "Advanced Crypto → LCG generate / recover",
        "When m is known, invert the first difference to recover a, then recover b and verify the supplied sequence.",
        "The needed inverse may not exist. Consecutive outputs and the correct modulus are required.",
        "This is an educational LCG only. It does not predict a cryptographically secure random generator.",
    )
    add(
        "Files, ZIP, PEM & DER",
        "File headers describe containers; they do not reveal encryption keys.",
        "PK starts ZIP; PEM has BEGIN headers; DER often starts an ASN.1 sequence.",
        "-----BEGIN PUBLIC KEY-----",
        "PEM public-key container identified",
        "File Analyzer / RSA Solver → Inspect PEM / DER",
        "Inspect signatures, printable strings and safe in-memory archive members; parse supported RSA/ECC keys.",
        "Do not run an unknown script. A .enc extension does not identify a cipher. Archive filenames are shown as text, never used as extraction paths.",
        "No nested archive recursion. At most 32 ZIP members, 1 MiB per member, 2 MiB total, and 100:1 expansion. Encrypted ZIP entries are skipped; generic certificates may only be recognized.",
    )
    return rows


def practice():
    rows = []

    def add(
        title,
        kind,
        data,
        answer,
        setup="",
        difficulty="Easy",
        hint="",
        steps="",
        **extra,
    ):
        if not steps:
            method = {
                "Caesar": f'Try all 26 negative shifts. The correct shift is -{extra.get("shift",0)}; punctuation stays unchanged.',
                "Atbash": "Map A↔Z, B↔Y and so on, preserving case and punctuation.",
                "Vigenère": "Repeat the key LEMON over letters only. Subtract each key letter modulo 26; preserve nonletters.",
                "Affine": "Check gcd(5,26)=1. The inverse of 5 is 21, so apply x = 21×(y−8) mod 26 to every letter.",
                "Rail Fence": "Mark the 3-rail zigzag positions for the entire input length. Fill each rail with ciphertext in order, then read the zigzag.",
                "Reverse": "Read the input characters from last to first, including braces and punctuation.",
            }.get(kind, "Apply the matching inverse transformation.")
            steps = f"1. Open the {kind} tool.\n2. {method}\n3. Inspect the recovered characters and verify braces and case.\n4. Submit {answer}."
        rows.append(
            dict(
                id=len(rows) + 1,
                title=title,
                kind=kind,
                input=data,
                answer=answer,
                setup=setup,
                difficulty=difficulty,
                points={"Easy": 50, "Medium": 100, "Advanced": 150}[difficulty],
                description="Recover the original message using the supplied clues. Submit the final flag unless instructed otherwise.",
                hints=[
                    hint or "Identify the representation before trying ciphers.",
                    "Use the matching workbench and inspect the result.",
                ],
                walkthrough=steps,
                **extra,
            )
        )

    for name, slug in [
        ("Base64", "base_camp"),
        ("URL-safe Base64", "safe_path"),
        ("Base32", "thirty_two"),
        ("Hex", "hex_trail"),
        ("Binary", "bit_by_bit"),
        ("Octal", "eight_way"),
        ("ASCII decimal", "number_notes"),
        ("Base58", "fifty_eight"),
        ("Base85", "dense_message"),
        ("URL encoding", "percent_path"),
        ("HTML entities", "web_letters"),
        ("Unicode escapes", "unicode_notes"),
    ]:
        flag = f"PCCP{{{slug}}}"
        lesson = next(x for x in lessons() if x["title"] == name)
        add(
            name + " checkpoint",
            "Encoding",
            encodings.encode(name, flag.encode()),
            flag,
            encoding=name,
            steps=f'1. Recognize the format: {lesson["recognize"]}\n2. Open Encoding / Decoding, choose {name}, and select Decode.\n3. {lesson["why"]}\n4. Read the resulting UTF-8 bytes: {flag}. Check that no extra layer remains, then submit the flag.',
        )
    for number, chain in enumerate(
        [
            ["Hex", "Base64"],
            ["ROT13", "Base64"],
            ["Hex", "ROT13", "Base64"],
            ["Base32", "Hex", "Base64"],
        ],
        1,
    ):
        flag = f"PCCP{{layer_lab_{number}}}"
        data = flag.encode()
        for name in chain:
            data = encodings.encode(name, data).encode()
        add(
            f"Layers {number}",
            "Layers",
            data.decode(),
            flag,
            difficulty="Medium",
            hint="Undo the outermost layer first.",
            steps="Encoding order was "
            + " → ".join(chain)
            + ". Decode in reverse: "
            + " → ".join(reversed(chain))
            + f". Result: {flag}.",
            chain=chain,
        )
    for shift in (3, 19):
        flag = f"PCCP{{shift_{shift}}}"
        add(
            f"Caesar patrol {shift}",
            "Caesar",
            caesar(flag, shift),
            flag,
            shift=shift,
            hint="Try all 26 shifts.",
        )
    flag = "PCCP{mirror_letters}"
    add("Alphabet mirror", "Atbash", atbash(flag), flag)
    flag = "PCCP{keyword_map}"
    add(
        "Keyword map",
        "Vigenère",
        vigenere(flag, "LEMON", False),
        flag,
        "Key: LEMON",
        key="LEMON",
    )
    flag = "PCCP{linear_letters}"
    add(
        "Linear letters",
        "Affine",
        affine(flag, 5, 8, False),
        flag,
        "a=5, b=8",
        a=5,
        b=8,
    )
    flag = "PCCP{rail_station}"
    add(
        "Rail station",
        "Rail Fence",
        rail(flag, 3, False),
        flag,
        "3 rails; spaces count",
        rails=3,
    )
    add(
        "Radio operator",
        "Morse",
        morse("PCCP RADIO READY", True),
        "PCCP{radio_ready}",
        "After decoding, lowercase the final two words, join with underscore and wrap them in PCCP{...}.",
        steps="Decode dot/dash groups to PCCP RADIO READY. Format the last two words as instructed: PCCP{radio_ready}.",
        plain="PCCP RADIO READY",
    )
    add(
        "Two-symbol alphabet",
        "Bacon",
        bacon("BACON", True),
        "PCCP{bacon}",
        "26-letter Bacon variant. Lowercase the decoded word and wrap it in PCCP{...}.",
        plain="BACON",
        steps="Map A to 0 and B to 1. Split into five-bit numbers: 1,0,2,14,13. Map A=0 through Z=25, giving BACON. Submit PCCP{bacon}.",
    )
    for title, key, kind, slug in [
        ("One-byte beacon", b"\x37", "Single-byte XOR", "xor_beacon"),
        ("Known XOR key", b"KEY", "Known XOR", "xor_key"),
        ("Repeating signal", b"ICE", "Repeating XOR", "repeat_signal"),
    ]:
        flag = f"PCCP{{{slug}}}"
        plain = (
            flag
            if kind != "Repeating XOR"
            else "This is a repeating key XOR practice message. The hidden flag is "
            + flag
            + ". Read the entire message carefully. " * 3
        )
        add(
            title,
            kind,
            xor(plain.encode(), key).hex(),
            flag,
            "Input encoding: Hex. "
            + (
                "Key hex: " + key.hex()
                if kind != "Single-byte XOR"
                else "Key is one byte."
            ),
            difficulty="Medium",
            key_hex=key.hex(),
            plain=plain,
            steps=f"Decode the hex to bytes. XOR each byte with the repeating key {key.hex()} (hex). XOR is its own inverse. The message contains {flag}.",
        )
    flag = "PCCP{digest_match}"
    add(
        "Digest comparison",
        "Hash",
        hashlib.sha256(flag.encode()).hexdigest(),
        flag,
        "Algorithm: SHA-256. Candidate list: PCCP{digest_wrong}, PCCP{digest_match}, PCCP{digest_other}",
        steps="Hash each supplied candidate with SHA-256 and compare the full digest. Only PCCP{digest_match} matches.",
        algorithm="SHA-256",
    )
    add(
        "Digest ambiguity",
        "Hash identification",
        "a" * 64,
        "SHA-256 / SHA3-256",
        "Name the two listed common SHA-family possibilities from this hex length; submit exactly SHA-256 / SHA3-256.",
        steps="64 hex digits represent 256 bits. Both SHA-256 and SHA3-256 fit. The length cannot prove which was used.",
    )
    add(
        "Tiny RSA postcard",
        "RSA",
        '{"p":61,"q":53,"e":17,"c":2790}',
        "PCCP{A}",
        "Decrypt the byte, then wrap that character in PCCP{...}.",
        params={"p": 61, "q": 53, "e": 17, "c": 2790},
        plain="A",
        steps="n=3233; phi=3120; d=2753. Compute 2790^2753 mod 3233 = 65. ASCII 65 is A. Submit PCCP{A}.",
    )
    add(
        "Unwrapped cube",
        "RSA root",
        '{"e":3,"c":74088}',
        "PCCP{42}",
        "No modular wrap occurred. Wrap the recovered integer in PCCP{...}.",
        params={"e": 3, "c": 74088},
        steps="The exact integer cube root of 74088 is 42. Verify 42^3=74088. Submit PCCP{42}.",
    )
    n = 3233
    m = 65
    params = {"n": n, "e1": 7, "e2": 11, "c1": pow(m, 7, n), "c2": pow(m, 11, n)}
    import json

    add(
        "Shared modulus",
        "RSA common",
        json.dumps(params),
        "PCCP{A}",
        "Two raw ciphertexts encrypt the same byte. Wrap the recovered character in PCCP{...}.",
        difficulty="Advanced",
        params=params,
        steps="gcd(7,11)=1 and 8×7−5×11=1. Compute c1^8 × c2^−5 mod n = 65. The byte is A. Submit PCCP{A}.",
    )
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    key = bytes(range(16))
    for mode in ("CBC", "GCM"):
        flag = f"PCCP{{aes_{mode.lower()}_lab}}"
        iv = bytes(range(16 if mode == "CBC" else 12))
        cipher = (
            AES.new(key, AES.MODE_CBC, iv=iv)
            if mode == "CBC"
            else AES.new(key, AES.MODE_GCM, nonce=iv)
        )
        if mode == "CBC":
            ct = cipher.encrypt(pad(flag.encode(), 16))
            tag = b""
        else:
            ct, tag = cipher.encrypt_and_digest(flag.encode())
        add(
            "Supplied AES " + mode,
            "AES",
            ct.hex(),
            flag,
            f'AES-{mode}; all fields Hex; key={key.hex()}; IV/nonce={iv.hex()}; tag={tag.hex() or "not used"}; PKCS7 for CBC.',
            difficulty="Medium",
            mode=mode,
            key_hex=key.hex(),
            iv_hex=iv.hex(),
            tag_hex=tag.hex(),
            steps=f"Enter the supplied key, IV/nonce and ciphertext as Hex. Select AES-{mode}, Decrypt. "
            + (
                "Verify the tag before accepting plaintext. "
                if mode == "GCM"
                else "Remove PKCS7 padding. "
            )
            + f"Result: {flag}.",
        )
    add(
        "Inverse ticket",
        "Inverse",
        '{"a":17,"m":3120}',
        "PCCP{2753}",
        "Find the modular inverse and wrap the integer in PCCP{...}.",
        steps="Extended Euclid gives 17×2753 ≡ 1 mod 3120. Submit PCCP{2753}.",
    )
    add(
        "Three remainder stops",
        "CRT",
        '{"moduli":[3,5,7],"remainders":[2,3,2]}',
        "PCCP{23}",
        "Find the smallest nonnegative solution and wrap it in PCCP{...}.",
        steps="The moduli are pairwise coprime. CRT gives x=23 modulo 105. Check all three remainders. Submit PCCP{23}.",
    )
    add(
        "Predict the toy generator",
        "LCG",
        '{"a":5,"b":1,"m":16,"seed":0,"count":5}',
        "PCCP{13}",
        "Compute five outputs after the seed. Wrap the fifth output in PCCP{...}.",
        steps="Apply (5x+1) mod 16 repeatedly: 1,6,15,12,13. Submit PCCP{13}.",
    )
    flag = "PCCP{reverse_route}"
    add("Backwards route", "Reverse", flag[::-1], flag)
    return rows


CHEATSHEET = r"""# Offline CTF field notes

Start with the story and flag format. Preserve the original bytes. Identify a representation, decode one layer, and inspect the output. Keep a record of each operation. Matching an alphabet is only a guess. If several decodings fit, compare their results.

## Windows PowerShell
Decode Base64 UTF-8: `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('UENDUHt0ZXN0fQ=='))`

View file bytes: `Format-Hex -LiteralPath .\challenge.bin`

Compute a digest: `Get-FileHash -LiteralPath .\challenge.bin -Algorithm SHA256`

## Python (Windows or Kali, when Python is installed)
Base64: `python -c "import base64; print(base64.b64decode('UENDUHt0ZXN0fQ=='))"`

Hex: `python -c "print(bytes.fromhex('504343507b746573747d'))"`

ROT13: `python -c "import codecs; print(codecs.decode('URYYB','rot_13'))"`

Modular inverse: `python -c "print(pow(17,-1,3120))"`

## Kali Linux shell
Decode: `printf '%s' 'UENDUHt0ZXN0fQ==' | base64 -d`

Hex to bytes: `printf '%s' '504343507b746573747d' | xxd -r -p`

Read strings: `strings -a challenge.bin`

Inspect file type: `file challenge.bin`

Digest: `sha256sum challenge.bin`

These commands are examples for your own authorized practice data. The application does not invoke a shell, Kali, or these commands. Its tools run offline using bundled Python libraries.

## Decision guide
Encoding has no secret key. Hashes compare candidates; they do not decrypt. Classical ciphers may have small key spaces. XOR with a short repeated key may leak patterns. Modern AES requires a key and exact parameters. Strong RSA needs a private key or a demonstrated weakness. A format label is never proof that encryption has been cracked.
"""

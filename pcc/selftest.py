"""Known-answer checks used by --smoke-test in source and packaged builds."""

import base64
from .classical import caesar


def cases():
    layered = base64.b64encode(caesar(b"PCCP{packaged_layers}".hex(), 13).encode())
    key = "000102030405060708090a0b0c0d0e0f"
    return [
        (
            "Hex",
            "encoding",
            dict(operation="Decode", method="Hex", text="504343507b6865787d"),
            ("output", "PCCP{hex}"),
        ),
        (
            "ROT13",
            "classical",
            dict(
                operation="ROT13",
                text="URYYB",
                shift="3",
                alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            ),
            ("output", "HELLO"),
        ),
        (
            "Known XOR",
            "xor",
            dict(
                operation="Known key",
                text="09040d0d0e",
                encoding="Hex",
                key="41",
                key_encoding="Hex",
            ),
            ("output", "HELLO"),
        ),
        (
            "RSA",
            "rsa",
            dict(operation="Decrypt", text='{"p":61,"q":53,"e":17,"c":2790}'),
            ("output", "A"),
        ),
        (
            "AES ECB known vector",
            "symmetric",
            dict(
                operation="Encrypt",
                text="00112233445566778899aabbccddeeff",
                encoding="Hex",
                algorithm="AES",
                mode="ECB",
                key=key,
                key_encoding="Hex",
                iv="",
                tag="",
                aad="",
                padding="None",
            ),
            ("ciphertext_hex", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ),
        (
            "AES GCM verified",
            "symmetric",
            dict(
                operation="Decrypt",
                text="0388dace60b6a392f328c2b971b2fe78",
                encoding="Hex",
                algorithm="AES",
                mode="GCM",
                key="00" * 16,
                key_encoding="Hex",
                iv="00" * 12,
                tag="ab6e47d42cec13bdf53a67b21257bddf",
                aad="",
                padding="None",
            ),
            ("authenticated", True),
        ),
        (
            "AES GCM rejects bad tag",
            "symmetric",
            dict(
                operation="Decrypt",
                text="0388dace60b6a392f328c2b971b2fe78",
                encoding="Hex",
                algorithm="AES",
                mode="GCM",
                key="00" * 16,
                key_encoding="Hex",
                iv="00" * 12,
                tag="00" * 16,
                aad="",
                padding="None",
            ),
            ("error", "MAC check failed"),
        ),
        (
            "SHA256",
            "hash",
            dict(operation="Generate", text="hello", algorithm="SHA-256", target=""),
            (
                "output",
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            ),
        ),
        (
            "CRT",
            "advanced",
            dict(operation="CRT", text='{"moduli":[3,5,7],"remainders":[2,3,2]}'),
            ("output_contains", "23"),
        ),
        (
            "File inspection",
            "file",
            dict(data=b"\0PCCP{packaged_file}\xff", name="smoke.bin"),
            ("flags", "PCCP{packaged_file}"),
        ),
        (
            "Layered search",
            "auto",
            dict(data=layered),
            ("flags", "PCCP{packaged_layers}"),
        ),
        (
            "Base64",
            "auto",
            dict(data=b"UENDUHtiYXNlX2NhbXB9"),
            ("flags", "PCCP{base_camp}"),
        ),
    ]

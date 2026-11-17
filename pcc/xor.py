from .common import english_score, flags


def xor(data, key):
    if not key:
        raise ValueError("XOR key cannot be empty.")
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def single_byte(data, budget=None, top=10):
    results = []
    for key in range(256):
        if budget and key % 16 == 0:
            budget.check()
        plain = xor(data, bytes([key]))
        results.append((english_score(plain) + (2 if flags(plain) else 0), key, plain))
    return sorted(results, reverse=True)[:top]


def key_lengths(data, maximum=32):
    results = []
    for size in range(2, min(maximum, len(data) // 4) + 1):
        blocks = [
            data[i * size : (i + 1) * size] for i in range(min(8, len(data) // size))
        ]
        pairs = [
            sum((a ^ b).bit_count() for a, b in zip(blocks[i], blocks[i + 1])) / size
            for i in range(len(blocks) - 1)
        ]
        results.append((sum(pairs) / len(pairs), size))
    return sorted(results)


def repeating_candidates(data, budget):
    if len(data) < 16:
        raise ValueError(
            "At least 16 bytes are needed; long English messages give better estimates."
        )
    out = []
    for distance, size in key_lengths(data)[:8]:
        budget.check()
        key = bytes(
            single_byte(data[col::size], budget, 1)[0][1] for col in range(size)
        )
        plain = xor(data, key)
        out.append(
            {
                "key_hex": key.hex(),
                "key_length": size,
                "distance": round(distance, 3),
                "score": round(english_score(plain), 3),
                "plaintext": plain.decode("utf-8", "replace"),
            }
        )
    return sorted(out, key=lambda x: x["score"], reverse=True)

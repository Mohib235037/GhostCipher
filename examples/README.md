# Worked examples

All payloads here are synthetic or standard test vectors. Each row describes the tool settings and the expected result.

| Tool | Input and settings | Expected result |
| --- | --- | --- |
| Auto Crypto Detector | Open [`base64.txt`](base64.txt) and click **Auto Detect & Solve**. | `PCCP{base_camp}` with a `Base64` transformation. |
| Encoding / Decoding | Select **Decode** and **Hex**. Paste `504343507b6865787d`. | `PCCP{hex}` |
| XOR Solver | Select **Known key**. Set input and key encoding to **Hex**. Paste `09040d0d0e` with key `41`. | `HELLO` |
| Hash Analyzer | Select **Generate** and **SHA-256**. Paste `hello` without a trailing newline. | `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` |
| RSA Solver | Select **Decrypt**. Paste `{"p":61,"q":53,"e":17,"c":2790}`. | `A`, whose integer value is `65` |
| File Analyzer | Select **Open & inspect a local file** and open [`file-inspection.txt`](file-inspection.txt). | `PCCP{local_example}` appears in the file report. |

## Verify AES-GCM output

In **AES / DES Tools**, select **Decrypt**, **AES**, and **GCM**. Set input and key encoding to **Hex**. Use the following public test vector and leave associated data blank.

| Field | Value |
| --- | --- |
| Ciphertext | `0388dace60b6a392f328c2b971b2fe78` |
| Key | `00000000000000000000000000000000` |
| IV / nonce | `000000000000000000000000` |
| Tag | `ab6e47d42cec13bdf53a67b21257bddf` |

The output preview shows 16 zero bytes in hex and the explanation reports verified authentication. Change the last digit of the tag to `e` and run again. The app reports a MAC check failure and clears the previous output.

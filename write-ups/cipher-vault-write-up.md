# Cipher Vault Write-up

## Challenge

The APK contains a locked vault with 64 encrypted records. Its resources and DEX files reveal the passphrase generator, verifier, and record encryption scheme.

## Recovering the passphrase

The legacy code in `LegacyPassphrase` generates six entries from a 256-entry, eight-byte lexicon, then appends a two-digit suffix. The lexicon is stored in `res/raw/m4.bin`; `Lexicon.load` decodes each byte with:

```text
plain[i] = encrypted[i] XOR ((((i * 73) + 93) XOR ((i >> 3) * 17)) AND 255)
```

`SeedWindow` defines a search window of `2^18` seeds. Its base is `764149760`, so the candidate range is `base` through `base + 262143`. For each seed, the passphrase generator initializes Java's `Random` with `0x6a09e667f3bcc909 XOR seed`, selects six lexicon entries, and computes the numeric suffix.

The matching seed is `764408707` (offset `258947`), yielding:

```text
smxvoisk-fcxfgnpl-poznukfv-zxpmztpo-yanlxwmm-yanlxwmm-42
```

## Verifying and decrypting the vault

`CryptoEngine.deriveRoot` uses PBKDF2-HMAC-SHA256 with 32,768 iterations and a 256-bit output. The salt is the 16-byte salt in `res/raw/p7.bin`.

The app verifies the derived root by calculating HMAC-SHA256 over `cipher-verifier-v3` and comparing its first 16 bytes with the value decoded from `res/raw/n3.bin`. The recovered passphrase matches this verifier.

The store contains 64 AES-GCM records. For each record index `i`, the app derives a key using HKDF-SHA256 from the root and store salt, with info `v1 || byte(i)`. AES-GCM uses the record nonce and associated data `V1LT || byte(i)`. Each plaintext contains a title and value separated by byte `0x1f`.

Record 47 is titled `Archived security memo`. Its value is the flag:

```text
hiCTF{cryptography_should_be_implemnetd_properly}
```

The spelling `implemnetd` is reproduced exactly as it appears in the decrypted record.

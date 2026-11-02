# C3 Vault — Write-up

## Overview

The evidence contains a 4 MiB ESP32-C3 flash image and a raw eFuse read-register window. The application uses ESP-IDF flash encryption and encrypted NVS. Recovering the gateway identity and key requires applying the two encryption layers correctly, then following the Berry-free RISC-V application code to reproduce its HMAC derivation and challenge response.

The live verifier returns a fresh challenge for each TLS connection and allows one authentication attempt on that connection.

## 1. Map the eFuse register window

`efuse_read.bin` is 336 bytes, or 84 little-endian 32-bit register values. The recovery notes give the register group sizes: six words for BLOCK0, six for BLOCK1, and eight for each block from BLOCK2 through BLOCK10.

This maps eFuse BLOCK4 (KEY0) to words 28 through 35. The key's register bytes are little-endian within each word:

```python
from pathlib import Path

efuse = Path("efuse_read.bin").read_bytes()
words = [int.from_bytes(efuse[i:i + 4], "little")
         for i in range(0, len(efuse), 4)]

# BLOCK0: 6 words, BLOCK1: 6, BLOCK2: 8, BLOCK3: 8
key0_words = words[6 + 6 + 8 + 8 : 6 + 6 + 8 + 8 + 8]
key0_register_bytes = b"".join(w.to_bytes(4, "little") for w in key0_words)
print(key0_register_bytes.hex())
```

The BLOCK4 bytes are:

```text
a60e11f7e712272a9cdf3d656ad89282e861dc0ffd2fc127f7f74da513654d7f
```

BLOCK0's `SPI_BOOT_CRYPT_CNT` is odd, so flash encryption is enabled. `KEY_PURPOSE_0` is 4 (`XTS_AES_128_KEY`), identifying BLOCK4 as the 256-bit XTS flash key. For the host-side `espsecure` tooling, reverse the full key byte sequence; this is the byte order used by ESP-IDF's eFuse flash-key programming path:

```python
Path("flash_enc.key").write_bytes(key0_register_bytes[::-1])
```

## 2. Decrypt the encrypted partitions

The partition table is at `0x8000`. Decrypting with the reversed key produces a valid table and shows:

| Partition | Offset | Size | Encrypted flag |
| --- | ---: | ---: | ---: |
| `nvs` | `0x9000` | `0x6000` | no |
| `nvs_keys` | `0xf000` | `0x1000` | yes |
| `factory` | `0x10000` | `0x100000` | no |

Although the `factory` entry's explicit flag bit is clear, its application image is flash-encrypted as an app partition. The `nvs_keys` data partition is also flash-encrypted because its explicit encrypted flag is set. The `nvs` data partition is not flash-encrypted. For example, use `espsecure` from esptool 4.8.1:

```powershell
espsecure.exe decrypt_flash_data --aes_xts --keyfile flash_enc.key `
  --output flash.dec.bin --address 0 flash_image.bin
```

The decrypted image has the partition-table magic `aa 50` at `0x8000`. Read the NVS encryption key material from the decrypted `nvs_keys` partition:

```python
flash_dec = Path("flash.dec.bin").read_bytes()
nvs_key_partition = flash_dec[0xF000:0x10000]
Path("nvs_keys.bin").write_bytes(nvs_key_partition)
```

The first 64 bytes contain the two AES-XTS keys for NVS. The following four bytes are the key-record CRC. The CRC matches the first 64 bytes when calculated with the NVS key-record convention (`zlib.crc32(key_bytes, 0xffffffff)`), confirming the extraction.

## 3. Decrypt and parse NVS

The `nvs` partition's encrypted flag is clear, so take it directly from the physical flash image. Do not take it from a copy that has had ESP flash decryption applied at every address. NVS has its own AES-XTS encryption for entries; decrypt it using the key data recovered above. With Espressif's NVS partition generator 0.1.6:

```powershell
# Extract this partition from the original physical image.
python -c "from pathlib import Path; b=Path('flash_image.bin').read_bytes(); Path('nvs.bin').write_bytes(b[0x9000:0xF000])"

python -m esp_idf_nvs_partition_gen decrypt nvs.bin nvs_keys.bin nvs.plain.bin
```

The namespace and credential entries are:

| Namespace | Key | Value |
| --- | --- | --- |
| `gateway` | `hostname` | `c3-vault-gw` |
| `gateway` | `device_id` | `ee0315f3953aad298d7f3f43973ad618` |
| `gateway` | `generation` | `7` |
| `vault_v1` | `seed` | `d857200f87a1728b5220a4d77c31d7d9ee9bf8992ad16dbb398d05844676aa4f` |
| `vault_v2` | `seed` | `826e4e9e65c0ce89f413b7c291bb7e84185c64d4ec8769805227253b985083c5` |

NVS blobs use a metadata entry followed by one or more data slots. Account for each entry's span when parsing: a blob's following slot contains the decrypted payload, not a new key/value entry. There are two seeds in the image, but the firmware explicitly opens namespace `vault_v2` and reads its `seed`; the old `vault_v1` value is stale.

## 4. Recover the authentication algorithm

The factory application is an ESP image with RISC-V code. Parsing its segment headers and disassembling the executable segment shows that startup reads the gateway's device ID and generation and the `vault_v2/seed` blob.

It derives the device key as:

```text
derived_key = HMAC-SHA256(
    key = vault_v2_seed,
    msg = "c3-vault/device-key/v2" || NUL || device_id || uint32_le(generation)
)
```

The string-copy length in the compiled code includes the terminating NUL. The complete derivation input is 43 bytes. Using the recovered values yields:

```text
derived_key = 3783807e8cd41e83a331f5cfe6050e8b5b21d70cd6ddcd26c405816fb094f444
```

The authentication function builds a 64-byte message from a 16-byte prefix, the 32-byte challenge, and the 16-byte device ID:

```text
response = HMAC-SHA256(
    key = derived_key,
    msg = "C3VAULT-AUTH-V2" || NUL || challenge || device_id
)
```

The prefix copy also includes its NUL terminator. The server's `CHALLENGE` line supplies the challenge as 64 hex characters.

## 5. Authenticate to the live verifier

Connect with the active instance endpoint:

```text
ncat --ssl c3-vault-bd8bf321b7b5.chall.hiddeninvestigations.net 1337
```

The service sends a device ID, a fresh challenge, and commands. Submit `auth <64 hex characters>` on the same connection that supplied the challenge. The following standard-library Python script automates the interaction:

```python
import hashlib
import hmac
import re
import socket
import ssl

HOST = "c3-vault-bd8bf321b7b5.chall.hiddeninvestigations.net"
PORT = 1337
DEVICE_ID = bytes.fromhex("ee0315f3953aad298d7f3f43973ad618")
SEED_V2 = bytes.fromhex(
    "826e4e9e65c0ce89f413b7c291bb7e84"
    "185c64d4ec8769805227253b985083c5"
)
GENERATION = 7

derived_key = hmac.new(
    SEED_V2,
    b"c3-vault/device-key/v2\x00"
    + DEVICE_ID
    + GENERATION.to_bytes(4, "little"),
    hashlib.sha256,
).digest()

# The CTF endpoint uses a TLS certificate that may not chain to a local CA.
context = ssl._create_unverified_context()
with context.wrap_socket(
    socket.create_connection((HOST, PORT), timeout=10), server_hostname=HOST
) as sock:
    sock.settimeout(5)
    data = b""
    while b"> " not in data:
        data += sock.recv(4096)
    print(data.decode(errors="replace"), end="")

    challenge_hex = re.search(rb"CHALLENGE ([0-9a-fA-F]{64})", data).group(1)
    challenge = bytes.fromhex(challenge_hex.decode())
    auth_message = b"C3VAULT-AUTH-V2\x00" + challenge + DEVICE_ID
    response = hmac.new(derived_key, auth_message, hashlib.sha256).hexdigest()
    sock.sendall(b"auth " + response.encode() + b"\n")

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        print(chunk.decode(errors="replace"), end="")
```

The verifier accepts the response and returns the event flag.

## Flag

```text
hiCTF{efus3_cl34r_jt4g_0p3n_nv5_0ac748a7a4}
```

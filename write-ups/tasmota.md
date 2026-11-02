# Tasmota Vault — Write-up

## Challenge summary

The goal is to recover a sealed vault record from an ESP32 Tasmota flash image and a short MQTT capture. The supplied `recovery.txt` describes the fixture and says the analysis is offline: no board, broker, emulator, or connection to captured hosts is needed.

The key steps are to identify and mount the filesystem hidden in the flash image, reverse engineer the Berry agent to learn its key derivation and validation rules, and pair the correct key epoch with a nonce from the MQTT capture. The flag is authenticated by AES-GCM, which gives a clear way to verify the recovered inputs.

## 1. Locate the filesystem in the flash image

The flash image is 4 MiB. Reading the ESP32 partition table reveals the relevant final partition:

| Label | Offset | Size |
| --- | ---: | ---: |
| `spiffs` | `0x3b0000` | `0x50000` |

The partition is labeled `spiffs`, but the acquisition notes identify its contents as LittleFS disk format 2.0. Mount the partition as LittleFS rather than relying on the label. For example, with `littlefs-python`:

```python
from pathlib import Path
from littlefs import LittleFS

flash = Path("flash.bin").read_bytes()
fs_image = flash[0x3B0000:0x3B0000 + 0x50000]

fs = LittleFS(); fs.mount(fs_image)
for name in fs.listdir("/"):
    print(name)
```

The important files are:

```text
/autoexec.be
/vault.bec
/vault/device.id
/vault/keyring.bin
/vault/sealed.bin
```

`autoexec.be` loads `vault.bec`, so the compiled Berry file contains the agent logic. The raw device identifier is 16 bytes. The keyring is 108 bytes, which divides into three 36-byte records. The sealed record is 74 bytes.

## 2. Reverse engineer the Berry agent

The bytecode begins with `be cd fe 04`, identifying Berry bytecode version 4. Use the Berry source/bytecode tools matching the supplied firmware version to disassemble it; the Tasmota 15.6.0 Berry port is a useful reference for the opcode and native byte APIs.

The disassembly shows that the agent subscribes to:

```text
farm/gw-01/cmnd/VaultRotate
```

For each request, `unseal` validates the device identifier, reads an integer epoch, decodes the supplied nonce from hex, and looks up the matching keyring record. Each keyring record has this layout:

```text
4-byte little-endian epoch || 32-byte epoch key
```

The agent rejects malformed records, duplicate or missing epoch matches, a device ID that differs from `device.id`, and a nonce that does not decode to 32 bytes. The nonce supplied by MQTT is therefore an input to key derivation, not the AES-GCM nonce itself.

The derivation in the agent is equivalent to:

```text
HMAC-SHA256(epoch_key,
    "tasmota-vault/unwrap/v2" || 0x00 || device_id ||
    uint32_le(epoch) || mqtt_nonce)
```

Two Berry details matter when translating this to Python: `bytes("00")` constructs a single zero byte, and the four-byte integer conversion is little-endian. The resulting 32-byte HMAC is the AES key. The first 12 bytes of `sealed.bin` are the AES-GCM nonce; the last 16 bytes are its authentication tag; bytes between them are ciphertext.

## 3. Extract the request parameters from MQTT

Inspect the pcap as a TCP/MQTT stream and reassemble the client-to-broker data. The client subscribes to the VaultRotate topic, and the capture contains requests for epochs 7 and 8. There is also a TCP retransmission of the epoch 7 packet; TCP sequence numbers identify it as a duplicate delivery at the packet level, so it should not be treated as a separate request.

The relevant request values are:

| Epoch | MQTT nonce (hex) |
| ---: | --- |
| 7 | `9bb1ebe2f5663269d3be1348ee57dc7dbce22b373243aebd67897581cf6f65f0` |
| 8 | `1a3dfb1382455e073f25450c8c8cee24ba89b0a924f86b7103a732ab902a2606` |

Do not assume the latest-looking MQTT state packet or the first request is the right one. Test each request against the matching epoch key and the sealed record. AES-GCM tag verification determines whether the complete set of inputs is correct.

## 4. Derive the key and authenticate the record

This Python snippet reproduces the agent's derivation and decryption. Fill `device_id`, `keyring`, and `sealed` from the extracted LittleFS files:

```python
import hashlib
import hmac
from Crypto.Cipher import AES

device_id = open("device.id", "rb").read()
keyring = open("keyring.bin", "rb").read()
sealed = open("sealed.bin", "rb").read()

nonces = {
    7: "9bb1ebe2f5663269d3be1348ee57dc7dbce22b373243aebd67897581cf6f65f0",
    8: "1a3dfb1382455e073f25450c8c8cee24ba89b0a924f86b7103a732ab902a2606",
}

for epoch, nonce_hex in nonces.items():
    matches = [
        keyring[i + 4:i + 36]
        for i in range(0, len(keyring), 36)
        if int.from_bytes(keyring[i:i + 4], "little") == epoch
    ]
    if len(matches) != 1:
        continue

    mqtt_nonce = bytes.fromhex(nonce_hex)
    message = (
        b"tasmota-vault/unwrap/v2\x00"
        + device_id
        + epoch.to_bytes(4, "little")
        + mqtt_nonce
    )
    aes_key = hmac.new(matches[0], message, hashlib.sha256).digest()

    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=sealed[:12])
        plaintext = cipher.decrypt_and_verify(sealed[12:-16], sealed[-16:])
        print(epoch, plaintext.decode())
    except ValueError:
        print(epoch, "GCM authentication failed")
```

Epoch 7 fails authentication. Epoch 8 succeeds, confirming the correct MQTT nonce and keyring entry. This validation also confirms the interpretation of the Berry bytecode, the record boundaries, and the sealed blob layout.

## Flag

```text
hiCTF{b3rry_r0t4t10n_c94934d76344ab1151e03afd}
```

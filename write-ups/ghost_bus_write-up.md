# Ghost Bus — write-up

## Evidence

    ghost_bus/
    ├── capture.csv
    ├── capture.vcd
    ├── diagram.png
    ├── firmware.elf
    └── flash_dump.bin

The diagram identifies UART capture channel 0 as hub TX and channel 1 as secure-element TX. Frames use AA 55 | LEN | CMD | PAYLOAD | CRC16-Modbus (little-endian).

The capture contains the hub's nonce request on UART1:

    AA 55 00 10 00 7C

The secure element replies:

    AA 55 10 10 9E 3B 7A 44 C1 D0 5F 82 A6 E1 B4 90 7C D3 F5 A2 F3 E2

Thus the response payload (the current, repeatable nonce) is:

    9e3b7a44c1d05f82a6e1b4907cd3f5a2

The frame LEN is 0x10 (16 bytes), CMD is 0x10, and the final two bytes are its CRC. This is a read of the currently provisioned nonce, not a fresh-random-number operation.

## Recovering the hidden read

In the Thumb firmware, the main maintenance handler accepts command 0x55 with an empty payload. It requests the nonce from the secure element with command 0x10, then reads the sealed record from SPI NOR. The SPI transaction is:

- 0x03: NOR READ
- Address bytes 06 A0 00, i.e. address 0x06A000
- 48 dummy bytes (0xFF) to clock out the 48-byte record

The firmware's four-byte normalization loop is at 0x080004B4. The record occupies flash_dump.bin[0x6A000:0x6A030]:

    bf4104ca13efeaef33d742378ccff4cc741ed9df3761005fd530c13789cfd1cac49087603aa31566bc579f0ac22bdecb

The SPI metadata at 0x7F000 independently says sealed=0x6A000 len=48; the descriptor at 0x6A030 labels it sealed v2.

## Key derivation and decryption

The firmware initializes its SHA-256 state at 0x080006E4, hashes 24 bytes beginning at 0x08000CA0, then hashes the 16-byte nonce and finalizes the digest. The 24-byte derivation domain in the flash recovery image is:

    04325a9c117f3da0c0ffee5aa55a00ff1234567890abcdef

So:

    SHA256(domain || nonce) = 664ecd32a0a21d02a90afb1efb6919b120a1d5c834dc4255d67e9e1e45c45b61

The firmware's AES setup at 0x08000B5E expands a 16-byte AES key. Its CBC decrypt path is at 0x08000BDC. For a standard AES library, use the first 16 digest bytes as the AES-128 key and reverse the byte order within each 32-bit nonce word for the effective IV:

- Key: 664ecd32a0a21d02a90afb1efb6919b1
- IV: 447a3b9e825fd0c190b4e1a6a2f5d37c

The firmware uses a little-endian word layout in its AES implementation; this IV normalization reproduces the firmware's effective CBC input with a conventional AES implementation. The plaintext has PKCS#7 padding (07 repeated seven times), which the firmware checks before requiring the hiCTF{ prefix.

Reproduction:

    from pathlib import Path
    import hashlib
    from Crypto.Cipher import AES

    root = Path(r"C:\Users\WannaSleep\Desktop\ghost_bus")
    flash = (root / "flash_dump.bin").read_bytes()

    # UART1 response: AA 55, LEN, CMD, 16-byte payload, CRC16.
    rows = (root / "capture.csv").read_text().splitlines()[1:]
    uart1 = bytes(int(row.split(",")[2], 16)
                  for row in rows if row.split(",")[1] == "1")
    nonce = uart1[4:20]

    domain = flash[0xCA0:0xCB8]
    digest = hashlib.sha256(domain + nonce).digest()
    key = digest[:16]
    iv = b"".join(nonce[i:i+4][::-1] for i in range(0, 16, 4))
    ciphertext = flash[0x6A000:0x6A030]

    padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    plaintext = padded[:-padded[-1]]
    print(plaintext.decode())

Output:

    hiCTF{gh0st_bu5_uart_n0nc3_r3v3al_9c3f12}

## Flag

**hiCTF{gh0st_bu5_uart_n0nc3_r3v3al_9c3f12}**

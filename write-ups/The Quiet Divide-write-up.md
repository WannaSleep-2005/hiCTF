# The Quiet Divide — Write-up

## Flag

`hiCTF{c8c46fdbd6e5e4eacabfba53a156ff9ab10567f2}`

## What the capture establishes

The capture contains signed custody records for incident `INC-3142`, device `ARCH-14`, shard `IDX-S9`, and operation `ROL-7044`. The event chain is:

| Epoch | Phase | Event hash |
|---:|---|---|
| 732 | ROOT | `8c3c30460048c7249ffa3434e7865b340c797cbb0efe9990319322fafd7beab7` |
| 733 | PREP | `4999e5422d136c54d164510f304a92cf57cba97459f71928340741688ac0457b` |
| 733 | COMMIT | `f61ce4fef4229b787c8911c9a827bbb8d339c0287af719e02ad380a98b1fff4d` |
| 734 | PREP | `9a5e13327a7d7ae8d785f681a105c82adcebf942a8d9bfb8217efb2f03702fad` |
| 734 | COMMIT | `b34dc728c1fa1525020b1969a8af2698b2bcd91a95d58b3e3b940de35deda6e1` |

The independently witnessed release checkpoint freezes at position 734, with the final COMMIT hash above. This distinguishes the committed custody history from later recovery and qualification traffic. In particular, the later successful qualification report for firmware 7.7.1 is evidence of qualification; by itself, it does not establish that firmware was installed in production. The later recovery observation is signed under the `dr-ops` domain and is separate from the production custody chain.

## Recovering the evidence inputs

The capture includes two diagnostic escrow shares for the production QUIC session. XORing their decoded `share_b64` values reconstructs a TLS key log. Its SHA-256 matches the `keylog_sha256` in the escrow records. Supplying that key log to Wireshark decrypts the QUIC exchange and reveals the signed `mb-quic-observation/3` record.

The HTTP traffic serves firmware in byte ranges. Reassembling the four ranges for `pulse-codec_7.7.0_amd64.elf` produces a 14,528-byte ELF whose SHA-256 is `0835dfce789d002d55f3d20fe7f953a30da0adbef336a861839ce8f579958836`, matching the signed manifest and attestation. The captured pulse frame has SHA-256 `10da1fc0d74d00257145dd88d5287b9c54536fd7969188ba511790f1da4bff8b`. Decoding it with the supplied SDK yields sequence `10450910`, scheduler queue `23`, load `71`, and epoch time `1793517529318` ms.

The `/v10/sdk` response documents the archive format and deterministic key derivation. Using its canonicalization, codec, and HKDF rules with the five custody records, firmware, attestation, and signed QUIC observation derives the archive key. The AAD uses the frozen terminal event hash. This decrypts the candidate `AVLT10` archives into SQLite databases.

## Selecting the archive record and recovering the seal

The archive snapshots contain competing records. The record consistent with the captured production evidence is in archive object `5a2c8adef3c0846a2d0fb62d00844c64`, under transaction ID `6dd9ec588c9914ca95df44b2`. Its fields include:

| Field | Value |
|---|---|
| Origin | `OPS-17` |
| Version | `10` |
| Counter | `10450910` |
| Case commit | `b34dc728c1fa1525020b1969a8af2698b2bcd91a95d58b3e3b940de35deda6e1` |
| Release checkpoint | `5e4f78ad0e23d862a60ef8fca9891b47997dc1936043dd13efe419beaf7b3c53` |
| Receipt disposition | `accepted` |
| Observed state | `c358a8d65550291f281fb21927a04e3462d0d33e0063eb6594b21a79181007c9` |

The observed-state digest matches the codec value derived from the captured frame. Unmasking the transaction's four ordered fragments with the SDK yields material `4dd704d4c5097fff29ce7eb00b4b894f62e5db0661d988be2e8d790a601cf7a1`. The resulting fragment commitment matches the SQLite receipt (`135fc978199e3bfe153799de7e981b1753686a9c9c73c31693aa113abe4161a2`).

Combining that material with the evidence bytes, the frozen checkpoint signature, and the seal's salt derives the final key. Decrypting the AES-256-GCM seal with the SDK's prescribed AAD returns the flag above.

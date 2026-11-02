# Last Execution — Write-up

## Summary

The image is a custom EXE-9 virtual-machine snapshot, not a native executable. The useful path is:

```text
EXEC_MAIN → EXEC_FOLD_A → EXEC_FOLD_B → EXEC_LIMIT → EXEC_FINAL
```

The important traps are a stale primer, a misleading telemetry record, a fake test seal, and a very large loop. `EXEC_LIMIT` runs for `0x123456789abc` iterations, so it must be fast-forwarded by exploiting the loop’s periodic state. `EXEC_FINAL` uses a scratch counter to make one warm-up pass and then terminate on the next pass.

The final state is:

```text
R1 = 30677DF2A112FFFB
R2 = FF975FD2B1F15576
R3 = ABEC2195F731C083
R4 = 9C3FB793EED6DA86
R15 = 000000005354414C   ('STAL')
```

The derived seal key is `ac35ec6ed245d7238d9784ae097766613649315beb12b8ba9836dda56ccd54a3`.

**Flag:** `hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}`

## 1. Parse the image

The header begins with `EXE9CORE`. Its segment directory starts at `0x100`, uses `0x40`-byte records, and contains 24 entries. All multi-byte fields are big-endian. Checking each segment CRC is a useful first pass; the directory maps the code and data regions, including `DLOOK`, `DSEED`, `WILL_SEAL`, the four test seals, `TELEMETRY`, and the decoy artifacts.

The header entry is segment 1 (`EXEC_MAIN`). Segment IDs must be resolved through the directory rather than treated as directory indices.

## 2. Reconstruct the VM fetch and dispatch

The primer contains stale formulas. The dispatch trace provides a direct correction: at `EXEC_SELFTEST:0x40`, the decoded opcode byte is `0x93`, and the trace says the resulting index is `0xE2`. This works with the instruction number `pc >> 3`:

```text
idx = (op_byte + (pc >> 3) + AUX) & 0xff
0x93 + 8 + 0x47 = 0xe2  (LDRR)
```

Using `pc >> 4`, as printed in the primer, does not reproduce the trace or the self-test commitment. Fetch is a big-endian 64-bit word rotated left by the page’s rotation count. The main segment’s trace gives rotations `0, 57, 55`; decoding the instruction patterns and links identifies the remaining pages:

| Segment | Page rotations |
| --- | --- |
| `EXEC_MAIN` | `0, 57, 55, 1` |
| `EXEC_FOLD_A` | `51, 62, 54` |
| `EXEC_FOLD_B` | `34, 7, 29` |
| `EXEC_LIMIT` | `4, 27` |
| `EXEC_FINAL` | `21, 44, 58, 6, 10, 32, 37, 12, 11, 31, 22, 38, 2, 15` |
| `EXEC_SELFTEST` | `55, 28` |

The self-test ends with SHA-256 commitment `0b6d8d4770eac443de6b9b73340a4a262117d9da42e6ced9411ebda286bbbcf2`, confirming the dispatch, register semantics, and table reads.

## 3. Decode the tables and the real code chain

`LDRR` reads a big-endian word from a 64-byte logical table row. The DSEED encode-time trace is `31, 2d, 30, 16`; the row recurrence that reproduces it uses `+ i*13`, despite the primer’s `+ i*11`.

With the corrected dispatch and page rotations, execution links from `EXEC_MAIN` to `EXEC_FOLD_A`, then `EXEC_FOLD_B`, then `EXEC_LIMIT`. The `HALT` link is:

```text
next_id = imm32 XOR low32(R1)
```

The code’s repeated instruction patterns make the fold segments identifiable: they load four words per row, mix `R1..R4`, and loop over 0x400 rows.

## 4. Fast-forward `EXEC_LIMIT`

The limit segment constructs a loop count of `0x123456789abc`. Simulating every VM instruction is impractical, but the loop state is periodic:

- The low 18 bits of `R6` follow an LCG modulo `2^18`:
  `x = (x * 0x19660d + 0x3c6ef35f) mod 2^18`.
- `R5` advances by one modulo `2^15` because it adds `0x4001` and masks with `0x7fff`.
- `R12` tracks the carry events and resets at 3.
- `R8` accumulates a deterministic contribution from `R6`, `R5`, and `R12`.

The joint state repeats every `786432` iterations. Run one full period to obtain its `R8` delta, multiply by the number of complete periods, then simulate the remainder. This gives the exact loop result without executing trillions of steps.

## 5. Follow the scratch-counter halts

`EXEC_FINAL` is writable and persists a counter at address `0x2048`.

1. On the first final pass, the counter advances from 0 to 1. The code sets `low32(R1) = 0x5eed0001`; its HALT immediate `0x5eed0004` therefore links back to segment 5 (`EXEC_LIMIT`).
2. The second limit pass runs, then the final pass sees the persisted counter at 1 and advances it to 2. This selects the other low-word constant, `0xa112fffb`.
3. The final HALT now resolves to the chain terminator:

   ```text
   0x5eed0004 XOR 0xa112fffb = 0xffffffff
   ```

That is the genuine terminal halt. The `STAL` marker is set in `R15`.

## 6. Reject the planted telemetry and test seal

`TEST_SEAL_2` decrypts under the telemetry state to `hiCTF{f4k3_fl4g}`. That is a deliberate decoy. The telemetry’s `R2` also differs from the emulated terminal state by `0x1000`; its listed fold values therefore do not match the real terminal register file.

Derive the key from the actual terminal registers:

```text
SHA256("LASTEXEC" || BE64(R1) || BE64(R2) || BE64(R3) || BE64(R4) || "LASTEXEC")
```

For the S-box, concatenate the first four logical DLOOK rows and run the documented Fisher–Yates construction. Undo the WILL_SEAL column rotation, decrypt each 16-byte block with SEAL-256, and remove PKCS#7 padding. The plaintext is:

```text
hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}
```

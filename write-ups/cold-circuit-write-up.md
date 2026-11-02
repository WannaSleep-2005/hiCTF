# Cold Circuit — Write-up

## Challenge

The challenge provides a small stripped x86-64 ELF checker. It reads a candidate flag and prints `Access granted.` only when the candidate's transformed contents match an embedded 16-byte target.

## Input format

The checker requires an input of exactly 39 characters (excluding the line ending):

```text
hiCTF{<32 hexadecimal characters>}
```

It parses each pair of hexadecimal characters into one byte, producing a 16-byte block. The prefix and closing brace are checked separately.

## Reversing the validation

The checker applies 20 rounds to the parsed block. Each round uses a 16-byte round key and performs these operations:

1. Add the round key byte-by-byte modulo 256.
2. Replace each byte using the embedded 256-byte substitution table.
3. Rearrange bytes using the embedded 16-entry permutation.

The final block is compared with the embedded target:

```text
97 67 14 88 0a 50 0d 16 0a 21 f6 95 0e ef 34 81
```

Since the tables and round keys are stored in the binary, the transform can be inverted. Starting with the target and processing rounds in reverse:

1. Undo the permutation.
2. Apply the inverse substitution table.
3. Subtract the round key byte-by-byte modulo 256.

A small script can extract the constants from the `.rodata` section and run these inverse steps. The recovered 16 bytes are:

```text
6e 30 5f 6a 74 61 67 5f 6e 65 65 64 65 64 21 21
```

Their hexadecimal representation is the required flag body. The checker also calls `ptrace(PTRACE_TRACEME)` and flips a round-key byte when it detects tracing; running normally leaves the key unchanged.

## Flag

```text
hiCTF{6e305f6a7461675f6e65656465642121}
```

Running the checker with this input prints `Access granted.`

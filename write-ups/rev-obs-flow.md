# rev-obs-flow — Write-up

## Challenge

The provided ELF is a local passkey validator. Its success path decrypts a static blob and prints it only after the supplied key has passed a sequence of arithmetic and state-machine checks.

## Input format

The validator reads a line, strips trailing CR/LF bytes, checks that the last character is `}`, and requires the zero-based index of that character to be `0x2e`. The complete input must therefore be 47 characters:

```text
hiCTF{<40-character body>}
```

The prefix is checked with `strncmp`. The body is then interpreted as ten little-endian 32-bit words, which makes the four-character groups useful to reason about directly.

## Reversing the checks

The program’s flattened state machine can be followed by tracing the state IDs selected from the tables near `0x4030e0`–`0x403180`. Most table entries are decoys. Each valid state adds another condition on the input words.

### 1. First two words: `m4th_c0n`

The first gate works modulo `p = 0x7fffffff`. Let `a` and `b` be the little-endian values of the first two groups. It requires:

```text
(a × b) mod p = 0x37c0f52c
(a² mod p) - (31337 × (b² mod p) mod p) = 0x1e054920
```

Solving those equations gives:

```text
group 1: m4th  -> 0x6874346d
group 2: _c0n  -> 0x6e30635f
```

These values move execution from the initial state through `0x6b3e91f2` to `0x19c45d80`.

### 2. Elliptic-curve gate: `tr0l_fl0`

The next state uses point arithmetic modulo `q = 1,000,000,007` on the curve

```text
y² = x³ + 133742x + 812846519  (mod q)
```

The binary multiplies the fixed point `(123456789, 239241263)` by `1337`, then adds the point derived from the next two words. Reversing that addition gives the required input point:

```text
x = 815114349 (mod q)
 y = 812410463 (mod q)
```

The four-byte little-endian representations are `tr0l` and `_fl0`. The `tr0l` word is larger than `q`, but its residue is the required x-coordinate. This satisfies the curve check and selects state `0x43b7e025`.

### 3. Discrete-log gate: `w_3ll1pt`

The next state raises 7 and 11 to exponents taken from the next two 32-bit words, modulo `0x7fffffff`. The required residues are:

```text
7^e ≡ 0x7bb949ec  (mod 0x7fffffff)
11^f ≡ 0x0b3bbfc8 (mod 0x7fffffff)
```

Solving the discrete logarithms gives these little-endian word values:

```text
group 5: w_3l  -> 0x6c335f77
group 6: l1pt  -> 0x7470316c
```

They make both residuals zero and advance to state `0x51e29f3a`.

### 4. Linear modular gate: `1c_dlog_`

The following gate combines the next two words, `x` and `y`, using modulus `m = 0xfffffffb`. For the table lookup to select its real entry, both expressions must equal their embedded constants:

```text
123456789x + 555666777y ≡ 0x7da7aac3  (mod m)
  13374241x + 987654321y ≡ 0x92660155 (mod m)
```

Solving this 2×2 system yields:

```text
group 7: 1c_d -> 0x645f6331
group 8: log_ -> 0x5f676f6c
```

### 5. Final arithmetic and primality checks: `4f7b2c9e`

The final eight characters are two words. In addition to primality checks after XOR with `9` and `0x11`, the validator checks their sum and product modulo `0x7fffffff`:

```text
group 9:  4f7b -> 0x62376634
group 10: 2c9e -> 0x65396332

(group9 + group10) mod 0x7fffffff = 0x4770c967
(group9 × group10) mod 0x7fffffff = 0x2e97d196
```

Together these checks select the valid transition to the decryption state `0x38a5f41c`.

## Recovered passkey and flag

Concatenating the ten groups gives the passkey:

```text
hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}
```

Running it through the supplied binary produces:

```text
[+] ACCESS GRANTED! Passkey verified.
[+] Flag: hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}
```

The flag is the decrypted plaintext printed by the success path.

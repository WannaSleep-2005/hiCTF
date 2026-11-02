# Rocinate - write-up

**Flag:** `hiCTF{lmaoooo_w0t???y0u_d1d_17_??435p37++}`

## What is exposed

The challenge prints `a`, `b`, `N`, and 100 values each of `Z`, `C`, and `T`. The source shows that all of the random choices except the primes come from Python's module-level `random` generator, which is MT19937:

```python
r = random.randint(1, N)
e = random.randint(1, N)
a = random.randint(1, N)
b = random.randint(1, N)
Cs = [random.randint(1, N) for _ in range(n)]
```

The initial LCG state `r` is not printed. Recovering it is enough to regenerate every `R_i`; the masks then reveal powers of the flag integer.

## Recovering the Python RNG

Here `N.bit_length() == 2047`. In Python, `randint(1, N)` draws `x = getrandbits(2047)`, rejects `x >= N`, and returns `x + 1`. Thus each printed `C_i - 1` is a 2047-bit MT output. A 2047-bit `getrandbits` call consumes 64 consecutive 32-bit MT outputs: 63 complete words and 31 bits of the last word. The last word's low bit is hidden.

The samples `C_15` through `C_24` are ten consecutive accepted draws. Their 640 MT words give enough data to recover a 624-word MT state. I untemper the observed words and brute-force the nine missing low bits among the first 624 words; the matching assignment is `mask = 471`. Checking the remaining 16 bits of the tenth draw and then predicting all later `C` values, including rejected draws, identifies the right state.

I reverse the MT state transition to recover draws preceding `C_15`. Walking backward, a raw draw at least `N` is a rejected `randbelow` attempt. The accepted draws match the known `C` values, then the printed `b` and `a`; the next two accepted draws recover hidden `e` and initial state `r`.

## Recovering the flag

Regenerate the LCG states with

\[
R_{i+1} = (aR_i+b) \bmod N.
\]

The printed values satisfy

\[
Z_i = R_i s^{C_i} \pmod N,
\]

so, since each `R_i` is invertible modulo `N`,

\[
S_i = Z_i R_i^{-1} \bmod N = s^{C_i} \bmod N.
\]

The integer gcd of the 100 public exponents `C_i` is 1. Extended Euclid gives coefficients whose weighted sum of the `C_i` is 1. Applying the same coefficients as modular powers to the `S_i` therefore yields `s mod N`, directly recovering the flag. Neither factoring `N` nor using the hidden RSA exponent `e` is necessary.

## Verification

The recovered integer decodes to the flag above, starts with `hiCTF{` and ends with `}`. The solver checks that the cloned RNG predicts the remaining `C` values, that the recovered earlier draws match the printed `a` and `b`, and that the recovered `s` satisfies every equation `s^C_i = Z_i/R_i (mod N)`.


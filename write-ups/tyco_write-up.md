# tyco write-up

## Flag

`hiCTF{your_ai_slop_bores_me}`

## Idea

The challenge encrypts two related messages with the same RSA modulus and exponent:

\[
c_1 = r^e \bmod N, \qquad c_2 = (r+d)^e \bmod N.
\]

Here `d` is disclosed. Define polynomials over \(\mathbb{Z}/N\mathbb{Z}\):

\[
f(x)=x^e-c_1, \qquad g(x)=(x+d)^e-c_2.
\]

The flag integer `r` is a root of both polynomials, so their common factor is \(x-r\). Computing their polynomial GCD (the Franklin–Reiter related-message attack) recovers `r` without factoring `N`.

The exponent in this instance is 56,263, so the ordinary Euclidean sequence takes many steps. The script below uses python-flint's fast polynomial remainder operation directly; its built-in GCD routine rejects composite moduli. Each division succeeded because the divisor's leading coefficient was invertible modulo `N` for this instance.

## Solver

Install `python-flint`, then use the values from `chall.txt`:

```python
from flint import fmpz_mod_poly_ctx

N = 6473367999588815881004572026588101750789079445857778536811168773336769104246291698373278825101339166586003503710113510158959567754294313663054146192986157
e = 56263
d = 2035764493091178624712794329705995870572416764083820061256032842991849492659098525475022938791830969705210788470345958581547703841173518982860845498416721
c1 = 5781684316211813340099872158841814667969949431547126810872317404279855836615577909943707949461944016952363993351117294907803807466967042600735326571642750
c2 = 5259035151262072090045557031571853293994610739483317199715493584749958652346593143297235904086846475896963065621327693095317182721586618178754533498537529

R = fmpz_mod_poly_ctx(N)
x = R.gen()
f = x**e - c1
g = (x + d)**e - c2

while g:
    f, g = g, f % g

# f = a*x + b, so its root is -b/a modulo N.
r = (-int(f[0]) * pow(int(f[1]), -1, N)) % N
flag = r.to_bytes((r.bit_length() + 7) // 8, "big")
print(flag.decode())

# Verify against both supplied ciphertexts.
assert pow(r, e, N) == c1
assert pow(r + d, e, N) == c2
```

The recovered integer is

```text
10995781022013361699631792555502989853144280540708804918390675039613
```

and both assertions pass.

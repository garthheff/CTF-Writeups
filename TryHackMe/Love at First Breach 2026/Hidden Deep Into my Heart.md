# Deep Into my Heart

Room: https://tryhackme.com/room/lafb2026e9

## Scenario

Cupid's Vault was designed to protect secrets meant to stay hidden forever. Intelligence suggests Cupid may have unintentionally left vulnerabilities in the system.

Your task is to investigate the web application and retrieve the hidden flag.

---

# 1. Initial Enumeration

The first step was checking common discovery locations such as **robots.txt**.

```
http://10.64.182.141:5000/robots.txt
```

Contents:

```
User-agent: *
Disallow: /cupids_secret_vault/*

# cupid_arrow_2026!!!
```

### Findings

Two interesting things were revealed

1. A hidden directory

```
/cupids_secret_vault/
```

2. A comment containing what appears to be a password

```
cupid_arrow_2026!!!
```

In real environments passwords are rarely exposed like this, but CTF challenges often include hints in comments.

---

# 2. Directory Enumeration

Next step was to enumerate the newly discovered directory.

Command used

```
gobuster dir \
-u http://10.64.182.141:5000/cupids_secret_vault \
-w /usr/share/wordlists/dirb/common.txt
```

Results

```
/administrator (Status: 200)
```

This revealed an **administrator login page**.

---

# 3. Login Testing

Navigate to

```
http://10.64.182.141:5000/cupids_secret_vault/administrator
```

Given the suspicious comment found earlier in `robots.txt`, the value `cupid_arrow_2026!!!` was tested as a password.

Attempted credentials

```
username: cupid
password: cupid_arrow_2026!!!
```

Result

```
Login failed
```

Trying another likely username

```
username: admin
password: cupid_arrow_2026!!!
```

Result

```
Login successful
```

---

# 4. Flag Retrieval

After successfully logging in as **admin**, the flag was revealed.

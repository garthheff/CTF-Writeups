# Internal

Penetration Testing Challenge

Room: https://tryhackme.com/room/internal

Walkthrough: https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/hard/internal.md

---

<details>
<summary>Hint 1</summary>

Pay close attention to the room instructions. The target hostname matters.

</details>

---

<details>
<summary>Hint 2</summary>

Make sure the hostname from the room resolves to the target IP before doing web enumeration.

</details>

---

<details>
<summary>Hint 3</summary>

The initial port scan has a small attack surface. Focus on the web service.

</details>

---

<details>
<summary>Hint 4</summary>

The web root may not contain the real application. Look for hidden directories or common CMS paths.

</details>

---

<details>
<summary>Hint 5</summary>

A WordPress installation is present, but not at the web root.

</details>

---

<details>
<summary>Hint 6</summary>

Enumerate WordPress users before attempting authentication attacks.

</details>

---

<details>
<summary>Hint 7</summary>

One WordPress user has a weak password from a common wordlist.

</details>

---

<details>
<summary>Hint 8</summary>

After getting into WordPress as a privileged user, look for a feature that allows editing server-side files.

</details>

---

<details>
<summary>Hint 9</summary>

A theme PHP file can be modified to prove command execution.

</details>

---

<details>
<summary>Hint 10</summary>

Once command execution works, turn it into an interactive shell as the web server user.

</details>

---

<details>
<summary>Hint 11</summary>

WordPress configuration files often contain database credentials.

</details>

---

<details>
<summary>Hint 12</summary>

The database is worth checking, but it is not the main escalation path.

</details>

---

<details>
<summary>Hint 13</summary>

Look around common non-web directories for notes left by users or admins.

</details>

---

<details>
<summary>Hint 14</summary>

A file under `/opt` contains credentials for a local user.

</details>

---

<details>
<summary>Hint 15</summary>

Use the recovered local-user credentials to move from the web server account to a real system user.

</details>

---

<details>
<summary>Hint 16</summary>

The user’s home directory contains both the first flag and a clue about an internal service.

</details>

---

<details>
<summary>Hint 17</summary>

The internal service is not directly exposed externally. You need to access it through the compromised host.

</details>

---

<details>
<summary>Hint 18</summary>

Use local port forwarding to reach the internal service from your browser.

</details>

---

<details>
<summary>Hint 19</summary>

Known reused credentials do not work for the internal service. Try a small, targeted username list with a common password list.

</details>

---

<details>
<summary>Hint 20</summary>

One of the service accounts has a very weak password.

</details>

---

<details>
<summary>Hint 21</summary>

After logging in to the internal service, look for an administrative feature that can execute scripts.

</details>

---

<details>
<summary>Hint 22</summary>

Use the script execution feature to confirm the user context and hostname.

</details>

---

<details>
<summary>Hint 23</summary>

The shell from this service lands inside a container, not directly on the host.

</details>

---

<details>
<summary>Hint 24</summary>

Search the container filesystem for notes or credentials.

</details>

---

<details>
<summary>Hint 25</summary>

A note inside the container contains credentials for the host’s root account.

</details>

---

<details>
<summary>Hint 26</summary>

Return to the host shell as the local user and use the recovered root credentials.

</details>

---

<details>
<summary>Hint 27</summary>

The final flag is in the usual root-only location.

</details>

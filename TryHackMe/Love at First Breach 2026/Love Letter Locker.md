# Love Letter Locker

Room: [https://tryhackme.com/room/lafb2026e2](https://tryhackme.com/room/lafb2026e2)

## ⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution:  
https://github.com/garthheff/CTF-Hints/blob/main/Love%20at%20First%20Breach%202026%20%20/Love%20Letter%20Locker.md


## Scenario

**Love Letter Locker** is a web app that lets users write and store Valentine’s letters.

From the challenge description alone, the phrase _“For your eyes only?”_ strongly hints that the vulnerability may involve **access control**, which makes **IDOR** a good thing to test early.

---

## Walkthrough

1. Create an account.
2. Log in to the application.
3. Send yourself a letter.
4. Open the saved letter and observe the URL format:

   `http://10.64.159.54:5000/letter/3`

5. Change the numeric ID in the URL to another value, such as:

   `http://10.64.159.54:5000/letter/1`

6. The application returns a letter that does not belong to your account, confirming an **IDOR** vulnerability.

---

## What happened

The application uses a direct object reference in the URL:

`/letter/<id>`

Instead of verifying that the currently logged-in user is authorized to access that specific letter, the server simply loads whichever letter ID is requested.

That means any user can change the ID in the URL and access other users’ private letters.

---

## Vulnerability

**Insecure Direct Object Reference**  
Also commonly referred to in modern API and app security as **Broken Object Level Authorization**.

---

## Why this works

The application appears to rely on the letter’s numeric identifier alone, without enforcing ownership checks on the backend.

A secure implementation should validate that:

- the requested letter exists
- the current user is allowed to access it
- unauthorized requests are denied

---

## Remediation

To fix this issue, the server should enforce authorization checks every time a letter is accessed.

For example, when a request is made for `/letter/1`, the application should confirm that letter `1` belongs to the currently authenticated user before returning it.

Other helpful improvements include:

- using non-predictable identifiers
- logging unauthorized access attempts
- testing access control on every sensitive object

---

## Summary

This challenge is a straightforward example of **IDOR**.

The clue was in the description, and testing by simply changing the object ID in the URL was enough to access another user’s letter.

Sometimes the easiest findings are the right ones.

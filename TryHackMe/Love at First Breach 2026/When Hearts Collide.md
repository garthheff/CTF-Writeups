# When Hearts Collide

Room: [https://tryhackme.com/room/lafb2026e1](https://tryhackme.com/room/lafb2026e1)

## ⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution:  
https://github.com/garthheff/CTF-Hints/blob/main/Love%20at%20First%20Breach%202026%20%20/When%20Hearts%20Collide.md

---

# Scenario

**Matchmaker** is a playful web application that pairs you with a dog by comparing **MD5 hashes** of uploaded images.

Upload a photo and the application generates an MD5 fingerprint.
If the fingerprint matches one of the hashes in their curated dog database, you get a **match**.

The challenge description hints that the algorithm is transparent and deterministic.

The room title also contains an important clue:

**“When Hearts Collide”**

---

# Initial Analysis

The keyword **Collide** strongly suggests a **hash collision attack**.

MD5 is known to be vulnerable to **collision attacks**, meaning two completely different files can produce the **same MD5 hash**.

However, simply uploading the **same image twice** does not work because the application detects duplicate uploads.

So the goal becomes:

> Upload **two different images with the same MD5 hash**.

---

# Finding MD5 Collision Files

Rather than generating a collision ourselves, we can use publicly available examples.

One well known example is from:

[https://natmchugh.blogspot.com/2015/02/create-your-own-md5-collisions.html](https://natmchugh.blogspot.com/2015/02/create-your-own-md5-collisions.html)

The article provides two images:

* `ship.jpg`
* `plane.jpg`

They are visually different but share the **same MD5 hash**.

---

# Verifying the Collision

We verify locally:

```
md5sum ship.jpg
253dd04e87492e4fc3471de5e776bc3d  ship.jpg

md5sum plane.jpg
253dd04e87492e4fc3471de5e776bc3d  plane.jpg
```

Both images produce the **same MD5 hash**, confirming the collision.

---

# Exploiting the Application

1. Upload `ship.jpg`
2. The application computes the MD5 and stores the hash
3. No match is found

Next:

4. Upload `plane.jpg`
5. The MD5 is identical to the previous upload
6. The application thinks the images are a match

Since the hashes collide, the application triggers the **match condition** and reveals the **flag**.

---

# Root Cause

The vulnerability exists because the application relies on **MD5 for identity comparison**.

MD5 is cryptographically broken and allows attackers to craft two different files with the **same hash value**.

Because the application compares hashes instead of verifying file integrity, an attacker can bypass the logic using a **collision attack**.

---

# Key Lesson

Never use **MD5 for security-sensitive operations** such as identity checks or file validation.


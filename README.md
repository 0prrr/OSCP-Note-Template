# OSCP-Note-Template

Exam note template for OSCP.

# Read Me First

There are two templates, one for Linux and one for Windows.

They provide you with a check list for information gathering.

Go through them one by one, and you may need to come back and re-do the list as needed (if get stuck in exam).

# Linux Template

# Overview

- OS
    
    ```
    # Result:
    
    ```
    
- Overall Type
    - 
    
- Creds
    
    ```
    # Result:
    
    ```

# Enumeration

| Ports Open |  |
| --- | --- |

## FTP Port 21

Try default credentials. anonymous? guest:guest? admin:admin? root:root?

Banner

```
# Result:

```

Nmap script scan

```
# Result:

```

Brute force

```
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp -vV -f

# Result:

```

Can upload file?

```
# Result:

```

Pubic vulnerability?

```
# Result:

```

## SSH Port 22

Banner. Is the version vulnerable?

```
# Result:

```

Additional info (ssh root@ip)

```
# Result:

```

User name found? Try machine name? username:username? username:hostname?

```
# Result:

```

## SMTP Port 25

Banner

```
# Result:

```

Nmap script scan

```
# Result:

```

Got usernames? Username enum?

```
# generate usernames first with usernamer.py

# smtp-user-enum

# don't forget username as password

# Result:

```

Public vulnerability?

```
# Result:

```

## DNS (Optional)

Subdomains?

```
# Result:

```

Zone Transfer?

```
# Result:

```

## HTTP Port 80

### Home Page (A screenshot will do)

### Need info for brute forcing? DON’T FORGET cewl!!!

### Third Party Web App? Public Vulnerability?

```
# Result:

```

### robots.txt

```
# Result:

```

### dirb/gobuster (common.txt, dirbuster-medium.txt)

```
# Result:

```

With domain name? vhost?

```
# Result:

```

### Backend Techstack/whatweb

```
whatweb -a 3 http://ip

# Result:

```

### 403

Simple Bypass?

```
# Result:

```

### 404

Any interesting information?

```
# Result:

```

### index.html/php? (gobuster with -x)

```
# Result:

```

### Source Code

Anything interesting?

```
# Result:

```

### Burp Traffic

```
# Result:

```

Command injection? Change request method?

```
# Result:

```

### nikto

```
# Result:

```

### Apache? cgi-bin?

```
# Result:

```

### Check Cookies

Anything interesting? Base64? JWT?

```
# Result:

```

### User Input Fields? SQLi?

```
# Result:

```

Can you lock the account out?

```
# Result:

```

### phpinfo()?

Server document root

```
# Result:

```

url open settings

```
# Result:

```

### LFI?RFI?

```
# Result:

```

### Users found? SSH open? Brute force?

```
# Result:

```

## Ident Port 113

Identify username

```
ident-user-enum <target-ip> <port-list>

# Result:

```

## SMB Port 139, 445

Null session?

```
# Result:

```

Can list shares?

```
# Result:

```

Nmap script scan:

```
# Result:

```

Version < 2.2.8? Cannot get version? Try wireshark? [https://www.exploit-db.com/exploits/10](https://www.exploit-db.com/exploits/10)

```
# Result:

```

enum4linux

```
# Result:

```

Anonymous login?

```
# Result:

```

Files

```
# Result:

```

## MySQL Port 3306

Banner

```
# Result:

```

Nmap script scan

```
# Result:

```

Default credential:

```
root:(empty)
root:root

# Result:

```

Brute force???

```
# Result:

```

## Postgresql Port 5432

Default credential:

```
postgres:postgres
postgres:(empty)

# Result:
```

# Foothold

Local proof

```
# Result:

```

# Privilege Escalation

## whoami

```
# Result:

```

## id

```
# Result:

```

## hostname

```
# Result:

```

## uname -a

```
# Result:

```

## cat /etc/*-release

```
# Result:

```

### SSH motd info

```
# Result:

```

## env

```
# Result:

```

## sudo version

```
sudo -V

# Result:
```

## sudo -l

```
sudo -l

# Result:

```

## Crontab

Any interesting PATH?

```
cat /etc/cron*

# Result:

```

## Processes

```
ps aux | grep root

# Result:

```

## fstab

```
cat /etc/fstab

# Result:

```

## SUID

```
find / -perm -04000 -type f 2>/dev/null

# Result:

```

## Capability

```
getcap -r / 2>/dev/null

# Result:

```

## /etc/passwd

```
grep -vE "nologin|false" /etc/passwd;ls -al /etc/passwd

# Result:

```

Users on target

```
# Result:

```

/etc/passwd file permission

```
# Result:

```

## /etc/shadow

/etc/shadow file permission

```
ls -al /etc/shadow

# Result:

```


## netstat/ss

Command

```
netstat -antlp
ss -antlp

# Result:

```

## Writable Files (grep -v for filtering)

Command

```
find / -writable -type f 2>/dev/null

# Result:

```

## Writable Dirs (grep -v for filtering)

```
find / -writable -type d 2>/dev/null

# Result:

```


## Home Dir Files

### Shell Script? Python? Any Source Code Worth Reading?

```
# Result:

```

### bash_history

```
cat ~/.bash_histroy

# Result:

```

### .ssh

```
# Result:

```

### Web server log files? Traffic come from?

```
# Result:

```

## LinPEAs

```
# Result:

```

## Pspy

```
# Result:

```

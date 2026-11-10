#!/usr/bin/env bash
# hardening-check.sh — read-only security audit for Ubuntu 26.04 LTS
# Companion to Ubuntu-26.04-Hardening-Checklist.xlsx
#
# Usage:
#   sudo bash hardening-check.sh [--port 2222] [--allow "80 443"] [--admins "james"] [--lynis]
#
#   --port    SSH port you expect the server to use (default 22)
#   --allow   other TCP/UDP ports that may be open to the network (default "80 443")
#   --admins  users who should be in the sudo group (default: not checked)
#   --lynis   also run a full Lynis audit (takes a few minutes)
#
# Output lines look like:  ID|RESULT|DETAIL   (RESULT = PASS, FAIL, WARN, MANUAL or VALUE)
# Paste the whole output into the "Import" sheet of the workbook.
# The script changes nothing on the system (apt-get update refreshes the package list only).

SSH_PORT=22
ALLOW_PORTS="80 443"
ADMINS=""
RUN_LYNIS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port)   SSH_PORT="$2"; shift 2 ;;
    --allow)  ALLOW_PORTS="$2"; shift 2 ;;
    --admins) ADMINS="$2"; shift 2 ;;
    --lynis)  RUN_LYNIS=1; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root:  sudo bash $0 $*" >&2
  exit 1
fi

OUT="hardening-results-$(hostname -s)-$(date +%Y%m%d-%H%M).txt"
exec > >(tee "$OUT")

clean() { tr '\n|' ' /' | tr -s ' ' | cut -c1-240; }
emit()  { printf '%s|%s|%s\n' "$1" "$2" "$(printf '%s' "$3" | clean)"; }
pass()  { emit "$1" PASS   "$2"; }
fail()  { emit "$1" FAIL   "$2"; }
warn()  { emit "$1" WARN   "$2"; }
man()   { emit "$1" MANUAL "$2"; }
val()   { emit "$1" VALUE  "$2"; }
have()  { command -v "$1" >/dev/null 2>&1; }
in_list() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }

emit HOST VALUE "$(hostname -f 2>/dev/null || hostname)"
emit DATE VALUE "$(date '+%Y-%m-%d %H:%M')"
emit OS   VALUE "$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME") kernel $(uname -r)"
emit ARGS VALUE "port=$SSH_PORT allow=$ALLOW_PORTS admins=${ADMINS:-unset}"

# ---------- 0. Safety ----------
man 0.1 "Confirm a second SSH session is open before changing SSH or firewall"
man 0.2 "Confirm console / rescue access works"
if ls -d /etc/ssh.bak-* >/dev/null 2>&1; then
  pass 0.3 "Backups found: $(ls -d /etc/ssh.bak-* | tail -1)"
else
  warn 0.3 "No /etc/ssh.bak-* backup found"
fi

# ---------- 1. Updates ----------
apt-get update -qq >/dev/null 2>&1
UPG=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ')
if [ "$UPG" -eq 0 ]; then pass 1.1 "No pending upgrades"; else fail 1.1 "$UPG package(s) can be upgraded"; fi

if [ -f /var/run/reboot-required ]; then
  fail 1.2 "Reboot required: $(cat /var/run/reboot-required.pkgs 2>/dev/null | sort -u | head -5)"
else
  pass 1.2 "Running kernel $(uname -r); no reboot pending"
fi

UU_EN=$(systemctl is-enabled unattended-upgrades 2>/dev/null)
UU_CFG=$(apt-config dump 2>/dev/null | grep -c 'APT::Periodic::Unattended-Upgrade "1"')
if [ "$UU_EN" = "enabled" ] && [ "$UU_CFG" -gt 0 ]; then
  pass 1.3 "unattended-upgrades enabled"
else
  fail 1.3 "service=${UU_EN:-missing} periodic-config=$UU_CFG"
fi

# ---------- 2. Packages ----------
AR=$(apt-get -s autoremove 2>/dev/null | grep -c '^Remv ')
if [ "$AR" -eq 0 ]; then pass 2.1 "Nothing to autoremove"; else warn 2.1 "$AR package(s) can be autoremoved"; fi

RISKY=""
for p in telnetd telnet rsh-client rsh-server ftp vsftpd xinetd nis talk talkd avahi-daemon cups; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' && RISKY="$RISKY $p"
done
if [ -z "$RISKY" ]; then pass 2.2 "None of the risky packages installed"; else fail 2.2 "Installed:$RISKY"; fi

ENS=$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//')
man 2.3 "$(echo "$ENS" | wc -l) enabled: $(echo $ENS)"

# ---------- 3/4. SSH ----------
if have sshd; then
  SSHT=$(sshd -T 2>/dev/null)
  sv() { echo "$SSHT" | awk -v k="$1" '$1==k{ $1=""; sub(/^ /,""); print; exit }'; }

  man 3.1 "From your laptop: ssh -o PasswordAuthentication=no -p $SSH_PORT user@server"

  PA=$(sv passwordauthentication); KI=$(sv kbdinteractiveauthentication)
  if [ "$PA" = "no" ] && [ "$KI" = "no" ]; then pass 3.2 "passwordauthentication=no kbdinteractive=no"
  else fail 3.2 "passwordauthentication=$PA kbdinteractiveauthentication=$KI"; fi

  OVR=$(grep -rliE '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null)
  if [ -z "$OVR" ]; then pass 3.3 "No file sets PasswordAuthentication yes"; else fail 3.3 "Sets yes: $OVR"; fi

  BAD=""; CHECKED=""
  for u in $(getent group sudo | cut -d: -f4 | tr ',' ' ') root; do
    h=$(getent passwd "$u" | cut -d: -f6); [ -d "$h/.ssh" ] || continue
    CHECKED="$CHECKED $u"
    m=$(stat -c %a "$h/.ssh"); [ "$m" = "700" ] || BAD="$BAD $u:.ssh=$m"
    if [ -f "$h/.ssh/authorized_keys" ]; then
      m=$(stat -c %a "$h/.ssh/authorized_keys"); case "$m" in 600|400) ;; *) BAD="$BAD $u:authorized_keys=$m" ;; esac
      o=$(stat -c %U "$h/.ssh/authorized_keys"); [ "$o" = "$u" ] || BAD="$BAD $u:owner=$o"
    fi
  done
  if [ -z "$CHECKED" ]; then man 3.4 "No ~/.ssh found for sudo users"
  elif [ -z "$BAD" ]; then pass 3.4 "OK for:$CHECKED"
  else fail 3.4 "$BAD"; fi

  LISTEN=$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')
  SOCK=$(systemctl is-active ssh.socket 2>/dev/null)
  if in_list "$SSH_PORT" "$LISTEN"; then
    if [ "$SSH_PORT" != "22" ] && in_list 22 "$LISTEN"; then
      warn 4.1 "Listening on $SSH_PORT but 22 still open (ssh.socket=$SOCK)"
    else
      pass 4.1 "Listening on $SSH_PORT (ssh.socket=$SOCK)"
    fi
  else
    fail 4.1 "Nothing listening on $SSH_PORT; sshd_config port=$(sv port) ssh.socket=$SOCK"
  fi

  PR=$(sv permitrootlogin)
  if [ "$PR" = "no" ]; then pass 4.2 "permitrootlogin=no"; else fail 4.2 "permitrootlogin=$PR"; fi

  AU=$(sv allowusers); AG=$(sv allowgroups)
  if [ -n "$AU$AG" ]; then pass 4.3 "allowusers=$AU allowgroups=$AG"; else fail 4.3 "No AllowUsers / AllowGroups set"; fi

  MT=$(sv maxauthtries); LG=$(sv logingracetime); CI=$(sv clientaliveinterval); XF=$(sv x11forwarding)
  P44=""
  [ "${MT:-99}" -le 4 ]  || P44="$P44 maxauthtries=$MT"
  [ "${LG:-999}" -le 60 ] || P44="$P44 logingracetime=$LG"
  { [ "${CI:-0}" -gt 0 ] && [ "${CI:-0}" -le 600 ]; } || P44="$P44 clientaliveinterval=$CI"
  [ "$XF" = "no" ] || P44="$P44 x11forwarding=$XF"
  if [ -z "$P44" ]; then pass 4.4 "maxauthtries=$MT logingracetime=$LG clientalive=$CI x11=$XF"
  else fail 4.4 "Needs change:$P44"; fi

  if ERR=$(sshd -t 2>&1); then pass 4.5 "sshd -t OK"; else fail 4.5 "$ERR"; fi
else
  for i in 3.1 3.2 3.3 3.4 4.1 4.2 4.3 4.4 4.5; do man "$i" "openssh-server not installed"; done
fi

# ---------- 5. Firewall ----------
if have ufw; then
  UV=$(ufw status verbose 2>/dev/null)
  if echo "$UV" | grep -q 'Status: active' && echo "$UV" | grep -q 'deny (incoming)'; then
    pass 5.1 "UFW active, default deny incoming"
  else
    fail 5.1 "$(echo "$UV" | grep -E '^(Status|Default):')"
  fi

  RULES=$(ufw status 2>/dev/null | awk 'NR>4 && $0!~/\(v6\)/ && NF>0 {print $1}' | sed 's#/.*##' | sort -u)
  EXTRA=""
  for r in $(echo $RULES | tr "," " "); do in_list "$r" "$SSH_PORT $ALLOW_PORTS" || EXTRA="$EXTRA $r"; done
  if echo "$UV" | grep -q 'Status: active'; then
    if [ -z "$EXTRA" ]; then pass 5.2 "Allowed: $(echo $RULES)"; else warn 5.2 "Not in allow list:$EXTRA"; fi
  else
    fail 5.2 "UFW inactive"
  fi

  SR=$(ufw status 2>/dev/null | grep -E "^${SSH_PORT}(/tcp)?[[:space:]]" | grep -v '(v6)' | head -1)
  if echo "$SR" | grep -q 'LIMIT'; then pass 5.3 "$SR"
  elif [ -n "$SR" ] && ! echo "$SR" | grep -q 'Anywhere'; then pass 5.3 "Source-restricted: $SR"
  elif [ -n "$SR" ]; then warn 5.3 "Open to anywhere, not rate-limited: $SR"
  else fail 5.3 "No UFW rule for port $SSH_PORT"; fi
else
  fail 5.1 "ufw not installed"; fail 5.2 "ufw not installed"; fail 5.3 "ufw not installed"
fi

# ---------- 6. Fail2ban ----------
FA=$(systemctl is-active fail2ban 2>/dev/null); FE=$(systemctl is-enabled fail2ban 2>/dev/null)
if [ "$FA" = "active" ] && [ "$FE" = "enabled" ]; then pass 6.1 "fail2ban active/enabled"
else fail 6.1 "active=${FA:-missing} enabled=${FE:-missing}"; fi

if have fail2ban-client && fail2ban-client status sshd >/dev/null 2>&1; then
  JP=$(grep -rhE '^\s*port\s*=' /etc/fail2ban/jail.local /etc/fail2ban/jail.d/ 2>/dev/null | tr -d ' ' | head -3 | tr '\n' ' ')
  if [ "$SSH_PORT" = "22" ] || echo "$JP" | grep -q "$SSH_PORT"; then
    pass 6.2 "sshd jail active ($(fail2ban-client status sshd | grep 'Total banned' | xargs)) $JP"
  else
    warn 6.2 "sshd jail active but port $SSH_PORT not found in jail config ($JP)"
  fi
else
  fail 6.2 "sshd jail not active"
fi

# ---------- 7. Accounts ----------
RS=$(passwd -S root 2>/dev/null | awk '{print $2}')
if [ "$RS" = "L" ]; then pass 7.1 "root password locked"; else fail 7.1 "root status=$RS"; fi

SG=$(getent group sudo | cut -d: -f4 | tr ',' ' ')
if [ -n "$ADMINS" ]; then
  X=""; for u in $SG; do in_list "$u" "$ADMINS" || X="$X $u"; done
  if [ -z "$X" ]; then pass 7.2 "sudo group: $SG"; else fail 7.2 "Unexpected sudo members:$X"; fi
else
  man 7.2 "sudo group: ${SG:-empty} (use --admins to auto-check)"
fi

U0=$(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' ')
if [ "$U0" = "root " ]; then pass 7.3 "Only root has UID 0"; else fail 7.3 "UID 0: $U0"; fi

EP=$(awk -F: '$2==""{print $1}' /etc/shadow | tr '\n' ' ')
if [ -z "$EP" ]; then pass 7.4 "No empty passwords"; else fail 7.4 "Empty password: $EP"; fi

# ---------- 8. Open ports ----------
PUB=""; DB=""
while read -r proto addr; do
  port=${addr##*:}; host=${addr%:*}
  case "$host" in 127.*|"[::1]"|::1) continue ;; esac
  case "$port" in 3306|5432|6379|27017|11211) DB="$DB $proto/$port" ;; esac
  in_list "$port" "$SSH_PORT $ALLOW_PORTS" || PUB="$PUB $proto/$port"
done < <(ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u)
PUB=$(echo $PUB | tr ' ' '\n' | sort -u | xargs)
if [ -n "$DB" ]; then fail 8.1 "Database port on network:$DB"
elif [ -z "$PUB" ]; then pass 8.1 "Only expected ports listening ($SSH_PORT $ALLOW_PORTS)"
else warn 8.1 "Unexpected listeners: $PUB"; fi
man 8.2 "From another host: nmap -Pn <server-ip>"

# ---------- 9. Kernel ----------
SYSCTLS="net.ipv4.tcp_syncookies=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.all.accept_source_route=0 net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1 net.ipv4.icmp_echo_ignore_broadcasts=1 net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0 kernel.randomize_va_space=2 kernel.kptr_restrict=2 kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=1 kernel.unprivileged_bpf_disabled=1,2 net.core.bpf_jit_harden=2
fs.protected_hardlinks=1 fs.protected_symlinks=1 fs.suid_dumpable=0"
MIS=0; TOT=0
for kv in $SYSCTLS; do
  k=${kv%%=*}; want=${kv#*=}; TOT=$((TOT+1))
  got=$(sysctl -n "$k" 2>/dev/null | xargs); [ -z "$got" ] && got="n/a"
  val "$k" "$got"
  case ",$want," in *",$got,"*) ;; *) MIS=$((MIS+1)) ;; esac
done
if [ "$MIS" -eq 0 ]; then pass 9.1 "All $TOT sysctl values match"
else fail 9.1 "$MIS of $TOT sysctl values differ (see Sysctl Reference sheet)"; fi

if have aa-status && aa-status --enabled 2>/dev/null; then
  pass 9.2 "AppArmor enabled, $(aa-status 2>/dev/null | grep -m1 'profiles are in enforce mode')"
else
  fail 9.2 "AppArmor not enabled"
fi

# ---------- 10. Auditd ----------
AA=$(systemctl is-active auditd 2>/dev/null); AE=$(systemctl is-enabled auditd 2>/dev/null)
if [ "$AA" = "active" ] && [ "$AE" = "enabled" ]; then pass 10.1 "auditd active/enabled"
else fail 10.1 "active=${AA:-missing} enabled=${AE:-missing}"; fi

if have auditctl; then
  AR=$(auditctl -l 2>/dev/null); MISS=""
  for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config; do
    echo "$AR" | grep -q -- "$f" || MISS="$MISS $f"
  done
  if [ -z "$MISS" ]; then pass 10.2 "All key files watched"; else fail 10.2 "Not watched:$MISS"; fi
else
  fail 10.2 "auditctl not installed"
fi

# ---------- 11. SUID / SGID / world-writable ----------
KNOWN_SUID="sudo sudo.ws sudo-rs su passwd chsh chfn newgrp gpasswd mount umount fusermount fusermount3 pkexec ping
ssh-keysign dbus-daemon-launch-helper polkit-agent-helper-1 snap-confine unix_chkpwd chage expiry
crontab ssh-agent at pam_extrausers_chkpwd utempter wall write bsd-write dotlockfile plocate mlocate locate ntfs-3g Xorg.wrap dmcrypt-get-device"
UNK=""; N=0
for f in $(find / -xdev -perm -4000 -type f 2>/dev/null); do
  N=$((N+1)); in_list "$(basename "$f")" "$(echo $KNOWN_SUID)" || UNK="$UNK $f"
done
if [ -z "$UNK" ]; then pass 11.1 "$N SUID files, all standard"; else warn 11.1 "Review:$UNK"; fi

UNK=""; N=0
for f in $(find / -xdev -perm -2000 -type f 2>/dev/null); do
  N=$((N+1)); in_list "$(basename "$f")" "$(echo $KNOWN_SUID)" || UNK="$UNK $f"
done
if [ -z "$UNK" ]; then pass 11.2 "$N SGID files, all standard"; else warn 11.2 "Review:$UNK"; fi

WW=$(find / -xdev -type f -perm -0002 ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/dev/shm/*' 2>/dev/null)
WN=$(echo "$WW" | grep -c .)
if [ "$WN" -eq 0 ]; then pass 11.3 "No world-writable files"; else fail 11.3 "$WN file(s): $(echo $WW | cut -c1-150)"; fi

# ---------- 12. Lynis ----------
if [ "$RUN_LYNIS" -eq 1 ] && have lynis; then
  lynis audit system --quiet --no-colors >/dev/null 2>&1
fi
if [ -f /var/log/lynis-report.dat ]; then
  LD=$(stat -c %y /var/log/lynis-report.dat | cut -d' ' -f1)
  WARNS=$(grep -c '^warning\[\]=' /var/log/lynis-report.dat)
  pass 12.1 "Report from $LD, $WARNS warning(s)"
  HI=$(grep '^hardening_index=' /var/log/lynis-report.dat | cut -d= -f2)
  if [ "${HI:-0}" -ge 70 ]; then pass 12.2 "hardening_index=$HI"; else warn 12.2 "hardening_index=$HI"; fi
else
  if have lynis; then man 12.1 "Run: sudo lynis audit system (or re-run this script with --lynis)"
  else man 12.1 "Install: sudo apt install lynis -y"; fi
  man 12.2 "No Lynis report yet"
fi

echo "END|VALUE|Saved to $(pwd)/$OUT"

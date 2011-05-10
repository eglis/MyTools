#!/usr/bin/perl
#
#
# Charles Lacroix ( charles.lacroix@gmail.com )
#
# Based on NSA rhel5 security guide here is the things i
# commonly use on my systems.
#
#

print "All good until i finish my script\n";
exit 0;


# 2.1.1.1 Disk Partitionning
#
# Make sure /, /boot are on seperate partitions
#
# 2.1.1.1.1
# Make sure /tmp has it's own partition.
#
# 2.1.1.1.2 
# Make sure /var has it's own partition
#
# 2.1.1.1.3
# Make sure /var/log has it's own partition
#
# 2.1.1.1.4
# Make sure /var/log/audit has it's own partition
#
# 2.1.1.1.5 /home has it's own partition
#
# * /
# * /boot
#   /home
# * /tmp
#   /var
#   /var/log
#   /var/log/audit
#

# 2.1.1.2 Boot Loader config
# Check that grub has a password

# 2.1.1.6
# Check Firewall=on, selinux=on and kdump=off
#
# /etc/selinux/config
# SELINUX=enforcing
# SELINUXTYPE=targetted
#
# check /etc/grub.conf does not contain:
# selinux=0
# enforcing=0
#
# /usr/sbin/sestatus

# 2.1.3.1
# AIDE:
# yum install aide
# /usr/sbin/aide --inet
# cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
# /usr/sbin/aide --check # Time consuming..
#
# put in crontab
# 05 4 * * * root /usr/sbin/aide --check
#

# 2.1.3.2
# Check for system files that have changed.
#rpm -qVa | awk '$2!="c" {print $0}'

# 2.2.1.1
# Add nodev to these filesystems:
#mount -t ext2,ext3,ext4 |awk '{print $3}' |grep -v ^/$

# 2.2.1.2 - 2.2.1.3
# Add noexec,nodev,nosuid to removable media ( floppy, cdrom, usb, /tmp, /dev/shm )
# 

# 2.2.1.4
# Bind-mount /var/tmp to /tmp
# /tmp	/var/tmp	none	rw,noexec,nosuid,nodev,bind	0 0
#

# 2.2.2.1
# Restrict Console Device Access
# /etc/security/console.perms.d/50-default.perms
# comment ^<console> and ^<xconsole>
#
# change 
#<console>=tty[0-9][0-9]* vc/[0-9][0-9]* :[0-9]\.[0-9] :[0-9]
#<xconsole>=:[0-9]\.[0-9] :[0-9]
#for
#<console>=tty[0-9][0-9]* vc/[0-9][0-9]* :0\.[0-9] :0
#<xconsole>=:[0-9]\.0 :0
#

# 2.2.2.2.1
# Keep datacenter employee from using usb storage 
#
#  add 
#  install usb-storage /bin/true
#  to
#  /etc/modprobe.conf

# 2.2.2.2.2
# If really depsperate find /lib/modules -name usb-storage.ko -exec rm -f {} \;
#

# 2.2.2.3 Disable autofs
# chkconfig autofs off

# 2.2.2.4 Disable GNOME automountinf if Possible
# I never install gnome on my servers.

 
# 2.2.2.5  Disable uncommong filesystem types
# add 
# install cramfs /bin/true
# install freevxfs /bin/true
# install jffs2 /bin/true
# install hfs /bin/true
# install hfsplus /bin/true
# install squashfs /bin/true
# install udf /bin/true
# to 
# /etc/modprobe.conf


# 2.2.3.1 Verify Permission on passwd, shadow, group, gshadow
# Make sure /etc/{passwd,shadow,group,gshadow} are owned by root:root
# chmod 0644 /etc/{passwd,group}
# chmod 0400 /etc/{shadow,gshadow}
# 
# test with ls -l /etc/{passwd,group,shadow,gshadow}


# 2.2.3.2 Locate World-Writable with Dticky Bits Set
#
# find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
#
# check and fix with:
# chmod  +t /dir
# * make exclusion @array for dires where you want to allow such permissions.


# 2.2.3.3 Locate World-Writable Files
#
# find / -xdev -type f -perm -0002 -print
#
# Fix with chmod o-w file
# * make exclusion @array

# 2.2.3.4 Locate SUID/SGID System Executables
#
# find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print
# fix with chmod -s file
# be careful some executables need a suid and sgid bit ...
# @suid_sgid_exclude(
# '/bin/mount', 
# '/bin/ping', 
# '/bin/su',
# '/bin/umount',
# '/sbin/mount.nfs',
# '/sbin/mount.nfs4',
# '/sbin/netreport',
# '/sbin/pam_timestamp_check',
# '/sbin/unmount.nfs',
# '/sbin/unmount.nfs4',
# '/sbin/unix_chkpwd',
# '/usr/bin/at',
# '/usr/bin/chage',
# '/usr/bin/chfn',
# '/usr/bin/chsh',
# '/usr/bin/gpasswd',
# '/usr/bin/locate',
# '/usr/bin/lockfile',
# '/usr/bin/newgrp',
# '/usr/bin/passwd',
# '/usr/bin/rcp',
# '/usr/bin/rlogin',
# '/usr/bin/rsh',
# '/usr/bin/ssh-agent',
# '/usr/bin/sudo',
# '/usr/bin/sudoedit',
# '/usr/bin/',
# '/usr/bin/wall',
# '/usr/bin/write',
# '/usr/bin/Xorg',
# '/usr/kerberos/bin/ksu',
# '/usr/libexec/utemper/utemper',
# '/usr/lib/squid/pam_auth',
# '/usr/lib/squid/ncsa_auth',
# '/usr/lib/vte/gnome-pty-helper',
# '/usr/sbin/lockdev',
# '/usr/sbin/sendmail.sendmail',
# '/usr/sbin/userhelper',
# '/usr/sbin/userisdnctl',
# '/usr/sbin/usernetctl',
#

# 2.2.3.5 Find unowned files
# find / -xdev \( -nouser -o -nogroup \) -print
# 
# Fix: Investigate and chown / chgrp them

# 2.2.3.6 Verify taht all World Writable Dir Have Proper Owner
# find / -xdev -type d -perm -0002 -uid +500 -print


# 2.2.4.1 Set Daemon umask
# unmask 027
# to
# /etc/sysconfig/init
#
# Add exception to apache i guess. to any deamon who need to write world writable files...
#


# 2.2.4.2 Disable Core Dumps
# add "hard core 0" to /etc/security/limits.conf
# add "fs.suid_dumpable = 0" to /etc/sysctl.conf
# add "ulimit -S -c 0 > /dev/null 2>&1" to /etc/profile
#

# 2.2.4.3 Enable ExecShield
#
# add "kernel.exec-shield = 1"
# add "kernel.randomize_va_space = 1"
# to
# /etc/sysctl.conf

# 2.2.4.4
# Check for pae/nx
# cat /proc/cpuinfo |grep -i '\<pae\>' |grep -i '\<nx\>'
# if true yum install kernel-PAE
# make sure it's installed in /etc/grub.conf


# 2.2.4.5 Disable Prelink
# edit /etc/sysconfig/prelink
# set PRELINKING=no
# Undo existing Prelinking
# /usr/sbin/prelink -ua

# 2.3.1
#
# 2.3.1.2 Be in wheel or no root.
# grep ^wheel /etc/group
# uncomment in /etc/pam.d/su
# auth		required		pam_wheel.so		use_uid

# 2.3.1.3 Make sudo require wheel group to use
# visudo
# %wheel	ALL=(ALL)	ALL

# 2.3.1.4 Block Login/Shell for Non-Root System Accounts
#
# review with 
# awk -F: '{print $1 ":" $3 ":" $7}' /etc/passwd
# check if locked in /etc/shadow ( with ! ) preceding the password
# lock with
# usermod -L Account
# usermond -s /sbin/nologin Account


# 2.3.1.5.1 Make sure everything is locked with a password
#
# awk -F: '($2  == "") {print}' /etc/shadow
#

# 2.3.1.5.2 Make sure all account password hashes are shadowed
#
# awk -F: '($2 != "x") {print}' /etc/passwd

# 2.3.1.6 Check for backdoor root account ( uid 0 )
#
# awk -F: '($3 == "0") {print}' /etc/passwd
#
# Warn if any ( on iWeb you have the admin account )
# that the staff can use to log in.
#

# 2.3.1.7 Set password Expiration Params
# 
# Make sure that:
# 30 < PASS_MAX_DAYS > 365
# PASS_MIN_DAYS > 0
# PASS_MIN_LEN > 8 ( the highter the better )
#
# Default:
# PASS_MAX_DAYS   99999
# PASS_MIN_DAYS   0
# PASS_MIN_LEN    5
# PASS_WARN_AGE   7
#
# NSA recomended
# PASS_MAX_DAYS   60
# PASS_MIN_DAYS   7
# PASS_MIN_LEN    14
# PASS_WARN_AGE   7
#

# 2.3.1.7.1 Make sure that /etc/libuser.conf has
#
# login_defs = /etc/login.defs
#
# and that 
#
# # LU_SHADOWMIN = 0
# # LU_SHADOWMAX = 99999
# # LU_SHADOWWARNING = 7
#
# are commented.
#

# 2.3.1.8 Make sure no Legacy '+' Entries from Password Files
#
# grep "^+:" /etc/{passwd,shadow,group}
#
# no output should be generated
#

# 2.3.2.1
# you should have a group with all users in it.
# groupadd usergroup
# usermod -G usergroup humainX
#
# This makes it easier to grant or restrict access to certain things.
#


#2.3.3.1.1 Set Password Quality  Rqquirements, if useing pam_cracklib
#
#
# /etc/pam.d/system-auth
# password	requisite	pam_cracklib.so try_first_pass retry=3
#
# replace with
# password	required	pam_cracklib.so try_first_pass retry=3 minlen=14 \
#                                            dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
#

# 2.3.3.1.2 Stronger password can be achived with pam_passwdqc.so


# 2.3.3.2 Set Lockouts for Failled Password Attempts
#
# pam_tally2 changed in rhel5 life time.
#
# add to /etc/pam.d/system-auth
# auth		required	pam_tally2.so	deny=5 onerr=fail unlock_time=900
#
# account	required	pam_tally2.so
#
# Manually unlock a user with /sbin/pam_tally2 --user User --reset
#

# 2.3.3.3 Use pam_deny.so on unused services
# add 
# auth		requisite	pam_deny.so
# on 1st line of /etc/pam.d/(service you don't use)

# 2.3.3.4 Restrict Execution of userhelper to Console Users ( graphical users )
#
# chgrp usergroup /usr/sbin/userhelper
# chmod 4710 /usr/sbin/userhelper


# 2.3.3.5 Upgrade Password Hashing Algorithm to SHA-512
#
# 1.
# /etc/pam.d/system-auth
# password	sufficient	pam_unix.sl sha512 shadow nullok try_first_pass use_authok
#
# 2.
# /etc/login.defs 
# MD5_CRYPT_ENAB no
# ENCRYPT_METHOD SHA512
#
# 3.
# /etc/libuser.conf
# crypt_style = sha512
#
# Change password for everyone!
#

# 2.3.3.6  Limit Password Reuse
#
# password sufficient pam_unix ( existing_options ) remember=5

# Remove the pam_ccreds Package if Possible
#
# yum erase pam_ccreds
#

# 2.3.4.1 Ensure taht No Dangerous Directories Exist in Root's Path
#
# echo $PATH
# check for 
# PATH=:/bin
# PATH=/bin:
# PATH=/bin::/sbin
#
# Make sure no relative path, no empty path 

# 2.3.4.1.2 No world writable or group writable directories in $PATH allowed
#

# 2.3.4.2 Home directories Not Group writable or World Readable
#
# chmod g-w  /home/*
# chmod o-rwx /home/*

# 2.3.4.3 Ensuire that User Dot-Files are not World-writable
#
# ld -ld /home/USER/.[A-Za-z0-9]*
#
# chmod go-w
#

# 2.3.4.4 Ensuire that users have sensible usermask values
#
# edit /etc/profile, /etc/bashrc, etc/csh.cshrc
# umask 077
#
# edit /etc/login.defs
# UMASK 077
#
# Edit /root/.bashrc, /root/.bash_profile, /root/.cshrc, /root/tcshrc
# umask 077


# 2.3.4.5 no .netrc files allowed
# find /home -name .netrc -print

# 2.3.5 Protect physical access.
# TODO
#

# 2.3.5.5 Setup Inactivity  Time-out for Login Shells
#
# Bash
# create a file called tmount.sh in /etc/profile.d
# with the following lines:
# TMOUT=900
# readonly TMOUT
# export TMOUT
#
# Tcsh
# create a file called autologout.csh in /etc/profile.d
# with the following line:
# set -r autologout 15
#
# Check for zsh.

# Disable stuff
# 2.4.3.1 chkconfig setroubleshoot off
# 2.4.3.2 chkconfig mcstrans off

# 2.4.4 Check of Unconfined Daemons ( services not configured with selinux )
# ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF}'
#
# Should not produce any output.

# 2.4.5 check for Unlabeled Device Files
# ls -Z /dev |grep unlabeled_t
# should not produce any output
#


# 2.5.1
#

# 2.5.1.1 Hosts Only ( most web servers )
#
# /etc/sysctl.conf
# net.ipv4.ip_forward = 0
# net.ipv4.conf.all.send_redirects = 0
# net.ipv4.conf.all.default.send_redirects = 0
#

# 2.5.1.2 Network Parameters for Hosts and Routers
#
# net.ipv4.conf.all.accept_source_route = 0
# net.ipv4.conf.all.accept_redirects = 0
# net.ipv4.conf.all.secure_redirects = 0
# net.ipv4.conf.all.log_martians = 1
# net.ipv4.conf.conf.default.accept_source_route = 0
# net.ipv4.conf.conf.default.accept_redirects = 0
# net.ipv4.conf.conf.default.secure_redirects = 0
# net.ipv4.conf.icmp_echo_ignore_broadcasts = 1
# net.ipv4.conf.icmp_ignore_bogus_error_messages = 1
# net.ipv4.tcp_syncookies = 1
# net.ipv4.conf.all.rp_filter = 1
# net.ipv4.conf.default.rp_filter = 1
#

# 2.5.1.3 Check that no sniffers are running:
#
# cat /proc/net/packet
# sk       RefCnt Type Proto  Iface R Rmem   User   Inode
#
# Shouldn't have anything else.



# 2.5.3 IPv6
#
# 2.5.3.1.1 Disable IPv6 unless needed
#
# The only way is to prevent it from being loaded into the kernel
#
# add to /etc/modprobe.conf
# install ipv6 /bin/true
#

# 2.5.3.1.2
#
#  /etc/sysconfig/network
#
#  NETWORKING_IPV6=no
#  IPv6INIT=no
#
#  foreach ( /etc/sysconfig/network-scripts/ifcfg-ethX )
#      IPV6INIT=no


# 2.5.3.2 Configure IPv6 if Necessary
#
# 2.5.3.2.1 Disable Automatic Configuration
#
# /etc/sysconfig/network
# IPV6_AUTOCONF=no
#
# /etc/sysconfig/sysctl.conf
#
# net.ipv6.conf.default.accept_ra = 0
# net.ipv6.conf.default.accept_redirect = 0

# Setup static ip and router ( 2.4.3.2.2 and 2.5.3.2.5 )

# 2.5.3.2.3 Use Privacy Extensions for Address
#
# /etc/sysconfig/network-scripts/ifcfg-ethX
# IPV6_PRIVACY=rfc3041
#


# 2.5.3.2.5 Limit Network-Transmitted Configuration
#
# /etc/sysctl.conf
#
# net.ipv6.conf.default.router_solicitations = 0
# net.ipv6.conf.default.accept_ra_rtr_pref = 0
# net.ipv6.conf.default.accept_ra_pinfo = 0
# net.ipv6.conf.default.accept_ra_defrtr = 0
# net.ipv6.conf.default.autoconf = 0
# net.ipv6.conf.default.dad_transmits = 0
# net.ipv6.conf.default.max_addresses = 1



# 2.5.4.4 Monitor Syslog for Relevent Connexions and Failures
#
# /etc/syslog.conf
# authpriv.*			/var/log/secure


# 2.5.5 iptables and ip6tables
#
# I will go over iptables and leave ip6table for someone else to fill in the blanks :)

# 2.5.5.3.1 Change de Default Policies
# /etc/sysconfig/iptables
#
# *filter
# :INPUT DROP [0:0]
# :FORWARD DROP [0:0]
# :LOG ACCEPT [0:0]

# remove 
# -A RH-Firewall-1-INPUT -p icmp --icmp-type any -j ACCEPT
#
# replace with 
#
# -A RH-Firewall-1-INPUT -p icmp --icmp-type echo-reply -j ACCEPT
# -A RH-Firewall-1-INPUT -p icmp --icmp-type destination-unreachable ACCEPT
# -A RH-Firewall-1-INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
#
# if you want to be pinged add:
# -A RH-Firewall-1-INPUT -p icmp --icmp-type echo-request  -j ACCEPT
#
#
# remove IPsec rules
# -A RH-Firewall-1-INPUT -p 50 -j ACCEPT
# -A RH-Firewall-1-INPUT -p 51 -j ACCEPT
#
#
# -A input -i eth0 -s 10.0.0.0/8 -j LOG --log-prefix "IP DROP SPOOF A: "
# -A input -i eth0 -s 172.16.0.0/12 -j LOG --log-prefix "IP DROP SPOOF B: "
# -A input -i eth0 -s 192.168.0.0/16 -j LOG --log-prefix "IP DROP SPOOF C: "
# -A input -i eth0 -s 224.0.0.0/4 -j LOG --log-prefix "IP DROP MULTICAST D: "
# -A input -i eth0 -s 240.0.0.0/5 -j LOG --log-prefix "IP DROP SPOOF E: "
# -A input -i eth0 -s 127.0.0.0/8 -j LOG --log-prefix "IP DROP LOOPBACK: "
 
# 2.5.5.3.5 Log and Drop All Other Packets
# replace
# -A RH-Firewall-1-INPUT -j REJECT --reject-with icmp-host-prohibited
#
# with
# -A RH-Firewall-1-INPUT -j LOG
# -A RH-Firewall-1-INPUT -j DROP
#

# 2.5.6 Secure Sockets Layer Support ( SSL )
#
# Use ssl when you can!
#
# Make an object checking used services and determin if they are using ssl or not.
#
# Good peice of work here but not urgent.


# 2.5.6 Secure Sockets Layer Support ( SSL )
#
# Use ssl when you can!
#
# Make an object checking used services and determin if they are using ssl or not.
#
# check apache, dovecot, postfix, and more
#
# Good peice of work here but not urgent.
# 



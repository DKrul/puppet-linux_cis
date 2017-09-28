# == Class: cis_rhel7::params
#
# This class defines parameters used by this module
#

class cis_rhel7::params (
  #enable/disable specific rules
  $rule_3_1 = true,
  $rule_3_2 = true,

  $iprange  = undef,
) {
  # Resource Defaults to NOOP 
  File      { noop => false}
  File_line { noop => false }
  User      { noop => false }
  Exec      { noop => false, path => '/usr/bin:/usr/sbin:/bin' }
  Mount     { noop => false }
  Service   { noop => false }
  Package   { noop => false }
  Cron      { noop => false }
  Augeas    { noop => false }
  Pam       { noop => false }

  if ($iprange == undef) {
    fail ("\n\n!! The IP network range needs to be defined for /etc/hosts.allow. Variable is named cis_rhel7::params::iprange !! \n\n")
  }

  # Rule 4.1.4
  $audit_rules = [
    #4.1.4
    '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change %4.1.4',
    '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change %4.1.4',
    '-a always,exit -F arch=b64 -S clock_settime -k time-change %4.1.4',
    '-a always,exit -F arch=b32 -S clock_settime -k time-change %4.1.4',
    '-w /etc/localtime -p wa -k time-change %4.1.4',
    #4.1.5
    '-w /etc/group -p wa -k identity %4.1.5',
    '-w /etc/passwd -p wa -k identity %4.1.5',
    '-w /etc/gshadow -p wa -k identity %4.1.5',
    '-w /etc/shadow -p wa -k identity %4.1.5',
    '-w /etc/security/opasswd -p wa -k identity %4.1.5',
    #4.1.6
    '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale %4.1.6',
    '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale %4.1.6',
    '-w /etc/issue -p wa -k system-locale %4.1.6',
    '-w /etc/issue.net -p wa -k system-locale %4.1.6',
    '-w /etc/hosts -p wa -k system-locale %4.1.6',
    '-w /etc/sysconfig/network -p wa -k system-locale %4.1.6',
    #4.1.7
    '-w /etc/selinux/ -p wa -k MAC-policy %4.1.7',
    #4.1.8
    '-w /var/run/faillock/ -p wa -k logins %4.1.8',
    '-w /var/log/faillock/ -p wa -k logins %4.1.8',
    '-w /var/log/lastlog -p wa -k logins %4.1.8',
    #4.1.9
    '-w /var/run/utmp -p wa -k session %4.1.9',
    '-w /var/log/wtmp -p wa -k session %4.1.9',
    '-w /var/log/btmp -p wa -k session %4.1.9',
    #4.1.10
    '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod %4.1.10',
    '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod %4.1.10',
    '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod %4.1.10',
    '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod %4.1.10',
    '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod %4.1.10',
    '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod %4.1.10',
    #4.1.11
    '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access %4.1.11',
    '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access %4.1.11',
    '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access %4.1.11',
    '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access %4.1.11',
    #4.1.12
    #4.1.12 Ensure use of privileged commands is collected
    #find /  -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"}'
    '-a always,exit -F path=/usr/sbin/mount.nfs -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/ksu -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/locate -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/libexec/sssd/selinux_child -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/libexec/sssd/krb5_child -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/libexec/sssd/proxy_child -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/libexec/sssd/ldap_child -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/libexec/sssd/p11_child -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    '-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged %4.1.12',
    #4.1.13
    '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts %4.1.13',
    '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts %4.1.13',
    #4.1.14
    '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete %4.1.14',
    '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete %4.1.14',
    #4.1.15
    '-w /etc/sudoers -p wa -k scope %4.1.15',
    '-w /etc/sudoers.d -p wa -k scope %4.1.15',
    #4.1.16
    '-w /var/log/sudo.log -p wa -k actions %4.1.16',
    #4.1.17
    '-w /sbin/insmod -p x -k modules %4.1.17',
    '-w /sbin/rmmod -p x -k modules %4.1.17',
    '-w /sbin/modprobe -p x -k modules %4.1.17',
    '-a always,exit arch=b64 -S init_module -S delete_module -k modules %4.1.17',
    #4.1.18
    '-e 2 %4.1.18'
  ]

  # Rule 4.3
  $logs = [ '/var/log/messages','/var/log/secure','/var/log/maillog','/var/log/spooler','/var/log/boot.log','/var/log/cron' ]
}

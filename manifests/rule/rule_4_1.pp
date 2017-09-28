# == Class: cis_rhel7::rule::rule_4_1
# includes Rules:
#4.1.1.1 Ensure audit log storage size is configured 
#4.1.1.2 Ensure system is disabled when audit logs are full 
#4.1.1.3 Ensure audit logs are not automatically deleted 
#4.1.2 Ensure auditd service is enabled
#4.1.3 Ensure auditing for processes that start prior to auditd is enabled
#4.1.4 Ensure events that modify date and time information are collected
#4.1.5 Ensure events that modify user/group information are collected 
#4.1.6 Ensure events that modify the system's network environment are collected 
#4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected
#4.1.8 Ensure login and logout events are collected 
#4.1.9 Ensure session initiation information is collected 
#4.1.10 Ensure discretionary access control permission modification events are collected 
#4.1.11 Ensure unsuccessful unauthorized file access attempts are collected
#NOT USED 4.1.12 Ensure use of privileged commands is collected 
#4.1.13 Ensure successful file system mounts are collected
#4.1.14 Ensure file deletion events by users are collected 
#4.1.15 Ensure changes to system administration scope (sudoers) is collected 
#4.1.16 Ensure system administrator actions (sudolog) are collected 
#4.1.17 Ensure kernel module loading and unloading is collected 
#4.1.18 Ensure the audit configuration is immutable 

class cis_rhel7::rule::rule_4_1(
  $rules = $::cis_rhel7::params::audit_rules
) {
  $auditfile = '/etc/audit/auditd.conf'
  $auditrules = '/etc/audit/audit.rules'
  $grubfile = '/etc/default/grub'

  #4.1.1.1 Ensure audit log storage size is configured 
  file_line { "(4.1.1.1) - ${auditfile}: max_log_file":
    ensure => present,
    path   => $auditfile,
    line   => 'max_log_file = 32',
    match  => '^max_log_file(?!_)',
  }
  file_line { "(4.1.1.2) - ${auditfile}: admin_space_left_action":
    ensure => present,
    path   => $auditfile,
    line   => 'admin_space_left_action = halt',
    match  => '^admin_space_left_action',
  }
  file_line { "(4.1.1.2) - ${auditfile}: action_mail_acct":
    ensure => present,
    path   => $auditfile,
    line   => 'action_mail_acct = root',
    match  => '^action_mail_acct',
  }
  file_line { "(4.1.1.2) - ${auditfile}: max_log_file_action":
    ensure => present,
    path   => $auditfile,
    line   => 'max_log_file_action = keep_logs',
    match  => '^max_log_file_action',
  }
  file_line { "(4.1.1.3) - ${auditfile}: max_log_file_action":
    ensure => present,
    path   => $auditfile,
    line   => 'max_log_file_action = keep_logs',
    match  => '^max_log_file_action',
  }
  file_line { "(4.1.1.3) - ${auditfile}: space_left_action":
    ensure => present,
    path   => $auditfile,
    line   => 'space_left_action = email',
    match  => '^space_left_action',
  }
  service { '(4.1.2) - auditd service enabled':
    ensure => running,
    name   => 'auditd',
    enable => true,
  }
  #4.1.3
  file { "(4.1.3) - ${grubfile} exists":
    ensure => file,
    name   => $grubfile,
    mode   => '0644',
    owner  => 'root',
    group  => 'root',
  }
  file_line { "(4.1.3) - ${grubfile}: audit=1":
    ensure => present,
    path   => $grubfile,
    line   => 'GRUB_CMDLINE_LINUX="nofb splash=quiet crashkernel=auto rd.lvm.lv=VolGroup01/root rhgb quiet audit=1"',
    match  => '^GRUB_CMDLINE_LINUX',
  }
  #4.1.4 t/m 4.1.18
  each ($rules) |$rule_item| {
    $rule = split($rule_item, '%')
    file_line { "(${rule[1]}) - ${auditrules}: ${rule[0]}":
      ensure   => present,
      path     => $auditrules,
      line     => $rule[0],
      multiple => false,
    }
  }
}
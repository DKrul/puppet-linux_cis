# == Class: cis_rhel7::rule::rule_6_1
# includes Rules:
#NOT USED 6.1.1 Audit system file permissions 
#6.1.2 Ensure permissions on /etc/passwd are configured
#6.1.3 Ensure permissions on /etc/shadow are configured
#6.1.4 Ensure permissions on /etc/group are configured
#6.1.5 Ensure permissions on /etc/gshadow are configured 
#6.1.6 Ensure permissions on /etc/passwd- are configured
#6.1.7 Ensure permissions on /etc/shadow- are configured
#6.1.8 Ensure permissions on /etc/group- are configured
#6.1.9 Ensure permissions on /etc/gshadow- are configured
#NOT USED 6.1.10 Ensure no world writable files exist
#NOT USED 6.1.11 Ensure no unowned files or directories exist 
#NOT USED 6.1.12 Ensure no ungrouped files or directories exist 
#NOT USED 6.1.13 Audit SUID executables
#NOT USED 6.1.14 Audit SGID executables

class cis_rhel7::rule::rule_6_1  {
#  notify{"NOT USED 6.1.1 Audit system file permissions ": loglevel => "debug" }

  file { '(6.1.2) - /etc/passwd: ownership & permissions':
    ensure => file,
    path   => '/etc/passwd',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
  file { '(6.1.3) - /etc/shadow: ownership & permissions':
    ensure => file,
    path   => '/etc/shadow',
    owner  => 'root',
    group  => 'root',
    mode   => '0000',
  }
  file { '(6.1.4) - /etc/group: ownership & permissions':
    ensure => file,
    path   => '/etc/group',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
  file { '(6.1.5) - /etc/gshadow: ownership & permissions':
    ensure => file,
    path   => '/etc/gshadow',
    owner  => 'root',
    group  => 'root',
    mode   => '0000',
  }
  file { '(6.1.6) - /etc/passwd-: ownership & permissions':
    ensure => file,
    path   => '/etc/passwd-',
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }
  file { '(6.1.7) - /etc/shadow-: ownership & permissions':
    ensure => file,
    path   => '/etc/shadow-',
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }
  file { '(6.1.8) - /etc/group-: ownership & permissions':
    ensure => file,
    path   => '/etc/group-',
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }
  file { '(6.1.9) - /etc/gshadow-: ownership & permissions':
    ensure => file,
    path   => '/etc/gshadow-',
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }
#  notify{"NOT USED 6.1.10 Ensure no world writable files exist": loglevel => "debug" }
#  notify{"NOT USED 6.1.11 Ensure no unowned files or directories exist": loglevel => "debug" }
#  notify{"NOT USED 6.1.12 Ensure no ungrouped files or directories exist": loglevel => "debug" }
#  notify{"NOT USED 6.1.13 Audit SUID executables": loglevel => "debug" }
#  notify{"NOT USED 6.1.14 Audit SGID executables": loglevel => "debug" }
}
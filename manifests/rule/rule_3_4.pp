# == Class: cis_rhel7::rule::rule_3_4
# includes Rules:
# 3.4.1 - Install TCP Wrappers (Not Scored)
#3.4.2 Ensure /etc/hosts.allow is configured 
#3.4.3 Ensure /etc/hosts.deny is configured
#3.4.4 Ensure permissions on /etc/hosts.allow are configured
#3.4.5 Ensure permissions on /etc/hosts.deny 

class cis_rhel7::rule::rule_3_4(
  $iprange = $cis_rhel7::params::iprange
) {
  $file = '/etc/hosts.allow'
  $filedeny = '/etc/hosts.deny'

  package { '(3.4.1) - Install TCP Wrappers':
    ensure => present,
    name   => 'tcp_wrappers',
  }
  file_line { "(3.4.2) - ${file}: ADD: net/mask":
    ensure            => present,
    path              => $file,
    line              => "ALL: ${iprange}",
    match             => '^ALL:.*',
    match_for_absence => true,
    multiple          => true,
    replace           => true,
  }
  file { "(3.4.4) - ${file} has 644 permissions":
    ensure => file,
    path   => $file,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
  file_line { "(3.4.3) - ${filedeny}: ALL:ALL":
    ensure   => present,
    path     => $filedeny,
    line     => 'ALL:ALL',
    match    => '^ALL.?:.?ALL',
    multiple => false,
    replace  => false,
  }
  file { "(3.4.5) - ${filedeny} has 644 permissions":
    ensure => file,
    path   => $filedeny,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
}
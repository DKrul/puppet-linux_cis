# == Class: cis_rhel7::rule::rule_5_4
#includes Rules:
#5.4.1.1 Ensure password expiration is 90 days or less
#5.4.1.2 Ensure minimum days between password changes is 7 or more
#5.4.1.3 Ensure password expiration warning days is 7 or more
#NOT USED 5.4.1.4 Ensure inactive password lock is 30 days or less 
#NOT USED 5.4.2 Ensure system accounts are non-login
#NOT USED 5.4.3 Ensure default group for the root account is GID 0
#NOT USED 5.4.4 Ensure default user umask is 027 or more restrictive

class cis_rhel7::rule::rule_5_4 {
  $file = '/etc/login.defs'

  file { "(5.4.1.1) - ${file} exists":
    ensure => file,
    path   => $file,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
  file_line { '(5.4.1.1) - Set password expiration date':
    ensure  => present,
    path    => $file,
    line    => 'PASS_MAX_DAYS 90',
    match   => '^PASS_MAX_DAYS.*90',
    replace => false,
  }
  file_line { '(5.4.1.2) - Set password change minimum number of days':
    ensure  => present,
    path    => $file,
    line    => 'PASS_MIN_DAYS 7',
    match   => '^PASS_MIN_DAYS.*7',
    replace => false,
  }
  file_line { '(5.4.1.3) - Set password expiring warning days':
    ensure  => present,
    path    => $file,
    line    => 'PASS_WARN_AGE 7',
    match   => '^PASS_WARN_AGE.*7',
    replace => false,
  }
  file_line { '(5.4.1.4) - Ensure inactive password lock is 30 days or less':
    ensure => present,
    path   => '/etc/default/useradd',
    line   => 'INACTIVE=30',
    match  => '^INACTIVE',
  }
#  notify{"NOT USED 5.4.2 Ensure system accounts are non-login":loglevel => "debug"}
#  notify{"NOT USED 5.4.3 Ensure default group for the root account is GID 0":loglevel => "debug"}
#  notify{"NOT USED 5.4.4 Ensure default user umask is 027 or more restrictive":loglevel => "debug"}
}
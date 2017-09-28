# == Class: cis_rhel7::rule::rule_1_5
# includes Rules:
#1.5.1 Ensure core dumps are restricted
#NOT USED 1.5.2 Ensure XD/NX support is enabled
#1.5.3 Ensure address space layout randomization (ASLR) is enabled 
#1.5.4 Ensure prelink is disabled (Scored

class cis_rhel7::rule::rule_1_5 {
  $file = '/etc/security/limits.conf'
  $file_sysctl = '/etc/sysctl.conf'

  file { "(1.5.1) - ${file} exists":
    ensure => file,
    path   => $file,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
  file_line { "(1.5.1) - ${file}: disable core dumps":
    ensure => present,
    path   => $file,
    line   => '* hard core 0',
  }
  file { "(1.5.1) - ${file_sysctl} exists":
    ensure => file,
    path   => $file_sysctl,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }
  file_line { "(1.5.1) - ${file_sysctl}: disable core dumps":
    ensure => present,
    path   => $file_sysctl,
    line   => 'fs.suid_dumpable = 0',
  }
  #1.5.2
#  notify {"#NOT USED 1.5.2 Ensure XD/NX support is enabled": loglevel => "debug"}
  #1.5.3
  file_line { "(1.5.3) - ${file_sysctl}: enable address space layout randomization (ASLR)":
    ensure => present,
    path   => $file_sysctl,
    line   => 'kernel.randomize_va_space = 2',
    match  => '^kernel.randomize_va_space',
  }
  #1.5.4
  service {'1.5.4 Ensure prelink is disabled':
    ensure => stopped,
    name   =>'prelink',
  }
  package { '1.5.4 Ensure prelink is removed' :
    ensure => absent,
    name   => 'prelink',
  }
}
# == Class: cis_rhel7::rule::rule_4_2
# includes Rules:
#NOT USED 4.2.1.1 Ensure rsyslog Service is enabled
#NOT USED 4.2.1.2 Ensure logging is configured
#NOT USED 4.2.1.3 Ensure rsyslog default file permissions configured
#NOT USED 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host
#NOT USED 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts
#NOT USED 4.2.2.1 Ensure syslog-ng service is enabled 
#NOT USED 4.2.2.2 Ensure logging is configured
#NOT USED 4.2.2.3 Ensure syslog-ng default file permissions configured
#NOT USED 4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host
#NOT USED 4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts
#NOT USED 4.2.3 Ensure rsyslog or syslog-ng is installed 
#NOT USED 4.2.4 Ensure permissions on all logfiles are configured 

class cis_rhel7::rule::rule_4_2 (
) inherits cis_rhel7::params {
#  notify {"4.2.1.1 Ensure rsyslog Service is enabled": loglevel => "debug" }
#  notify {"4.2.1.2 Ensure logging is configured": loglevel => "debug" }
#  notify {"4.2.1.3 Ensure rsyslog default file permissions configured": loglevel => "debug" }
  file_line { '(4.2.1.3) - Ensure rsyslog default file permissions configured':
    ensure => present,
    path   => '/etc/rsyslog.conf',
    line   => '$FileCreateMode 0640',
    match  => '^$FileCreateMode',
  }
#  notify {"4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host": loglevel => "debug" }
#  notify {"4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts": loglevel => "debug" }
#  notify {"4.2.2.1 Ensure syslog-ng service is enabled ": loglevel => "debug" }
#  notify {"4.2.2.2 Ensure logging is configured": loglevel => "debug" }
#  notify {"4.2.2.3 Ensure syslog-ng default file permissions configured": loglevel => "debug" }
#  notify {"4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host": loglevel => "debug" }
#  notify {"4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts": loglevel => "debug" }
#  notify {"4.2.3 Ensure rsyslog or syslog-ng is installed": loglevel => "debug" }
#  notify {"4.2.4 Ensure permissions on all logfiles are configured ": loglevel => "debug" }
  #fix file permissions of odd files
  file { '(4.2.4) Ensure permissions on all logfiles are configured boot.log':
    ensure => file,
    path   => '/var/log/boot.log',
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  file { '(4.2.4) Ensure permissions on all logfiles are configured btmp':
    ensure => file,
    path   => '/var/log/btmp',
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  file { '(4.2.4) Ensure permissions on all logfiles are configured dmesg':
    ensure => file,
    path   => '/var/log/dmesg',
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  file { '(4.2.4) Ensure permissions on all logfiles are configured lastlog':
    ensure => file,
    path   => '/var/log/lastlog',
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  file { '(4.2.4) Ensure permissions on all logfiles are configured wtmp':
    ensure => file,
    path   => '/var/log/wtmp',
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
}
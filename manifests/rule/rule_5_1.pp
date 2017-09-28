# == Class: cis_rhel7::rule::rule_5_1
# includes Rules:
#5.1.1 Ensure cron daemon is enabled 
#5.1.2 Ensure permissions on /etc/crontab are configured
#5.1.3 Ensure permissions on /etc/cron.hourly are configured
#5.1.4 Ensure permissions on /etc/cron.daily are configured 
#5.1.5 Ensure permissions on /etc/cron.weekly are configured
#5.1.6 Ensure permissions on /etc/cron.monthly are configured
#5.1.7 Ensure permissions on /etc/cron.d are configured
#5.1.8 Ensure at/cron is restricted to authorized users

class cis_rhel7::rule::rule_5_1 {
  service { '(5.1.1) - crond service is enabled':
    ensure => running,
    name   => 'crond',
    enable => true,
  }
  file { '(5.1.2) -  /etc/crontab permissions':
    ensure => file,
    path   =>  '/etc/crontab',
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  file { '(5.1.8) -  /etc/cron.allow permissions':
    ensure => file,
    path   =>  '/etc/cron.allow',
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  file { '(5.1.8) -  /etc/at.allow permissions':
    ensure => file,
    path   =>  '/etc/at.allow',
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  file { '(5.1.8) -  /etc/cron.deny existence':
    ensure => absent,
    path   =>  '/etc/cron.deny',
  }
  file { '(5.1.8) -  /etc/at.deny existence':
    ensure => absent,
    path   =>  '/etc/at.deny',
  }
  file { '(5.1.3) - /etc/cron.hourly permissions':
      ensure => directory,
      path   => '/etc/cron.hourly',
      mode   => '0700',
      owner  => 'root',
      group  => 'root',
  }
  file { '(5.1.4) - /etc/cron.daily permissions':
      ensure => directory,
      path   => '/etc/cron.daily',
      mode   => '0700',
      owner  => 'root',
      group  => 'root',
  }
  file { '(5.1.5) - /etc/cron.weekly permissions':
      ensure => directory,
      path   => '/etc/cron.weekly',
      mode   => '0700',
      owner  => 'root',
      group  => 'root',
  }
  file { '(5.1.6) - /etc/cron.monthly permissions':
      ensure => directory,
      path   => '/etc/cron.monthly',
      mode   => '0700',
      owner  => 'root',
      group  => 'root',
  }
  file { '(5.1.7) - /etc/cron.d permissions':
      ensure => directory,
      path   => '/etc/cron.d',
      mode   => '0700',
      owner  => 'root',
      group  => 'root',
  }
}
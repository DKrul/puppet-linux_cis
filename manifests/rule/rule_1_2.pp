# == Class: cis_rhel7::rule::rule_1_2
#includes Rules:
#RHEL
# 1.2.1 Ensure package manager repositories are configured (Not Scored)
# 1.2.2 Ensure gpgcheck is globally activated(Not Scored)
# 1.2.3 Ensure GPG keys are configured (Not Scored)
# 1.2.4 Ensure Red Hat Network or Subscription Manager connection is configured (Not Scored)
# 1.2.5 Disable the rhnsd Daemon (Not Scored)

#CentOS
#NOT CHECKED 1.2.1 Ensure package manager repositories are configured 
#NOT CHECKED 1.2.2 Ensure GPG keys are configured
#1.2.3 Ensure gpgcheck is globally activated 

class cis_rhel7::rule::rule_1_2 {
  ## APPLIES TO REDHAT only
  if $::operatingsystem == 'RedHat' {
    #1.2.1
    $redhat_network = $::cis_benchmarks['redhat_network']

    if $redhat_network == 'not registered with RHN'
    {
      notify { '(1.2.1) - RedHat Repository is not configured': }
    }
    #1.2.2
    file { '/etc/yum.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file_line { '(1.2.2) /etc/yum.conf contains gpgcheck=1':
      ensure => present,
      path   => '/etc/yum.conf',
      line   => 'gpgcheck=1',
    }
    #1.2.3
    $gpgkey = $::cis_benchmarks['redhat_gpg']

    if $gpgkey == 'RedHat GPG Key is not installed'
    {
      notify { '(1.2.3) - RedHat GPG Key is not installed': }
    }

    #1.2.4
    #if exists /etc/sysconfig/rhn/systemid and not empty
    #  notify {"NOT CHECKED Ensure Red Hat Network or Subscription Manager connection is configured": loglevel => "debug" }

    #1.2.5
    service { '(1.2.4) rhnsd service is disabled':
      ensure => stopped,
      name   => 'rhnsd',
      enable => false,
    }
  } elsif $::operatingsystem == 'CentOS' {
    #1.2.1
    #  notify {"NOT CHECKED 1.2.1 Ensure package manager repositories are configured ": loglevel => "debug" }

    #1.2.2
    #  notify {"NOT CHECKED 1.2.2 Ensure GPG keys are configured": loglevel => "debug" }

    #1.2.3
    file_line { '(1.2.3) /etc/yum.conf contains gpgcheck=1':
      ensure => present,
      path   => '/etc/yum.conf',
      line   => 'gpgcheck=1',
    }
  } else {
    notify { 'This operating system is not RedHat or CentOS, skipping rules..': }
  }
}

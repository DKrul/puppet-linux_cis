# == Class: cis_rhel7::rule::rule_1_7
# includes Rules:
#1.7.1.1 Ensure message of the day is configured properly
#1.7.1.2 Ensure local login warning banner is configured properly
#1.7.1.3 Ensure remote login warning banner is configured properly
#1.7.1.4 Ensure permissions on /etc/motd are configured 
#1.7.1.5 Ensure permissions on /etc/issue are configured 
#1.7.1.6 Ensure permissions on /etc/issue.net are configured
#NOT USED 1.7.2 Ensure GDM login banner is configured

class cis_rhel7::rule::rule_1_7 {
  $issuenet = '/etc/issue.net'
  $issue = '/etc/issue'
  $motdfile =  '/etc/motd'
  $issuecontent = 'Authorized uses only. All activity may be monitored and reported.'
  $motdcontent = 'Authorized uses only. All activity may be monitored and reported.'

  #1.7.1.1 + 1.7.1.4
  file {$motdfile :
    ensure  => present,
    path    => $motdfile,
    content => $motdcontent,
    mode    => '0644',
    owner   => 'root',
    group   => 'root',
  }
  #1.7.1.2 +1.7.1.5
  file {$issue :
    ensure  => present,
    path    => $issue,
    content => $issuecontent,
    mode    => '0644',
    owner   => 'root',
    group   => 'root',
  }
  #1.7.1.3+1.7.1.6
  file {$issuenet :
    ensure  => present,
    path    => $issuenet,
    content => $issuecontent,
    mode    => '0644',
    owner   => 'root',
    group   => 'root',
  }
#  notify {"NOT USED #1.7.2 Ensure GDM login banner is configured": loglevel =>  "debug"}
}
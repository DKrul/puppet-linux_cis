# == Class: cis_rhel7::rule::rule_3_5
# includes Rules:
#3.5.1 Ensure DCCP is disabled
#3.5.2 Ensure SCTP is disabled
#3.5.3 Ensure RDS is disabled
#3.5.4 Ensure TIPC is disabled

class cis_rhel7::rule::rule_3_5 {
  $file = '/etc/modprobe.d/CIS.conf'

  file_line { "(4.6.1) - ${file}: disable DCCP ":
    ensure => present,
    path   => $file,
    line   => 'install dccp /bin/true',
  }
  file_line { "(4.6.2) - ${file}: disable SCTP ":
    ensure => present,
    path   => $file,
    line   => 'install sctp /bin/true',
  }
  file_line { "(4.6.3) - ${file}: disable RDS ":
    ensure => present,
    path   => $file,
    line   => 'install rds /bin/true',
  }
  file_line { "(4.6.4) - ${file}: disable TIPC ":
    ensure => present,
    path   => $file,
    line   => 'install tipc /bin/true',
  }
}
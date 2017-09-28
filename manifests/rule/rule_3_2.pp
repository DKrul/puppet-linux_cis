# == Class: cis_rhel7::rule::rule_3_2
# includes Rules:
#3.2.1 Ensure source routed packets are not accepted 
#3.2.2 Ensure ICMP redirects are not accepted 
#3.2.3 Ensure secure ICMP redirects are not accepted
#3.2.4 Ensure suspicious packets are logged
#3.2.5 Ensure broadcast ICMP requests are ignored
#3.2.6 Ensure bogus ICMP responses are ignored
#3.2.7 Ensure Reverse Path Filtering is enabled 
#3.2.8 Ensure TCP SYN Cookies is enabled

class cis_rhel7::rule::rule_3_2(
  $enabled = $cis_rhel7::params::rule_3_2,
) {
if $enabled {
    $file = '/etc/sysctl.conf'

    file_line { "(3.2.1) - ${file}: all.accept_source_route=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.all.accept_source_route=0',
      match  => '^net.ipv4.conf.all.accept_source_route',
    }
    file_line { "(3.2.1) - ${file}: default.accept_source_route=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.default.accept_source_route=0',
      match  => '^net.ipv4.conf.default.accept_source_route',
    }
    file_line { "(3.2.2) - ${file}: all.accept_redirects=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.all.accept_redirects=0',
      match  => '^net.ipv4.conf.all.accept_redirects=0',
    }
    file_line { "(3.2.2) - ${file}: default.accept_redirects=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.default.accept_redirects=0',
      match  => '^net.ipv4.conf.default.accept_redirects=0',
    }
    file_line { "(3.2.3) - ${file}: all.secure_redirects=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.all.secure_redirects=0',
      match  => '^net.ipv4.conf.all.secure_redirects=0',
    }
    file_line { "(3.2.3) - ${file}: default.secure_redirects=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.default.secure_redirects=0',
      match  => '^net.ipv4.conf.default.secure_redirects=0',
    }
    file_line { "(3.2.4) - ${file}: all.log_martians=1":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.all.log_martians=1',
      match  => '^net.ipv4.conf.all.log_martians=1',
    }
    file_line { "(3.2.4) - ${file}: default.log_martians=1":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.default.log_martians=1',
      match  => '^net.ipv4.conf.default.log_martians=1',
    }
    file_line { "(3.2.5) - ${file}: icmp_echo_ignore_broadcasts=1":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.icmp_echo_ignore_broadcasts=1',
      match  => '^net.ipv4.icmp_echo_ignore_broadcasts',
    }
    file_line { "(3.2.6) - ${file}: icmp_ignore_bogus_error_responses=1":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.icmp_ignore_bogus_error_responses=1',
      match  => '^net.ipv4.icmp_ignore_bogus_error_responses',
    }
    file_line { "(3.2.7) - ${file}: all.rp_filter=1":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.all.rp_filter=1',
      match  => '^net.ipv4.conf.all.rp_filter',
    }
    file_line { "(3.2.7) - ${file}: default.rp_filter=1":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.default.rp_filter=1',
      match  => '^net.ipv4.conf.default.rp_filter',
    }
    file_line { "(3.2.8) - ${file}: net.ipv4.tcp_syncookies=1":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.tcp_syncookies=1',
      match  => '^net.ipv4.tcp_syncookies',
    }
  }
}
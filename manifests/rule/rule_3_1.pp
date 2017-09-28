# == Class: cis_rhel7::rule::rule_3_1
#includes Rules:
#3.1.1 Ensure IP forwarding is disabled
#3.1.2 Ensure packet redirect sending is disabled 

class cis_rhel7::rule::rule_3_1 (
  $enabled = $cis_rhel7::params::rule_3_1,
) {
  if $enabled {
    $file = '/etc/sysctl.conf'

    file_line { "(3.1.1) - ${file}: ip_forward=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.ip_forward=0',
      match  => '^net.ipv4.ip_forward',
    }
    file_line { "(3.1.2) - ${file}: all.send_redirects=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.all.send_redirects=0',
      match  => '^net.ipv4.conf.all.send_redirects',
    }
    file_line { "(3.1.2) - ${file}: default.send_redirects=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv4.conf.default.send_redirects=0',
      match  => '^net.ipv4.conf.default.send_redirects',
    }
  }
}

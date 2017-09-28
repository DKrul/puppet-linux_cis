# == Class: cis_rhel7::rule::rule_3_3
# includes Rules:
#3.3.1 Ensure IPv6 router advertisements are not accepted 
#3.3.2 Ensure IPv6 redirects are not accepted
#3.3.3 Ensure IPv6 is disabled

class cis_rhel7::rule::rule_3_3 (
  $disable_ipv6_router_advertisements = true,
  $disable_ipv6_redirects = true,
  $disable_ipv6 = true
) {
  $file = '/etc/sysctl.conf'
  $file_cis = '/etc/modprobe.d/CIS.conf'

  if $disable_ipv6_router_advertisements {
    file_line { "(3.3.1) - ${file}: net.ipv6.conf.all.accept_ra=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv6.conf.all.accept_ra=0',
      match  => '^net.ipv6.conf.all.accept_ra',
    }
    file_line { "(3.3.1) - ${file}: net.ipv6.conf.default.accept_ra=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv6.conf.default.accept_ra=0',
      match  => '^net.ipv6.conf.default.accept_ra',
    }
  }
  if $disable_ipv6_redirects {
    file_line { "(3.3.2) - ${file}: net.ipv6.conf.all.accept_redirects=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv6.conf.all.accept_redirects=0',
      match  => '^net.ipv6.conf.all.accept_redirects',
    }
    file_line { "(3.3.2) - ${file}: net.ipv6.conf.default.accept_redirect=0":
      ensure => present,
      path   => $file,
      line   => 'net.ipv6.conf.default.accept_redirects=0',
      match  => '^net.ipv6.conf.default.accept_redirects',
    }
  }
  if $disable_ipv6 {
    file_line { "(3.3.3) ${file_cis} - disable ipv6":
      ensure => present,
      path   => $file_cis,
      line   => 'options ipv6 disable=1',
    }
  }
}
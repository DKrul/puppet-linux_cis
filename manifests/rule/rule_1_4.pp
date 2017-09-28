# == Class: cis_rhel7::rule::rule_1_4
# includes Rules:
# 1.4.1 - Ensure permissions on bootloader config are configured  (Scored)
# NOT USED 1.4.2 - Ensure bootloader password is set 
# NOT USED 1.4.3 - Ensure authentication required for single user mode 

class cis_rhel7::rule::rule_1_4 {
  if $::operatingsystemmajrelease == '7' {
    #1.4.1
    file { '/etc/grub.conf' :
      ensure => file,
      mode   => '0600',
      owner  => 'root',
      group  => 'root',
    }
    file { '/boot/grub2/grub.cfg' :
      ensure => file,
      mode   => '0600',
      owner  => 'root',
      group  => 'root',
    }
  } elsif $::operatingsystemmajrelease == '6'{
    #1.4.1
    file { '/boot/grub/grub.conf' :
      ensure => file,
      mode   => '0600',
      owner  => 'root',
      group  => 'root',
    }
  } else {
    notify {'Hardening not supported for your OS release, skipping':}
  }

#  notify {"NOT USED 1.4.2 - Ensure bootloader password is set ": loglevel => "debug"}
#  notify {"NOT USED 1.4.3 - Ensure authentication required for single user mode ": loglevel => "debug"}
}
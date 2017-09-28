# == Class: cis_rhel7::rule::rule_1_1
# includes Rules:
#1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)
#1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)
#1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)
#1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)
#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)
#1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored)
#1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)
#1.1.1.8 Ensure mounting of FAT filesystems is disabled (Scored)
#1.1.2 Ensure separate partition exists for /tmp (Scored)
#1.1.3 Ensure nodev option set on /tmp partition (Scored)
#1.1.4 Ensure nosuid option set on /tmp partition (Scored)
#1.1.5 Ensure noexec option set on /tmp partition (Scored)
#1.1.6 Ensure separate partition exists for /var (Scored)
#1.1.7 Ensure separate partition exists for /var/tmp (Scored)
#1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
#1.1.9 Ensure nosuid option set on /var/tmp partition (Scored)
#1.1.10 Ensure noexec option set on /var/tmp partition (Scored)
#1.1.11 Ensure separate partition exists for /var/log (Scored)
#1.1.12 Ensure separate partition exists for /var/log/audit (Scored)
#1.1.13 Ensure separate partition exists for /home (Scored)
#1.1.14 Ensure nodev option set on /home partition (Scored)
#1.1.15 Ensure nodev option set on /dev/shm partition (Scored)
#1.1.16 Ensure nosuid option set on /dev/shm partition (Scored)
#1.1.17 Ensure noexec option set on /dev/shm partition (Scored)
# NOT USED 1.1.18 Ensure nodev option set on removable media partitions (Not Scored)
# NOT USED 1.1.19 Ensure nosuid option set on removable media partitions (Not Scored)
# NOT USED 1.1.20 Ensure noexec option set on removable media partitions (Not Scored)
#1.1.21 Ensure sticky bit is set on all world - writable directories (Scored)
#1.1.22 Disable Automounting (Scored)

class cis_rhel7::rule::rule_1_1 {
  $file = '/etc/modprobe.d/CIS.conf'

  file { '/etc/modprobe.d':
    ensure => directory,
    mode   => '0755',
    owner  => 'root',
    group  => 'root',
  }
  file { $file :
    ensure => file,
    mode   => '0600',
    owner  => 'root',
    group  => 'root',
  }
  file_line { "(1.1.1.1) ${file} - cramfs":
    ensure => present,
    path   => $file,
    line   => 'install cramfs /bin/true',
  }
  file_line { "(1.1.1.2) ${file} - freevxfs":
    ensure => present,
    path   => $file,
    line   => 'install freevxfs /bin/true',
  }
  file_line { "(1.1.1.3) ${file} - jffs2":
    ensure => present,
    path   => $file,
    line   => 'install jffs2 /bin/true',
  }
  file_line { "(1.1.1.4) ${file} - hfs":
    ensure => present,
    path   => $file,
    line   => 'install hfs /bin/true',
  }
  file_line { "(1.1.1.5) ${file} - hfsplus":
    ensure => present,
    path   => $file,
    line   => 'install hfsplus /bin/true',
  }
  file_line { "(1.1.1.6) ${file} - squashfs":
    ensure => present,
    path   => $file,
    line   => 'install squashfs /bin/true',
  }
  file_line { "(1.1.1.7) ${file} - udf":
    ensure => present,
    path   => $file,
    line   => 'install udf /bin/true',
  }
  file_line { "(1.1.1.8) ${file} - udf":
    ensure => present,
    path   => $file,
    line   => 'install vfat /bin/true',
  }
  file { '(1.1.2) "/tmp" properties':
    ensure => 'directory',
    path   => '/tmp',
    mode   => '1777',
    owner  => 'root',
    group  => 'root',
  }
  #notify{"NOT USED (1.1.3 - 1.1.5) /tmp is mounted + (1.1.8 - 1.1.10) /var/tmp is mounted": loglevel => "debug"}
  #notify{"NOT USED (1.1.6) /var is mounted": loglevel => "debug"}
  #notify{"NOT USED (1.1.7) /var/tmp is bound to /tmp": loglevel => "debug"}
  #notify{"NOT USED (1.1.11) /var/log is separate mount": loglevel => "debug"}
  #notify{"NOT USED (1.1.12) /var/log/audit is separate mount": loglevel => "debug"}
  #notify{"NOT USED (1.1.13 - 1.1.14) /home is separate mount": loglevel => "debug"}
  #notify{"NOT USED (1.1.15) /dev/shm - nodev": loglevel => "debug"}
  #notify{"NOT USED (1.1.16) /dev/shm - nosuid": loglevel => "debug"}
  #notify{"NOT USED (1.1.17) /dev/shm - noexec": loglevel => "debug"}
  #notify {"NOT USED 1.1.18 Ensure nodev option set on removable media partitions": loglevel => "debug"}
  #notify {"NOT USED 1.1.19 Ensure nosuid option set on removable media partitions": loglevel => "debug"}
  #notify {"NOT USED 1.1.20 Ensure noexec option set on removable media partitions": loglevel => "debug"}
  # 1.1.21 - Set Sticky Bit on All World-Writable Directories
  $ww_dirs = $::cis_benchmarks['ww_dirs']
  #if ($ww_dirs != "") {
  #    notify { "(1.1.21) sticky bit not set on: ${ww_dirs}": loglevel => "info"}
  #}
  #1.1.22 disable automounting
  service {'autofs':
    enable => false,
  }
}
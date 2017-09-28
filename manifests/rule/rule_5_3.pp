# == Class: cis_rhel7::rule::rule_5_3
# includes Rules:
#NOT USED 5.3.1 Ensure password creation requirements are configured
#NOT USED 5.3.2 Ensure lockout for failed password attempts is configured
#NOT USED 5.3.3 Ensure password reuse is limited
#NOT USED 5.3.4 Ensure password hashing algorithm is SHA-512

class cis_rhel7::rule::rule_5_3{
  if $::operatingsystemmajrelease == '7' {
    file_line {'(5.3.1) Ensure password creation requirements are configured minlen':
      ensure => present,
      path   => '/etc/security/pwquality.conf',
      line   => 'minlen = 14',
      match  => '^minlen',
    }
    file_line {'(5.3.1) Ensure password creation requirements are configured dcredit':
      ensure => present,
      path   => '/etc/security/pwquality.conf',
      line   => 'dcredit = -1',
      match  => '^dcredit',
    }
    file_line {'(5.3.1) Ensure password creation requirements are configured ucredit':
      ensure => present,
      path   => '/etc/security/pwquality.conf',
      line   => 'ucredit = -1',
      match  => '^ucredit',
    }
    file_line {'(5.3.1) Ensure password creation requirements are configured ocredit':
      ensure => present,
      path   => '/etc/security/pwquality.conf',
      line   => 'ocredit = -1',
      match  => '^ocredit',
    }
    file_line {'(5.3.1) Ensure password creation requirements are configured lcredit':
      ensure => present,
      path   => '/etc/security/pwquality.conf',
      line   => 'lcredit = -1',
      match  => '^lcredit',
    }
  } elsif $::operatingsystemmajrelease == '6'{
    file_line {'(5.3.1) Ensure password creation requirements are configured - system-auth':
      ensure => present,
      path   => '/etc/pam.d/system-auth',
      line   => 'password requisite pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1',
      match  => '^password.*requisite.*pam_cracklib.so.*$',
    }
    file_line {'(5.3.1) Ensure password creation requirements are configured - password-auth':
      ensure => present,
      path   => '/etc/pam.d/password-auth',
      line   => 'password requisite pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1',
      match  => '^password.*requisite.*pam_cracklib.so.*$',
    }
  } else {
    notify {'Hardening not supported for your OS release, skipping':}
  }
  file_line {'(5.3.2) Ensure lockout for failed password attempts is configured pam_faillock password-auth':
    ensure => present,
    path   => '/etc/pam.d/password-auth',
    line   => 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900',
    match  => '^auth.*required.*pam_faillock.so',
  }
  file_line {'(5.3.2) Ensure lockout for failed password attempts is configured pam_faillock system-auth':
    ensure => present,
    path   => '/etc/pam.d/system-auth',
    line   => 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900',
    match  => '^auth.*required.*pam_faillock.so',
  }
# file_line {"(5.3.2) Ensure lockout for failed password attempts is configured pam_default password-auth":
#   ensure => present,
#   path => "/etc/pam.d/password-auth",
#   line => 'auth [success=1 default=bad] pam_unix.so',
#   match => '^auth.*[success=1 default=bad].*pam_unix.so',
# }

# file_line {"(5.3.2) Ensure lockout for failed password attempts is configured pam_default system-auth":
#   ensure => present,
#   path => "/etc/pam.d/system-auth",
#   line => 'auth [success=1 default=bad] pam_unix.so',
#   match => '^auth.*[success=1 default=bad].*pam_unix.so',
# }
  file_line {'(5.3.2) Ensure lockout for failed password attempts is configured pam_faillock_die password-auth':
    ensure => present,
    path   => '/etc/pam.d/password-auth',
    line   => 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900',
    match  => '^auth.*[default=die].*pam_faillock.so',
  }
  file_line {'(5.3.2) Ensure lockout for failed password attempts is configured pam_faillock_die system-auth':
    ensure => present,
    path   => '/etc/pam.d/system-auth',
    line   => 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900',
    match  => '^auth.*[default=die].*pam_faillock.so',
  }
  file_line {'(5.3.2) Ensure lockout for failed password attempts is configured faillock authsucc password-auth':
    ensure => present,
    path   => '/etc/pam.d/password-auth',
    line   => 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900',
    match  => '^auth.*sufficient.*pam_faillock.so.*authsucc',
  }
  file_line {'(5.3.2) Ensure lockout for failed password attempts is configured faillock authsucc system-auth':
    ensure => present,
    path   => '/etc/pam.d/system-auth',
    line   => 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900',
    match  => '^auth.*sufficient.*pam_faillock.so authsucc',
  }
#  notify{"NOT USED 5.3.3 Ensure password reuse is limited": loglevel => "debug" }
#  notify{"NOT USED 5.3.4 Ensure password hashing algorithm is SHA-512": loglevel => "debug" }
  file_line {'(5.3.4) Ensure password hashing algorithm is SHA-512 - password-auth':
    ensure => present,
    path   => '/etc/pam.d/password-auth',
    line   => 'password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5',
    match  => '^password.*sufficient.*pam_unix.so',
  }
  file_line {'(5.3.4) Ensure password hashing algorithm is SHA-512 - system-auth':
    ensure => present,
    path   => '/etc/pam.d/system-auth',
    line   => 'password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5',
    match  => '^password.*sufficient.*pam_unix.so',
  }
}
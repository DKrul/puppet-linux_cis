# == Class: cis_rhel7::rule::rule_1_6
# includes Rules:
#1.6.1 Configure SELinux
#1.6.1.1 Ensure SELinux is not disabled in bootloader configuration 
#1.6.1.2 Ensure the SELinux state is enforcing (Scored)
#1.6.1.3 Ensure SELinux policy is configured (Scored)
#1.6.1.4 Ensure SETroubleshoot is not installed (Scored)
#1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed 
#1.6.1.6 Ensure no unconfined daemons exist (Scored)
#1.6.2 Ensure SELinux is installed
#NOT USED; enforced from the base profile.

class cis_rhel7::rule::rule_1_6 {
#  notify {"NOT USED 1.6.1 Configure SELinux": loglevel => "debug"}
#  notify {"NOT USED 1.6.2 Ensure SELinux is installed": loglevel => "debug"}
}
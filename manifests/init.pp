# == Class: cis_rhel7
#
# This is the main class of the cis benchmark
#

class cis_rhel7 inherits ::cis_rhel7::params {
  include ::cis_rhel7::rule::rule_1_1
  include ::cis_rhel7::rule::rule_1_2
  include ::cis_rhel7::rule::rule_1_3
  include ::cis_rhel7::rule::rule_1_4
  include ::cis_rhel7::rule::rule_1_5
  include ::cis_rhel7::rule::rule_1_6
  include ::cis_rhel7::rule::rule_1_7
  include ::cis_rhel7::rule::rule_1_8
  include ::cis_rhel7::rule::rule_2_1
  include ::cis_rhel7::rule::rule_2_2
  include ::cis_rhel7::rule::rule_2_3
  include ::cis_rhel7::rule::rule_3_1
  include ::cis_rhel7::rule::rule_3_2
  include ::cis_rhel7::rule::rule_3_3
  include ::cis_rhel7::rule::rule_3_4
  include ::cis_rhel7::rule::rule_3_5
  include ::cis_rhel7::rule::rule_3_6
  include ::cis_rhel7::rule::rule_3_7
  include ::cis_rhel7::rule::rule_4_1
  include ::cis_rhel7::rule::rule_4_2
  include ::cis_rhel7::rule::rule_4_3
  include ::cis_rhel7::rule::rule_5_1
  include ::cis_rhel7::rule::rule_5_2
  include ::cis_rhel7::rule::rule_5_3
  include ::cis_rhel7::rule::rule_5_4
  include ::cis_rhel7::rule::rule_5_5
  include ::cis_rhel7::rule::rule_5_6
  include ::cis_rhel7::rule::rule_6_1
  include ::cis_rhel7::rule::rule_6_2
}

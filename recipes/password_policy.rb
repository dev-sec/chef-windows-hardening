#
# Cookbook:: windows-hardening
# Recipe:: password_policy
#
# Copyright:: (c) 2018 The Authors, All Rights Reserved.

return unless platform_family?('windows')

# Set Enforce password history to 24 or more passwords
# cis: enforce-password-history 1.1.1
password_policy 'password_history' do
  policy_command 'uniquepw'
  value 24
  action :set
end

# Set Minimum password age to 1 or more days
# cis: minimum-password-age 1.1.3
password_policy 'password_age' do
  policy_command 'minpwage'
  value 1
  action :set
end

# Set Minimum password length to 14 or more characters
# cis: minimum-password-length 1.1.4
password_policy 'password_length' do
  policy_command 'minpwlen'
  value 14
  action :set
end

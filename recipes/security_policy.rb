#
# Cookbook Name:: windows-hardening
# Recipe:: account-lockout
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# cis: account-lockout-duration 1.2.1,
# cis: reset-account-lockout 1.2.3
# windows-baseline: windows-account-104
# windows-baseline: windows-account-100,
# cis: add-workstations 2.2.4
security_policy 'Local Policy' do
  policy_template "#{node['security_policy']['template']['location']}\\mySecurityPolicy.inf"
  database "#{node['security_policy']['database']['location']}\\#{node['security_policy']['database']['name']}"
  action :configure
end

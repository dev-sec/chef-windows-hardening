#
# Cookbook Name:: windows-hardening
# Recipe:: account-lockout
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# see sec_policy attributes
security_policy 'Local Policy' do
  policy_template "#{node['security_policy']['template']['location']}\\mySecurityPolicy.inf"
  database "#{node['security_policy']['database']['location']}\\#{node['security_policy']['database']['name']}"
  action :configure
end

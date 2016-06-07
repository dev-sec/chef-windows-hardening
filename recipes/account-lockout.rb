#
# Cookbook Name:: base-win2012-hardening
# Recipe:: account-lockout
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

# start of fix for cis-account-lockout-duration-1.2.1, cis-reset-account-lockout-1.2.3, windows-account-104
# windows-account-100, cis-add-workstations-2.2.4
template 'C:\newSecurityPolicy.txt' do
  source 'newSecurityPolicy.erb'
  rights :read, 'Everyone'
  action :create_if_missing
  notifies :run, 'execute[Import security policy settings]', :immediately
end

execute 'Import security policy settings' do
  command 'secedit.exe /configure /db "secedit.sdb" /cfg C:\newSecurityPolicy.txt'
  action :nothing
end

# end of fix for cis-account-lockout-duration-1.2.1, cis-reset-account-lockout-1.2.3, windows-account-104
# windows-account-100, cis-add-workstations-2.2.4
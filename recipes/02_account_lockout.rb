#
# Cookbook Name:: base-win2012-hardening
# Recipe:: account-lockout
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

# start of fix for cis-account-lockout-duration-1.2.1,
# cis-reset-account-lockout-1.2.3, windows-account-104 windows-account-100,
# cis-add-workstations-2.2.4
template 'C:\newSecurityPolicy.txt' do
  source 'newSecurityPolicy.erb'
  rights :read, 'Everyone'
#  notifies :run, 'execute[Import security policy settings]', :immediately
end

powershell_script 'Import security policy settings' do
#  command 'secedit.exe /configure /db "secedit.sdb" /cfg C:\newSecurityPolicy.txt'
  code 'secedit /configure /db secedit.sdb /cfg C:/newSecurityPolicy.txt /overwrite /quiet'
#  action :nothing
end

execute 'Refresh policy settings' do
  command 'secedit /refreshpolicy machine_policy /enforce /quiet'
  action :run
end

# end of fix for cis-account-lockout-duration-1.2.1,
# cis-reset-account-lockout-1.2.3, windows-account-104 windows-account-100,
# cis-add-workstations-2.2.4

#
# Cookbook Name:: windows-hardening
# Recipe:: account-lockout
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

# cis: account-lockout-duration 1.2.1,
# cis: reset-account-lockout 1.2.3
# windows-baseline: windows-account-104
# windows-baseline: windows-account-100,
# cis: add-workstations 2.2.4
template 'C:\windows\security\templates\hardeningSecurityPolicy.inf' do
  source 'hardeningSecurityPolicy.erb'
  rights :read, 'Everyone'
  action :create
end

execute 'Import security policy settings' do
  command 'Secedit /configure /db hardening.sdb /cfg C:\windows\security\templates\hardeningSecurityPolicy.inf'
  cwd 'C:/Windows/security/database'
  live_stream true
  action :run
end

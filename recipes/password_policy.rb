#
# Cookbook Name:: windows-hardening
# Recipe:: password
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Set Enforce password history to 24 or more passwords
# cis: enforce-password-history 1.1.1
execute 'Password history' do
  command 'net accounts /uniquepw:24'
  action :run
  not_if { ::File.exist?('C:\passHistory.lock') }
  notifies :create, 'file[C:\passHistory.lock]', :immediately
end

file 'C:\passHistory.lock' do
  action :create
end

# Set Minimum password age to 1 or more days
# cis: minimum-password-age 1.1.3
execute 'Minimum password age' do
  command 'net accounts /minpwage:1'
  action :run
  not_if { ::File.exist?('C:\minPassAge.lock') }
  notifies :create, 'file[C:\minPassAge.lock]', :immediately
end

file 'C:\minPassAge.lock' do
  action :nothing
end

# Set Minimum password length to 14 or more characters
# cis: minimum-password-length 1.1.4
execute 'Minimum password length' do
  command 'net accounts /minpwlen:14'
  action :run
  not_if { ::File.exist?('C:\minPassLength.lock') }
  notifies :create, 'file[C:\minPassLength.lock]', :immediately
end

file 'C:\minPassLength.lock' do
  action :nothing
end

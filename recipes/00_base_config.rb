#
# Cookbook Name:: base-win2012-hardening
# Recipe:: 00_base_config
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.


case node['kernel']['os_info']['os_architecture']
when '64-bit'
  windows_package 'powerShellGet module 64' do
    source 'https://download.microsoft.com/download/C/4/1/C41378D4-7F41-4BBE-9D0D-0E4F98585C61/PackageManagement_x64.msi'
    installer_type :msi
    action :install
    options '/quiet /norestart'
  end
when '32-bit'
  windows_package 'powerShellGet module 32' do
    source 'https://download.microsoft.com/download/C/4/1/C41378D4-7F41-4BBE-9D0D-0E4F98585C61/PackageManagement_x86.msi'
    installer_type :msi
    action :install
    options '/quiet /norestart'
  end
end

#include_recipe 'powershell::powershell5'

#chocolatey_package 'powershell'

#powershell_module 'cSecurityOptions' do
#  package_name 'cSecurityOptions'
#  action :install
#end

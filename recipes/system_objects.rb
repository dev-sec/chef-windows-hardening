#
# Cookbook Name:: windows-hardening
# Recipe:: system_objects
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'System objects: Require case insensitivity for non-Windows subsystems\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.15.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.15.1'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel' do
  values [{
    name: 'ObCaseInsensitive',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.15.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.15.2'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager' do
  values [{
    name: 'ProtectionMode',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

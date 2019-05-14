#
# Cookbook Name:: windows-hardening
# Recipe:: network_client
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Microsoft network client: Digitally sign communications (always)\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.1'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do # ignore: ~FC005
  values [{
    name: 'RequireSecuritySignature',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Microsoft network client: Digitally sign communications (if server agrees)\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.2'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{
    name: 'EnableSecuritySignature',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Microsoft network client: Send unencrypted password to third-party SMB servers\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.8.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.8.3'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{
    name: 'EnablePlainTextPassword',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

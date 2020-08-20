#
# Cookbook Name:: windows-hardening
# Recipe:: network_server
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Microsoft network server: Amount of idle time required before suspending session\' is set to \'15 or fewer minute(s), but not 0\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.1'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do # ignore: ~FC005
  values [{
    name: 'AutoDisconnect',
    type: :dword,
    data: 15
  }]
  action :create
  recursive true
end

# Ensure \'Microsoft network server: Digitally sign communications (always)\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.2'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'RequireSecuritySignature',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Microsoft network server: Digitally sign communications (if client agrees)\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.3'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'EnableSecuritySignature',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Microsoft network server: Disconnect clients when logon hours expire\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.4'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'EnableForcedLogoff',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Microsoft network server: Server SPN target name validation level\' is set to \'Accept if provided by client\' or higher\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.9.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.9.5'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'SMBServerNameHardeningLevel',
    type: :dword,
    data: 2
  }]
  action :create
  recursive true
end

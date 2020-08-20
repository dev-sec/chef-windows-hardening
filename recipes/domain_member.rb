#
# Cookbook Name:: windows-hardening
# Recipe:: domain_member
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows' && node['windows_hardening']['ms_or_dc'] == 'MS'

# Ensure \'Domain member: Digitally encrypt or sign secure channel data (always)\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.1'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do # ignore: ~FC005
  values [{
    name: 'RequireSignOrSeal',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Domain member: Digitally encrypt secure channel data (when possible)\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.2'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{
    name: 'SealSecureChannel',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Domain member: Digitally sign secure channel data (when possible)\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.3'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{
    name: 'SignSecureChannel',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Domain member: Disable machine account password changes\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.4'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{
    name: 'DisablePasswordChange',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Domain member: Maximum machine account password age\' is set to \'30 or fewer days, but not 0\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.5'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{
    name: 'MaximumPasswordAge',
    type: :dword,
    data: 30
  }]
  action :create
  recursive true
end

# Ensure \'Domain member: Require strong (Windows 2000 or later) session key\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.6.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.6.6'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{
    name: 'RequireStrongKey',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

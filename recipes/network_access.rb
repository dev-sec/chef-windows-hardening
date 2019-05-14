#
# Cookbook Name:: windows-hardening
# Recipe:: network_access
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Network access: Do not allow anonymous enumeration of SAM accounts\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.2'
if node['windows_hardening']['ms_or_dc'] == 'MS'
  registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    values [{
      name: 'RestrictAnonymousSAM',
      type: :dword,
      data: 1
    }]
    action :create
    recursive true
  end
end

# Ensure \'Network access: Do not allow anonymous enumeration of SAM accounts and shares\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.3'
if node['windows_hardening']['ms_or_dc'] == 'MS'
  registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    values [{
      name: 'RestrictAnonymous',
      type: :dword,
      data: 1
    }]
    action :create
    recursive true
  end
end

# Ensure \'Network access: Do not allow storage of passwords and credentials for network authentication\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.4'
if node['windows_hardening']['level_1_or_2'] == 2
  registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
    values [{
      name: 'DisableDomainCreds',
      type: :dword,
      data: 1
    }]
    action :create
    recursive true
  end
end

# Ensure \'Network access: Let Everyone permissions apply to anonymous users\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.5'
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'EveryoneIncludesAnonymous',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Configure \'Network access: Named Pipes that can be accessed anonymously\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.3.10.6', '2.3.10.7']
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'NullSessionPipes',
    type: :multi_string,
    data: []
  }]
  action :create
  recursive true
end

# Configure \'Network access: Remotely accessible registry paths\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.7'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.8'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths' do
  values [{
    name: 'Machine',
    type: :multi_string,
    data: ['System\\CurrentControlSet\\Control\\ProductOptions', 'System\\CurrentControlSet\\Control\\Server Applications', 'Software\\Microsoft\\Windows NT\\CurrentVersion']
  }]
  action :create
  recursive true
end

# Configure \'Network access: Remotely accessible registry paths and sub-paths\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.8'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.9'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths' do
  values [{
    name: 'Machine',
    type: :multi_string,
    data: ['System\\CurrentControlSet\\Control\\Print\\Printers', 'System\\CurrentControlSet\\Services\\Eventlog', 'Software\\Microsoft\\OLAP Server', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows', 'System\\CurrentControlSet\\Control\\ContentIndex', 'System\\CurrentControlSet\\Control\\Terminal Server', 'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig', 'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib', 'System\\CurrentControlSet\\Services\\SysmonLog']
  }]
  action :create
  recursive true
end

# Ensure \'Network access: Restrict anonymous access to Named Pipes and Shares\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.9'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.10'
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'RestrictNullSessAccess',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Network access: Restrict clients allowed to make remote calls to SAM\' is set to \'Administrators: Remote Access: Allow\'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.11'
if node['platform_version'].to_f == 10.0
  registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
    values [{
      name: 'restrictremotesam',
      type: :string,
      data: 'O:BAG:BAD:(A;;RC;;;BA)'
    }]
    action :create
    recursive true
  end
end

# Ensure \'Network access: Shares that can be accessed anonymously\' is set to \'None\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.10'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.12'
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'NullSessionShares',
    type: :multi_string,
    data: []
  }]
  action :create
  recursive true
end

# Ensure \'Network access: Sharing and security model for local accounts\' is set to \'Classic - local users authenticate as themselves\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.10.11'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.10.13'
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'ForceGuest',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Network security: Allow Local System to use computer identity for NTLM\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.1'
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'UseMachineId',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

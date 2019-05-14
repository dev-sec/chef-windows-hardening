#
# Cookbook Name:: windows-hardening
# Recipe:: windows_firewall
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows' && node['firewall']['activate'] == true

# Ensure \'Windows Firewall: Domain: Firewall state\' is set to \'On (recommended)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.1'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' do
  values [{
    name: 'EnableFirewall',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Domain: Inbound connections\' is set to \'Block (default)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.2'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' do
  values [{
    name: 'DefaultInboundAction',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Domain: Outbound connections\' is set to \'Allow (default)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.3'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' do
  values [{
    name: 'DefaultOutboundAction',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Domain: Settings: Display a notification\' is set to \'No\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.4'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' do
  values [{
    name: 'DisableNotifications',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Domain: Logging: Name\' is set to \'%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.5'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging' do
  values [{
    name: 'LogFilePath',
    type: :string,
    data: '%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log'
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Domain: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.6'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging' do
  values [{
    name: 'LogFileSize',
    type: :dword,
    data: 16_384
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Domain: Logging: Log dropped packets\' is set to \'Yes\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.7'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.7'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging' do
  values [{
    name: 'LogDroppedPackets',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Domain: Logging: Log successful connections\' is set to \'Yes\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.1.8'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.1.8'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging' do
  values [{
    name: 'LogSuccessfulConnections',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Private: Firewall state\' is set to \'On (recommended)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.1'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' do
  values [{
    name: 'EnableFirewall',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Private: Inbound connections\' is set to \'Block (default)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.2'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' do
  values [{
    name: 'DefaultInboundAction',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Private: Outbound connections\' is set to \'Allow (default)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.3'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' do
  values [{
    name: 'DefaultOutboundAction',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Private: Settings: Display a notification\' is set to \'No\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.4'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' do
  values [{
    name: 'DisableNotifications',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Private: Logging: Name\' is set to \'%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.5'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging' do
  values [{
    name: 'LogFilePath',
    type: :string,
    data: '%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log'
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Private: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.6'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging' do
  values [{
    name: 'LogFileSize',
    type: :dword,
    data: 16_384
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Private: Logging: Log dropped packets\' is set to \'Yes\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.7'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.7'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging' do
  values [{
    name: 'LogDroppedPackets',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Private: Logging: Log successful connections\' is set to \'Yes\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.2.8'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.2.8'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging' do
  values [{
    name: 'LogSuccessfulConnections',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Firewall state\' is set to \'On (recommended)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.1'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' do
  values [{
    name: 'EnableFirewall',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Inbound connections\' is set to \'Block (default)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.2'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' do
  values [{
    name: 'DefaultInboundAction',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Outbound connections\' is set to \'Allow (default)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.3'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' do
  values [{
    name: 'DefaultOutboundAction',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Settings: Display a notification\' is set to \'Yes\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.4'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' do
  values [{
    name: 'DisableNotifications',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Settings: Apply local firewall rules\' is set to \'No\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.5'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' do
  values [{
    name: 'AllowLocalPolicyMerge',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Settings: Apply local connection security rules\' is set to \'No\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.6'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' do
  values [{
    name: 'AllowLocalIPsecPolicyMerge',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Logging: Name\' is set to \'%SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.7'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.7'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging' do
  values [{
    name: 'LogFilePath',
    type: :string,
    data: '%SYSTEMROOT%\\system32\\logfiles\\firewall\\publicfw.log'
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.8'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.8'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging' do
  values [{
    name: 'LogFileSize',
    type: :dword,
    data: 16_384
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Logging: Log dropped packets\' is set to \'Yes\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.9'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.9'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging' do
  values [{
    name: 'LogDroppedPackets',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Windows Firewall: Public: Logging: Log successful connections\' is set to \'Yes\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '9.3.10'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '9.3.10'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging' do
  values [{
    name: 'LogSuccessfulConnections',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# setup some basic firewall rules, it is just required to test this cookbook
if node['firewall']['rules_on'] == true
  node['firewall']['rules'].each do |rule|
    windows_firewall_rule rule['name'] do
      local_port rule['local_port']
      protocol rule['protocol']
      firewall_action rule['action']
    end
  end
end

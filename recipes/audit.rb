#
# Cookbook Name:: windows-hardening
# Recipe:: audit-logging
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.2.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.2.1'
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa' do
  values [{
    name: 'SCENoApplyLegacyAuditPolicy',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Audit: Shut down system immediately if unable to log security audits\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.2.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.2.2'
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa' do
  values [{
    name: 'CrashOnAuditFail',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Configure System Event Log (Application)
# windows-baseline: windows-audit-100
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 4_194_240
  }]
  recursive true
  action :create
end

# Configure System Event Log (Security)
# windows-baseline: windows-audit-101
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 4_194_240
  }]
  recursive true
  action :create
end

# Configure System Event Log (Setup)
# windows-baseline: windows-audit-102
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 4_194_240
  }]
  recursive true
  action :create
end

# Configure System Event Log (System)
# windows-baseline: windows-audit-103
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 4_194_240
  }]
  recursive true
  action :create
end

# Account Logon Audit Log
# windows-baseline: windows-audit-203

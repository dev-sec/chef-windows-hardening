#
# Cookbook Name:: windows-hardening
# Recipe:: audit-logging
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Configure System Event Log (Application)
# windows-baseline: windows-audit-100
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 1
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
    data: 1
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
    data: 1
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
    data: 1
  }]
  recursive true
  action :create
end

# Account Logon Audit Log
# windows-baseline: windows-audit-203
execute 'Account Logon Audit Log' do
  command 'AuditPol /Set /Category:"Account Logon" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\accountLogonAudit.lock') }
  notifies :create, 'file[C:\accountLogonAudit.lock]', :immediately
end

file 'C:\accountLogonAudit.lock' do
  action :nothing
end

# Audit Application Group Management
# windows-baseline: windows-audit-204
execute 'Audit Application Group Management' do
  command 'AuditPol /Set /SubCategory:"Application Group Management" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\appGroupMngmtAudit.lock') }
  notifies :create, 'file[C:\appGroupMngmtAudit.lock]', :immediately
end

file 'C:\appGroupMngmtAudit.lock' do
  action :nothing
end

# Audit Computer Account Management
# windows-baseline: windows-audit-205
execute 'Audit Computer Account Management' do
  command 'AuditPol /Set /SubCategory:"Computer Account Management" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\appAccountMngmtAudit.lock') }
  notifies :create, 'file[C:\appAccountMngmtAudit.lock]', :immediately
end

file 'C:\appAccountMngmtAudit.lock' do
  action :nothing
end

# Audit Distributed Group Management
# windows-baseline: windows-audit-206
execute 'Audit Distributed Group Management' do
  command 'AuditPol /Set /SubCategory:"Distribution Group Management" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\distGroupMngmtAudit.lock') }
  notifies :create, 'file[C:\distGroupMngmtAudit.lock]', :immediately
end

file 'C:\distGroupMngmtAudit.lock' do
  action :nothing
end

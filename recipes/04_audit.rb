#
# Cookbook Name:: base-win2012-hardening
# Recipe:: audit-logging
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

# start of fix for windows-audit-100 - Configure System Event Log (Application)
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end
# end of fix for windows-base-100 - Configure System Event Log (Application)

# start of fix for windows-audit-101 - Configure System Event Log (Security)
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end
# end of fix for windows-base-101 - Configure System Event Log (Security)

# start of fix for windows-audit-102 - Configure System Event Log (Setup)
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end
# end of fix for windows-base-102 - Configure System Event Log (Setup)

# start of fix for windows-audit-103 - Configure System Event Log (System)
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end
# end of fix for windows-base-103 - Configure System Event Log (System)

# start of fix for windows-audit-203 - Account Logon Audit Log
execute 'Account Logon Audit Log' do
  command 'AuditPol /Set /Category:"Account Logon" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\accountLogonAudit.lock') }
  notifies :create, 'file[C:\accountLogonAudit.lock]', :immediately
end

file 'C:\accountLogonAudit.lock' do
  action :nothing
end
# end of fix for windows-audit-203 - Account Logon Audit Log

# start of fix for windows-audit-204 - Audit Application Group Management
execute 'Audit Application Group Management' do
  command 'AuditPol /Set /SubCategory:"Application Group Management" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\appGroupMngmtAudit.lock') }
  notifies :create, 'file[C:\appGroupMngmtAudit.lock]', :immediately
end

file 'C:\appGroupMngmtAudit.lock' do
  action :nothing
end
# end of fix for windows-audit-204 - Audit Application Group Management

# start of fix for windows-audit-206 - Audit Distributed Group Management
execute 'Audit Distributed Group Management' do
  command 'AuditPol /Set /SubCategory:"Distribution Group Management" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\distGroupMngmtAudit.lock') }
  notifies :create, 'file[C:\distGroupMngmtAudit.lock]', :immediately
end

file 'C:\distGroupMngmtAudit.lock' do
  action :nothing
end
# end of fix for windows-audit-206 - Audit Distributed Group Management

#
# Cookbook Name:: windows-hardening
# Recipe:: advanced_audit_policy_configuration
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

# 'Ensure \'Audit Credential Validation\' is set to \'Success and Failure\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.1.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.1.1'
execute 'Audit Credential Validation' do
  command 'AuditPol /Set /SubCategory:"Credential Validation" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\CredentialValidation.lock') }
  notifies :create, 'file[C:\CredentialValidation.lock]', :immediately
end

file 'C:\CredentialValidation.lock' do
  action :nothing
end

# Ensure \'Audit Application Group Management\' is set to \'Success and Failure\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.1'
execute 'Audit Application Group Management' do
  command 'AuditPol /Set /SubCategory:"Application Group Management" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\appGroupMngmtAudit.lock') }
  notifies :create, 'file[C:\appGroupMngmtAudit.lock]', :immediately
end

file 'C:\appGroupMngmtAudit.lock' do
  action :nothing
end

# Ensure \'Audit Computer Account Management\' is set to \'Success and Failure\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.2'
execute 'Audit Computer Account Management' do
  command 'AuditPol /Set /SubCategory:"Computer Account Management" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\appAccountMngmtAudit.lock') }
  notifies :create, 'file[C:\appAccountMngmtAudit.lock]', :immediately
end

file 'C:\appAccountMngmtAudit.lock' do
  action :nothing
end

# Ensure \'Audit Distribution Group Management\' is set to \'Success and Failure\' (DC only)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.3'
if node['windows_hardening']['ms_or_dc'] == 'DC'
  execute 'Audit Distributed Group Management' do
    command 'AuditPol /Set /SubCategory:"Distribution Group Management" /Failure:Enable /Success:Enable'
    action :run
    not_if { ::File.exist?('C:\distGroupMngmtAudit.lock') }
    notifies :create, 'file[C:\distGroupMngmtAudit.lock]', :immediately
  end

  file 'C:\distGroupMngmtAudit.lock' do
    action :nothing
  end
end

# Ensure \'Audit Other Account Management Events\' is set to \'Success and Failure\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '17.2.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '17.2.4'
execute 'Other Account Management Events' do
  command 'AuditPol /Set /SubCategory:"Other Account Management Events" /Failure:Enable /Success:Enable'
  action :run
  not_if { ::File.exist?('C:\OtherAccountManagementEvents.lock') }
  notifies :create, 'file[C:\OtherAccountManagementEvents.lock]', :immediately
end

file 'C:\OtherAccountManagementEvents.lock' do
  action :nothing
end

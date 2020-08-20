#
# Cookbook Name:: windows-hardening
# Recipe:: account_status
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Accounts: Administrator account status\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.1'
# Ensure \'Accounts: Guest account status\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.3'
node['account_status']['names'].each do |name|
  account_status "disable #{name} account" do
    account_name name
    value node['account_status']['active_yes_no']
    action :set
  end
end

# Ensure \'Accounts: Block Microsoft accounts\' is set to \'Users can\'t add or log on with Microsoft accounts\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.2'
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{
    name: 'NoConnectedUser',
    type: :dword,
    data: 3
  }]
  action :create
  recursive true
end

# Ensure \'Accounts: Limit local account use of blank passwords to console logon only\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.4'
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa' do
  values [{
    name: 'LimitBlankPasswordUse',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Configure \'Accounts: Rename administrator account\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.5'
if node['rename_account']['admin_account'] == true
  rename_account "rename Administrator name to #{node['rename_account']['new_admin_name']} account" do
    original_name 'Administrator'
    new_name node['rename_account']['new_admin_name']
    action :set
  end
end

# Configure \'Accounts: Rename guest account\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.1.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.1.6'
if node['rename_account']['guest_account'] == true
  rename_account "rename Guest name to #{node['rename_account']['new_guest_name']} account" do
    original_name 'Guest'
    new_name node['rename_account']['new_guest_name']
    action :set
  end
end

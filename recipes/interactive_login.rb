#
# Cookbook Name:: windows-hardening
# Recipe:: interactive_login
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Interactive logon: Do not display last user name\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.1'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'DontDisplayLastUserName',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Interactive logon: Do not require CTRL+ALT+DEL\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.2'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'DisableCAD',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Interactive logon: Machine inactivity limit\' is set to \'900 or fewer second(s), but not 0\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.3'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'InactivityTimeoutSecs',
    type: :dword,
    data: 900
  }]
  action :create
  recursive true
end

# Configure \'Interactive logon: Message text for users attempting to log on\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.4'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'LegalNoticeText',
    type: :string,
    data: node['interactive_login']['LegalNoticeText']
  }]
  action :create
  recursive true
end

# Configure \'Interactive logon: Message title for users attempting to log on\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.5'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'LegalNoticeCaption',
    type: :string,
    data: node['interactive_login']['LegalNoticeCaption']
  }]
  action :create
  recursive true
end

# Ensure \'Interactive logon: Number of previous logons to cache (in case domain controller is not available)\' is set to \'4 or fewer logon(s)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.6'
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{
    name: 'CachedLogonsCount',
    type: :dword,
    data: 4
  }]
  action :create
  recursive true
end

# Ensure \'Interactive logon: Prompt user to change password before expiration\' is set to \'between 5 and 14 days\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.7'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.7'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{
    name: 'PasswordExpiryWarning',
    type: :dword,
    data: 14
  }]
  action :create
  recursive true
end

# Ensure \'Interactive logon: Require Domain Controller Authentication to unlock workstation\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.8'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.8'
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{
    name: 'ForceUnlockLogon',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Interactive logon: Smart card removal behavior\' is set to \'Lock Workstation\' or higher
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.7.9'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.7.9'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{
    name: 'ScRemoveOption',
    type: :string,
    data: 1
  }]
  action :create
  recursive true
end

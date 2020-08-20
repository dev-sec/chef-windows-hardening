#
# Cookbook Name:: windows-hardening
# Recipe:: user_account_control
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'User Account Control: Admin Approval Mode for the Built-in Administrator account\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.1'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do # ignore: ~FC005
  values [{
    name: 'FilterAdministratorToken',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.2'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'EnableUIADesktopToggle',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode\' is set to \'Prompt for consent on the secure desktop\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.3'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'ConsentPromptBehaviorAdmin',
    type: :dword,
    data: 2
  }]
  action :create
  recursive true
end

# Ensure \'User Account Control: Behavior of the elevation prompt for standard users\' is set to \'Automatically deny elevation requests\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.4'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'ConsentPromptBehaviorUser',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'User Account Control: Detect application installations and prompt for elevation\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.5'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'EnableInstallerDetection',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'User Account Control: Only elevate UIAccess applications that are installed in secure locations\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.6'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'EnableSecureUIAPaths',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'User Account Control: Run all administrators in Admin Approval Mode\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.7'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.7'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'EnableLUA',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'User Account Control: Switch to the secure desktop when prompting for elevation\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.8'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.8'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'PromptOnSecureDesktop',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'User Account Control: Virtualize file and registry write failures to per-user locations\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.17.9'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.17.9'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'EnableVirtualization',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

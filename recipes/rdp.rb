#
# Cookbook Name:: base-win2012-hardening
# Recipe:: rdp
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

# start of fix for windows-rdp-100 - Windows Remote Desktop Configured to Always Prompt for Password
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{
    name: 'fPromptForPassword',
    type: :dword,
    data: 1
  }]
  action :create
end
# end of fix for windows-rdp-100 - Windows Remote Desktop Configured to Always Prompt for Password

# start of fix for windows-rdp-101 - Strong Encryption for Windows Remote Desktop Required
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{
    name: 'MinEncryptionLevel',
    type: :dword,
    data: 3
  }]
  action :create
end
# end of fix for windows-rdp-101 - Strong Encryption for Windows Remote Desktop Required
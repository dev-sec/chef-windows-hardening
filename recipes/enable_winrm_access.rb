#
# Cookbook Name:: base-win2012-hardening
# Recipe:: enable_winrm_access
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

# Winrm access is required for agentless verification. Add this recipe as required.

powershell_script 'Remote Management' do
  code 'Set-NetFirewallRule WINRM-HTTP-In-TCP-PUBLIC -RemoteAddress "any"'
end

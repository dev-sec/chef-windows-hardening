#
# Cookbook Name:: windows-hardening
# Recipe:: default
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# include_recipe 'windows-hardening::password_policy'
include_recipe 'windows-hardening::accounts'
include_recipe 'windows-hardening::security_policy'
include_recipe 'windows-hardening::devices'
include_recipe 'windows-hardening::domain_controller'
include_recipe 'windows-hardening::domain_member'
include_recipe 'windows-hardening::interactive_login'
include_recipe 'windows-hardening::network_client'
include_recipe 'windows-hardening::network_server'
include_recipe 'windows-hardening::network_access'
include_recipe 'windows-hardening::network_security'
include_recipe 'windows-hardening::shutdown'
include_recipe 'windows-hardening::system_objects'
include_recipe 'windows-hardening::user_account_control'
include_recipe 'windows-hardening::windows_firewall'
include_recipe 'windows-hardening::advanced_audit_policy_configuration'

include_recipe 'windows-hardening::audit'
include_recipe 'windows-hardening::ie'
include_recipe 'windows-hardening::rdp'
include_recipe 'windows-hardening::access'
include_recipe 'windows-hardening::privacy'
include_recipe 'windows-hardening::powershell'

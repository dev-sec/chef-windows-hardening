# encoding: utf-8

# Cookbook Name:: windows-hardening
# Attributes:: account

# define which accounts should be disabled
default['account_status']['names'] = %w[Administrator Guest]
default['account_status']['active_yes_no'] = 'no'

# define the new account names for Administrator and Guest
default['rename_account']['admin_account'] = true
default['rename_account']['guest_account'] = true
default['rename_account']['new_admin_name'] = 'CustomAdminName'
default['rename_account']['new_guest_name'] = 'CustomGuestName'

#
# Cookbook Name:: base-win2012-hardening
# Recipe:: default
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

include_recipe 'base-win2012-hardening::00_base_config'
#include_recipe 'base-win2012-hardening::01_password_policy'
#include_recipe 'base-win2012-hardening::02_account_lockout'
#include_recipe 'base-win2012-hardening::03_user_rights'
#include_recipe 'base-win2012-hardening::04_audit'
#include_recipe 'base-win2012-hardening::05_ie'
#include_recipe 'base-win2012-hardening::07_rdp'
#include_recipe 'base-win2012-hardening::08_access'

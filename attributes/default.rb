# encoding: utf-8

# Cookbook Name:: windows-hardening
# Attributes:: default

# set this value if you want to harden terminal services
default['windows_hardening']['rdp']['harden'] = true
default['windows_hardening']['smbv1']['disable'] = true

# apply MS or DC configuration, possible values MS or DC
default['windows_hardening']['ms_or_dc'] = 'MS'

# apply Level 1 or 2 configuration, possible values 1 or 2
default['windows_hardening']['level_1_or_2'] = 1

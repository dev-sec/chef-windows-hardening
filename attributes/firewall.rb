# encoding: utf-8

# Cookbook Name:: windows-hardening
# Attributes:: firewall

# set this value if you want to activate Firewall
default['firewall']['activate'] = false

# set this value if you want to add firewall rules
default['firewall']['rules_on'] = false

# add some simply firewall rule, but it is recommended to apply this with an overlay cookbook
# its an array of hashes like, [{'name':'rdp','local_port': 3389,'protocol': 'TCP', 'action': 'allow'},{'name':'winrm','local_port': 5985,'protocol': 'TCP', 'action': 'allow'}]
default['firwall']['rules'] = []

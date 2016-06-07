# base-win2012-hardening

TODO: Enter the cookbook description here.

# Manual boot node
`knife ec2 server create --node-name windows-test --flavor t2.medium --image ami-29eb7e5a --security-group-ids sg-238e5744 --user-data win-userdata.ps1 --winrm-user Administrator --winrm-password Ch4ng3m3 --ssh-key emea-sa-shared -r 'recipe[base-win2012-hardening::enable-winrm-access]'`

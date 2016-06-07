<powershell>
# Set our admin password
$admin = [adsi]("WinNT://./Administrator, user")
$admin.psbase.invoke("SetPassword", "Ch4ng3m3")
# Turn on WinRM, make sure to relax its security a bit.
# Please don't expose the WinRM port to the world on these machines.
# I am not responsible for anything that happens if you do.
winrm qc -q
winrm set winrm/config '@{MaxTimeoutms="1800000"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
# Make sure to trust all hosts
Set-Item wsman:localhost\client\trustedhosts -value * -force
# Turn off the Windows firewall. Its default WinRM rules only allow traffic from
# hosts in your domain and from "private" networks. Its functionality is superseded
# by security groups anyway.
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False
# Stop the WinRM service, make sure it autostarts on reboot, and start it
net stop winrm
sc.exe config winrm start=auto
net start winrm
</powershell>

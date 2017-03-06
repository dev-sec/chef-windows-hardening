# encoding: utf-8

# Inspec test for CIS_2012r2_L1
#
# Copyright (c) 2017 Matt Tunny, All Rights Reserved.
#
# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# WinLogon Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
  its('PasswordExpiryWarning') { should eq 14 }
  its('ScreenSaverGracePeriod') { should eq '5' }
  its('AllocateDASD') { should eq '0' }
  its('ScRemoveOption') { should eq '1' }
  its('CachedLogonsCount') { should eq '4' }
end

# LSA tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
  its('FullPrivilegeAuditing') { should eq [01] }
  its('AuditBaseObjects') { should eq 1 }
  its('scenoapplylegacyauditpolicy') { should eq 1 }
  its('DisableDomainCreds') { should eq 1 }
  its('LimitBlankPasswordUse') { should eq 1 }
  its('CrashOnAuditFail') { should eq 0 }
  its('RestrictAnonymousSAM') { should eq 1 }
  its('RestrictAnonymous') { should eq 0 }
  its('SubmitControl') { should eq 0 }
  its('ForceGuest') { should eq 0 }
  its('EveryoneIncludesAnonymous') { should eq 0 }
  its('NoLMHash') { should eq 1 }
  its('LmCompatibilityLevel') { should eq 5 }
end

# LSA Pku2 tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u') do
  its('AllowOnlineID') { should eq 0 }
end

# LSA MSV1_0 Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
  its('NTLMMinServerSec') { should eq 537_395_200 }
  its('allownullsessionfallback') { should eq 0 }
  its('NTLMMinClientSec') { should eq 537_395_200 }
  its('AuditReceivingNTLMTraffic') { should eq 2 }
end

# NTLM Test
# describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
#  its('RestrictReceivingNTLMTraffic') { should eq 2 }
#  its('RestrictSendingNTLMTraffic') { should eq 2 }
# end

# FIPS FIPSAlgorithmPolicy Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy') do
  its('Enabled') { should eq 0 }
end

# Netlogon Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
  its('MaximumPasswordAge') { should eq 30 }
  its('DisablePasswordChange') { should eq 0 }
  its('RefusePasswordChange') { should eq 0 }
  its('SealSecureChannel') { should eq 1 }
  its('RequireSignOrSeal') { should eq 1 }
  its('SignSecureChannel') { should eq 1 }
  its('RequireStrongKey') { should eq 1 }
  its('RestrictNTLMInDomain') { should eq 7 }
  its('AuditNTLMInDomain') { should eq 7 }
end

# TCPIP v4 Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
  its('DisableIPSourceRouting') { should eq 2 }
  its('TcpMaxDataRetransmissions') { should eq 3 }
end

# TCPIP v6 Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
  its('DisableIPSourceRouting') { should eq 2 }
  its('TcpMaxDataRetransmissions') { should eq 3 }
end

# Windows System Policies Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
  its('ConsentPromptBehaviorUser') { should eq 0 }
  its('EnableLUA') { should eq 1 }
  its('PromptOnSecureDesktop') { should eq 1 }
  its('EnableVirtualization') { should eq 1 }
  its('EnableUIADesktopToggle') { should eq 0 }
  its('ConsentPromptBehaviorAdmin') { should eq 2 }
  # its('LocalAccountTokenFilterPolicy') { should eq 0 } Removed due to breaking Test-Kitchen
  its('EnableSecureUIAPaths') { should eq 1 }
  its('FilterAdministratorToken') { should eq 1 }
  its('MaxDevicePasswordFailedAttempts') { should eq 10 }
  its('DontDisplayLastUserName') { should eq 1 }
  its('DontDisplayLockedUserId') { should eq 3 }
  its('InactivityTimeoutSecs') { should eq 900 }
  its('EnableInstallerDetection') { should eq 1 }
  its('DisableCAD') { should eq 0 }
  its('ShutdownWithoutLogon') { should eq 0 }
  its('legalnoticecaption') { should eq 'Legal caption here' }
  its('legalnoticetext') do
    should eq 'Legal text and harsh warnings etc here.....'
  end
end

# LanMan Server Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters') do
  its('enablesecuritysignature') { should eq 1 }
  its('requiresecuritysignature') { should eq 1 }
  its('RestrictNullSessAccess') { should eq 1 }
  its('enableforcedlogoff') { should eq 1 }
  its('autodisconnect') { should eq 15 }
  its('SMBServerNameHardeningLevel') { should eq 0 }
end

# Lanman Workstations Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
  its('RequireSecuritySignature') { should eq 1 }
  its('EnableSecuritySignature') { should eq 1 }
  its('EnablePlainTextPassword') { should eq 0 }
end

# LDAP Client Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP') do
  its('LDAPClientIntegrity') { should eq 1 }
end

# LDAP Server Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters') do
  its('LDAPServerIntegrity') { should eq 2 }
end

# Session Manager Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
  its('ProtectionMode') { should eq 1 }
  its('SafeDllSearchMode') { should eq 1 }
end

# EMET (IE)Parameters Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults') do
  its('IE') { should eq '*\Internet Explorer\iexplore.exe' }
  its('7z') { should eq '*\7-Zip\7z.exe -EAF' }
  its('7zFM') { should eq '*\7-Zip\7zFM.exe -EAF' }
  its('7zGUI') { should eq '*\7-Zip\7zG.exe -EAF' }
  its('Access') { should eq '*\OFFICE1*\MSACCESS.EXE' }
  its('Acrobat') { should eq '*\Adobe\Acrobat*\Acrobat\Acrobat.exe' }
  its('AcrobatReader') { should eq '*\Adobe\Reader*\Reader\AcroRd32.exe' }
  its('Chrome') { should eq '*\Google\Chrome\Application\chrome.exe -SEHOP' }
  its('Excel') { should eq '*\OFFICE1*\EXCEL.EXE' }
  its('Firefox') { should eq '*\Mozilla Firefox\firefox.exe' }
  its('FirefoxPluginContainer') { should eq '*\Mozilla Firefox\plugin-container.exe' }
  its('FoxitReader') { should eq '*\Foxit Reader\Foxit Reader.exe' }
  its('GoogleTalk') { should eq '*\Google\Google Talk\googletalk.exe -DEP -SEHOP' }
  its('InfoPath') { should eq '*\OFFICE1*\INFOPATH.EXE' }
  its('iTunes') { should eq '*\iTunes\iTunes.exe' }
  its('jre6_java') { should eq '*\Java\jre6\bin\java.exe -HeapSpray' }
  its('jre6_javaw') { should eq '*\Java\jre6\bin\javaw.exe -HeapSpray' }
  its('jre6_javaws') { should eq '*\Java\jre6\bin\javaws.exe -HeapSpray' }
  its('jre7_java') { should eq '*\Java\jre7\bin\java.exe -HeapSpray' }
  its('jre7_javaw') { should eq '*\Java\jre7\bin\javaw.exe -HeapSpray' }
  its('jre7_javaws') { should eq '*\Java\jre7\bin\javaws.exe -HeapSpray' }
  its('jre8_java') { should eq '*\Java\jre1.8*\bin\java.exe -HeapSpray' }
  its('jre8_javaw') { should eq '*\Java\jre1.8*\bin\javaw.exe -HeapSpray' }
  its('jre8_javaws') { should eq '*\Java\jre1.8*\bin\javaws.exe -HeapSpray' }
  its('LiveWriter') { should eq '*\Windows Live\Writer\WindowsLiveWriter.exe' }
  its('Lync') { should eq '*\OFFICE1*\LYNC.EXE' }
  its('LyncCommunicator') { should eq '*\Microsoft Lync\communicator.exe' }
  its('mIRC') { should eq '*\mIRC\mirc.exe' }
  its('Opera') { should eq '*\Opera\opera.exe' }
  its('Outlook') { should eq '*\OFFICE1*\OUTLOOK.EXE' }
  its('PhotoGallery') { should eq '*\Windows Live\Photo Gallery\WLXPhotoGallery.exe' }
  its('Photoshop') { should eq '*\Adobe\Adobe Photoshop CS*\Photoshop.exe' }
  its('Picture Manager') { should eq '*\OFFICE1*\OIS.EXE' }
  its('Pidgin') { should eq '*\Pidgin\pidgin.exe' }
  its('PowerPoint') { should eq '*\OFFICE1*\POWERPNT.EXE' }
  its('PPTViewer') { should eq '*\OFFICE1*\PPTVIEW.EXE' }
  its('Publisher') { should eq '*\OFFICE1*\MSPUB.EXE' }
  its('QuickTimePlayer') { should eq '*\QuickTime\QuickTimePlayer.exe' }
  its('RealConverter') { should eq '*\Real\RealPlayer\realconverter.exe' }
  its('RealPlayer') { should eq '*\Real\RealPlayer\realplay.exe' }
  its('Safari') { should eq '*\Safari\Safari.exe' }
  its('SkyDrive') { should eq '*\SkyDrive\SkyDrive.exe' }
  its('Skype') { should eq '*\Skype\Phone\Skype.exe -EAF' }
  its('Thunderbird') { should eq '*\Mozilla Thunderbird\thunderbird.exe' }
  its('ThunderbirdPluginContainer') { should eq '*\Mozilla Thunderbird\plugin-container.exe' }
  its('UnRAR') { should eq '*\WinRAR\unrar.exe' }
  its('Visio') { should eq '*\OFFICE1*\VISIO.EXE' }
  its('VisioViewer') { should eq '*\OFFICE1*\VPREVIEW.EXE' }
  its('VLC') { should eq '*\VideoLAN\VLC\vlc.exe' }
  its('Winamp') { should eq '*\Winamp\winamp.exe' }
  its('WindowsLiveMail') { should eq '*\Windows Live\Mail\wlmail.exe' }
  its('WindowsMediaPlayer') { should eq '*\Windows Media Player\wmplayer.exe -SEHOP -EAF -MandatoryASLR' }
  its('WinRARConsole') { should eq '*\WinRAR\rar.exe' }
  its('WinRARGUI') { should eq '*\WinRAR\winrar.exe' }
  its('WinZip') { should eq '*\WinZip\winzip32.exe' }
  its('Winzip64') { should eq '*\WinZip\winzip64.exe' }
  its('Word') { should eq '*\OFFICE1*\WINWORD.EXE' }
  its('Wordpad') { should eq '*\Windows NT\Accessories\wordpad.exe' }
end

# EMET (IE)Parameters Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings') do
  its('DEP') { should eq 2 }
end

# Session Management Kernal Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel') do
  its('ObCaseInsensitive') { should eq 1 }
end

# WDigest Parameters Test
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest') do
  its('UseLogonCredential') { should eq 0 }
end

# Memory Management Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management') do
  its('ClearPageFileAtShutdown') { should eq 0 }
end

# RecoveryConsole Parameters Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole') do
  its('setcommand') { should eq 0 }
  its('securitylevel') { should eq 0 }
end

# Event Log Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security') do
  its('WarningLevel') { should eq 90 }
end

# Cryptography Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography') do
  its('ForceKeyProtection') { should eq 2 }
end

# Lanman Print Drivers Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers') do
  its('AddPrinterDrivers') { should eq 1 }
end

# CodeIdentifiers Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers') do
  its('authenticodeenabled') { should eq 0 }
end

# rubocop:disable all
# AllowedPaths Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths') do
  its('Machine') { should include /(System\\CurrentControlSet\\Control\\Print\\Printers)/ }
end

# AllowedExactPaths Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths') do
  its('Machine') { should include /(System\\CurrentControlSet\\Control\\ProductOptions)/ }
end

# rubocop:enable all
# WinRS Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS') do
  its('AllowRemoteShellAccess') { should eq 1 }
end

# Search Companion prevented from automatically downloading content updates.
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion') do
  its('DisableContentFileUpdates') { should eq 1 }
end

# SQMC Test
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows') do
  its('CEIPEnable') { should eq 0 }
end

# Disable Microsoft Online Accounts Test
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount') do
  its('value') { should eq 0 }
end

# Disable Network SelectionUI Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
  its('DontDisplayNetworkSelectionUI') { should eq 1 }
end

# UAC Elevation TesT
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
  its('AlwaysInstallElevated') { should eq 0 }
end

# Audit Application Log Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application') do
  its('MaxSize') { should eq 327_68 }
  its('Retention') { should eq '0' }
end

# Audit Security Log Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security') do
  its('MaxSize') { should eq 196_608 }
  its('Retention') { should eq '0' }
end

# Audit EventLog Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System') do
  its('MaxSize') { should eq 327_68 }
  its('Retention') { should eq '0' }
end

# Auto Mount CD Drive Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
  its('NoDriveTypeAutoRun') { should eq 255 }
  its('NoPublishingWizard') { should eq 1 }
end

# RDP encryption Test
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
  its('MinEncryptionLevel') { should eq 3 }
end

# Index of Encryption Files Test
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
  its('AllowIndexingEncryptedStoresOrItems') { should eq 0 }
end

# Personalization Lock screen Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization') do
  its('NoLockScreenSlideshow') { should eq 1 }
  its('NoLockScreenCamera') { should eq 1 }
end

# Personalization Lock screen Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client') do
  its('CEIP') { should eq 2 }
end

# Turn off Windows Update device driver searching Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching') do
  its('DontSearchWindowsUpdate') { should eq 1 }
end

# PowerShell Settings
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
  its('EnableScriptBlockLogging') { should eq 0 }
end
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription') do
  its('EnableTranscripting') { should eq 0 }
end

# Local Policy Script
script = <<-EOH
secedit /export /cfg c:\\temp\\tempexport.inf /quiet
Get-content C:\\temp\\tempexport.inf | findstr /B `
/C:"MinimumPasswordAge = 1" `
/C:"MaximumPasswordAge = 42" `
/C:"MinimumPasswordLength = 14" `
/C:"PasswordComplexity = 1" `
/C:"PasswordHistorySize = 24" `
/C:"LockoutBadCount = 10" `
/C:"ResetLockoutCount = 15" `
/C:"LockoutDuration = 15" `
/C:"SeNetworkLogonRight = *S-1-5-11,*S-1-5-32-544" `
/C:"SeServiceLogonRight = *S-1-5-80-0" `
/C:"SeInteractiveLogonRight = *S-1-5-32-544" `
/C:"SeSecurityPrivilege = *S-1-5-32-544" `
/C:"SeSystemEnvironmentPrivilege = *S-1-5-32-544" `
/C:"SeProfileSingleProcessPrivilege = *S-1-5-32-544" `
/C:"SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20" `
/C:"SeRestorePrivilege = *S-1-5-32-544" `
/C:"SeShutdownPrivilege = *S-1-5-32-544" `
/C:"SeTakeOwnershipPrivilege = *S-1-5-32-544" `
/C:"SeDenyNetworkLogonRight = *S-1-5-32-546" `
/C:"SeDenyBatchLogonRight = *S-1-5-32-546" `
/C:"SeDenyServiceLogonRight = *S-1-5-32-546" `
/C:"SeDenyInteractiveLogonRight = *S-1-5-32-546"
del "C:\\temp\\tempexport.inf" -force -ErrorAction SilentlyContinue
EOH

# Local Policy Tester
describe powershell(script) do
  its('stdout') do
    should eq "MinimumPasswordAge = 1\r
MaximumPasswordAge = 42\r
MinimumPasswordLength = 14\r
PasswordComplexity = 1\r
PasswordHistorySize = 24\r
LockoutBadCount = 10\r
ResetLockoutCount = 15\r
LockoutDuration = 15\r
SeNetworkLogonRight = *S-1-5-11,*S-1-5-32-544\r
SeServiceLogonRight = *S-1-5-80-0\r
SeInteractiveLogonRight = *S-1-5-32-544\r
SeSecurityPrivilege = *S-1-5-32-544\r
SeSystemEnvironmentPrivilege = *S-1-5-32-544\r
SeProfileSingleProcessPrivilege = *S-1-5-32-544\r
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20\r
SeRestorePrivilege = *S-1-5-32-544\r
SeShutdownPrivilege = *S-1-5-32-544\r
SeTakeOwnershipPrivilege = *S-1-5-32-544\r
SeDenyNetworkLogonRight = *S-1-5-32-546\r
SeDenyBatchLogonRight = *S-1-5-32-546\r
SeDenyServiceLogonRight = *S-1-5-32-546\r
SeDenyInteractiveLogonRight = *S-1-5-32-546\r\n"
  end
  its('stderr') { should eq '' }
end

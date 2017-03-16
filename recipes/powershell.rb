#
# Cookbook Name:: windows-hardening
# Recipe:: powershell
#

# Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts
# Powershell ScriptBlock Logging
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' do
  values [{
    name: 'EnableScriptBlockLogging',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Transcription creates a unique record of every PowerShell session, including all input and output, exactly as it appears in the session.
# Powershell Transcription
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' do
  values [{
    name: 'EnableTranscripting',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

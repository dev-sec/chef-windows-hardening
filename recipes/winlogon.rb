# Winlogon Settings
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'PasswordExpiryWarning', type: :dword, data: 14 },
          { name: 'ScreenSaverGracePeriod', type: :string, data: 5 },
          { name: 'AllocateDASD', type: :string, data: 0 },
          { name: 'ScRemoveOption', type: :string, data: 1 },
          { name: 'ForceUnlockLogon', type: :string, data: 0 },
          { name: 'AutoAdminLogon', type: :string, data: 0 }, # This will stop auto login for kitchen tests
          { name: 'CachedLogonsCount', type: :string, data: 4 }]
  action :create
end
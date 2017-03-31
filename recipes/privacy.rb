# Disable Microsoft Online Accounts
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount' do
  values [{
    name: 'value',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

# Disable Windows Store
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore' do
  values [{ name: 'AutoDownload', type: :dword, data: 4 },
          { name: 'DisableOSUpgrade', type: :dword, data: 1 }]
  recursive true
  action :create
end

# Index of encrypted files
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search' do
  values [{
    name: 'AllowIndexingEncryptedStoresOrItems',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

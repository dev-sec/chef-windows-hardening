include_controls 'windows-baseline' do
  # we need to skip the test to ensure we can connect with non-administrator
  # winrm user for our tests
  attribute('se_network_logon_right', default: ['S-1-1-0', 'S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-551'])
end

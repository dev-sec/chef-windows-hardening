resource_name :rename_account

property :rename_account_name, String, name_property: true
property :original_name, String, required: true
property :new_name, String, required: true

action :set do
  execute new_resource.rename_account_name do
    command "wmic useraccount where name=\'#{new_resource.original_name}\' call rename name=\'#{new_resource.new_name}\'"
    action :run
    not_if { ::File.exist?("C:\\rename_#{new_resource.original_name}.lock") }
    notifies :create, "file[C:\\rename_#{new_resource.original_name}.lock]", :immediately
  end

  file "C:\\rename_#{new_resource.original_name}.lock" do
    action :create
  end
end
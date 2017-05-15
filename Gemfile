source 'https://rubygems.org'

gem 'berkshelf', '~> 5.3'
gem 'chef', '~> 12.5'

group :test do
  gem 'rubocop', '~> 0.44.0'
  gem 'highline', '~> 1.6.0'
  gem 'foodcritic', '~> 6.0'
end

group :integration do
  gem 'kitchen-inspec'
  gem 'test-kitchen'
  gem 'kitchen-vagrant'
  gem 'inspec', '~> 1'
end

group :tools do
  gem 'github_changelog_generator', '~> 1.12.0'
end

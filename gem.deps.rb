source "https://rubygems.org/"

gem 'loggability', '~> 0.14'
gem 'rbnacl', '~> 5.0'
gem 'msgpack', '~> 1.2'

group( :development ) do
	gem 'hoe-deveiate', '~> 0.10'
	gem 'simplecov', '~> 0.7'
	gem 'rdoc-generator-fivefish', '~> 0.3'
	gem 'rdoc', "~> 6.2"
end

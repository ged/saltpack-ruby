# -*- ruby -*-
#encoding: utf-8

require 'simplecov' if ENV['COVERAGE']

require 'pathname'
require 'rspec'
require 'loggability/spechelpers'

require 'saltpack'


module Saltpack::SpecHelpers

	SPEC_DIR = Pathname( __FILE__ ).parent
	DATA_DIR = SPEC_DIR + 'data'


	### Load a file named +name+ from the test data directory and return it as a
	### frozen String.
	def read_test_data( name, **options )
		path = DATA_DIR + name
		return path.read( **options )
	end


end # module Saltpack::SpecHelpers


### Mock with RSpec
RSpec.configure do |config|
	config.run_all_when_everything_filtered = true
	config.filter_run :focus
	config.order = 'random'
	config.mock_with( :rspec ) do |mock|
		mock.syntax = :expect
	end

	config.include( Loggability::SpecHelpers )
	config.extend( Saltpack::SpecHelpers )
end



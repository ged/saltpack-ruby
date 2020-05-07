#!/usr/bin/ruby -*- ruby -*-

$LOAD_PATH.unshift( 'lib' )

require 'pry'
require 'pry/command'
require 'rbnacl'
require 'saltpack'

cmdset = Pry::CommandSet.new

class DumpKeyCommand < Pry::ClassCommand

	match 'dump-naclkey'
	group 'Saltpack'
	description "Dump a NaCl private/public keypair as Ruby code"

	banner <<-END_BANNER
	Usage: dump-naclkey

	Dump a new NaCl keypair as Ruby code to load the key.
	END_BANNER

	### Pry::Command API -- run the command.
	def process
		key = RbNaCl::PrivateKey.generate

		puts "private_key = %p" % [ key.to_s.unpack1('h*') ],
			"public_key = %p" % [ key.public_key.to_s.unpack1('h*') ]
	end

end
cmdset.add_command( DumpKeyCommand )


Pry::Commands.import( cmdset )


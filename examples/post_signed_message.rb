#!/usr/bin/env ruby

require 'rbnacl'
require 'saltpack'

key1 = RbNaCl::PrivateKey.
	new( ["1e42fd5f0ba92398e6e87b633d06987467f237caac217693c7ee14056f153b3a"].pack('h*') )
key2 = RbNaCl::PrivateKey.
	new( ["3d8ff66ec5d042a41fdcc93e57b909647e9017a6599f8120dd1726a4772a0626"].pack('h*') )

msg = Saltpack::Message.new( 'Hey, want to get a beer later?', from: key1, to: key2 )

msg.add_recipient( key3 )
# -or-
msg.add_anonymous_recipient( key3 )

puts msg.encrypt
# -or-
puts msg.encrypt( armor: true )



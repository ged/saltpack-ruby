#!/usr/bin/env ruby

require 'rbnacl'
require 'saltpack'

key1 = RbNaCl::PrivateKey.generate
key2 = RbNaCl::PrivateKey.generate
key3 = RbNaCl::PrivateKey.generate

text = 'Hey, want to get a beer later?'

msg = Saltpack::Message.new( text, key1, key2 )

msg.add_recipient( key3 )
# -or-
msg.add_anonymous_recipient( key3 )

puts msg.encrypt
# -or-
puts msg.encrypt_armor



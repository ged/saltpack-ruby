# -*- ruby -*-
# frozen_string_literal: true

require 'loggability'
require 'rbnacl'

require 'saltpack' unless defined?( Saltpack )
require 'saltpack/header'
require 'saltpack/payload'


# An encrypted message.
class Saltpack::Message

	### Create a new Message for the given +recipients+ using the specified
	### +sender_key+.
	def initialize( data, sender_key, *recipients, **options )
		
	end

end # class Saltpack::Message

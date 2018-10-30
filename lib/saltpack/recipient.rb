# -*- ruby -*-
# frozen_string_literal: true

require 'msgpack'
require 'rbnacl'

require 'saltpack' unless defined?( Saltpack )

# A recipient in a Saltpack header.
class Saltpack::Recipient


	### Create a new Saltbox::Recipient using their +public_key+.
	def initialize( public_key )
		@public_key = public_key
	end


	######
	public
	######

	##
	# The recipient's public key
	attr_reader :public_key


	### 
	def payload_key_box
		
	end

end # class Saltpack::Recipient

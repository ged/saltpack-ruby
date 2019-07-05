# -*- ruby -*-
# frozen_string_literal: true

require 'loggability'
require 'rbnacl'

require 'saltpack' unless defined?( Saltpack )


# A payload packet of a Saltpack message.
class Saltpack::Payload

	#################################################################
	###	I N S T A N C E   M E T H O D S
	#################################################################

	### Create a new Saltpack::Payload
	def initialize( payload, *authenticators, final: false )

	end


end # class Saltpack::Payload


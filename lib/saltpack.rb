# -*- ruby -*-
# frozen_string_literal: true

require 'rbnacl'
require 'loggability'


# Saltpack -- a modern crypto messaging format based on Dan Bernstein's NaCl.
#
# Refs:
# - https://saltpack.org/
# - https://nacl.cr.yp.to/
module Saltpack
	extend Loggability

	# Package version
	VERSION = '0.0.1'

	# Version control revision
	REVISION = %q$Revision: e216e8bc10bb $

	# The default options for the ::encrypt/::decrypt methods.
	DEFAULT_ENCRYPTION_OPTIONS = {
		chunk_size: 10 ** 6,
		visible_recipients: false,
	}


	# Create a logger for this library
	log_as :saltpack


	require 'saltpack/errors'

	autoload :Armor, 'saltpack/armor'
	autoload :Header, 'saltpack/header'
	autoload :Message, 'saltpack/message'
	autoload :Payload, 'saltpack/payload'
	autoload :Recipient, 'saltpack/recipient'


	### Encrypt the given +message+ for the given +recipient_public_keys+ using the
	### +sender_key+.
	def self::encrypt( message, sender_key, *recipient_public_keys, **options )
		msg = Saltpack::Message.new( message, sender_key, *recipient_public_keys, **options )
		return msg.to_s
	end


	### Decrypt the given +message+ with the specified +recipient_key+.
	def self::decrypt( message, recipient_key )
		msg = Saltpack::Message.parse( message, recipient_key )
		return msg.decrypt
	end


	### Return the +input_bytes+ ascii-armored using the specified +options+
	def self::armor( input, **options )
		return Saltpack::Armor.armor( input, **options )
	end


	### Decode the ascii-armored data from the specified +input_chars+ using
	### the given +options+.
	def self::dearmor( input_chars, **options )
		return Saltpack::Armor.dearmor( input_chars, **options )
	end

end # module Saltpack


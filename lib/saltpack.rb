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
		msg = Saltpack::Message.read( message, recipient_key )
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


	#
	# Utility functions
	#


	### Calculate a MAC hash for the 
	def self::calculate_recipient_hash( header_hash, index, keypair1, keypair2 )

		# 9. Concatenate the first 16 bytes of the header hash from step 7 above, with the
		# recipient index from step 4 above. This is the basis of each recipient's MAC
		# nonce.
		mac_key_nonce_prefix = header_hash[0, 16]
		basis = mac_key_nonce_prefix + [i].pack('Q>')

		# Clear the least significant bit of byte 15. That is: nonce[15] &= 0xfe.
		nonce1 = basis.dup
		nonce1[15] = (nonce1[15].ord & 0xfe).chr

		# Modify the nonce from step 10 by setting the least significant bit of byte
		# That is: nonce[15] |= 0x01.
		nonce2 = basis.dup
		nonce2[15] = (nonce2[15].ord | 0x01).chr

		# Encrypt 32 zero bytes using crypto_box with the recipient's public key, the
		# sender's long-term private key, and the nonce from the previous step.
		# Encrypt 32 zero bytes again, as in step 11, but using the ephemeral private
		# key rather than the sender's long term private key.
		box1 = RbNaCl::Box.new( *keypair1 ).encrypt( nonce1, ZEROS_32 )
		box2 = RbNaCl::Box.new( *keypair2 ).encrypt( nonce2, ZEROS_32 )

		# Concatenate the last 32 bytes each box from steps 11 and 13. Take the SHA512
		# hash of that concatenation. The recipient's MAC Key is the first 32 bytes of
		# that hash.
		mac_hash = RbNaCl::Hash.sha512( box1[-16..] + box2[-16..] )

		return mac_hash[ 0, 32 ]
	end

end # module Saltpack


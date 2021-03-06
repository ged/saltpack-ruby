# -*- ruby -*-
# frozen_string_literal: true

require 'loggability'
require 'msgpack'
require 'rbnacl'

require 'saltpack' unless defined?( Saltpack )
require 'saltpack/header'
require 'saltpack/payload'


# An encrypted message.
class Saltpack::Message
	extend Loggability


	# Loggability -- log to the Saltpack module's logger
	log_to :saltpack


	### Read a Saltpack::Message from the given +source+ and +recipient_key+ and
	### return it.
	def self::read( source, recipient_key )
		header = Saltpack::Header.parse( source, recipient_key )
		self.log.debug( header )

		# Try to open each of the payload key boxes in the recipients list using
		# crypto_box_open_afternm, the precomputed secret from #5, and the nonce
		# saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian unsigned recipient
		# index, where the first recipient is index 0. Successfully opening one gives
		# the payload key.
		if ( recipient = recipients.assoc(recipient_key.public_key) )
			index = recipients.index( recipient ) or
				raise "Recipient %p not present in the recipients list?!"
			nonce = PAYLOAD_KEY_BOX_NONCE_PREFIX + [index].pack( 'Q>' )
			box = RbNaCl::Box.new( ephemeral_pubkey, recipient_key )
			payload_key = box.decrypt( nonce, recipient[1] )
		else
			ephemeral_beforenm = RbNaCl::Box.beforenm( ephemeral_pubkey, recipient_key ) or
				raise "Failed to extract the ephemeral shared key."
			recipients.each_with_index do |(_, encrypted_key), index|
				nonce = self.payload_key_nonce( header.version, index )
				payload_key = RbNaCl::Box.open_afternm( encrypted_key,
					ephemeral_beforenm, nonce, RbNaCl::SecretBox.key_bytes )
				break if payload_key
			end
		end

	    raise "Failed to extract the payload key" unless payload_key
		sender_public = RbNaCl::SecretBox.new( payload_key ).
			decrypt( SENDER_KEY_SECRETBOX_NONCE, sender_secretbox )

		recipient_mac = Saltpack.calculate_recipient_hash( header_hash, index,
			[sender_public, recipient_key],
			[ephemeral_pubkey, recipient_key]
		)

	    self.log.debug "recipient index: %p" % [ recipient_index ]
	    self.log.debug "sender key: %p" % [ sender_public ]
	    self.log.debug "payload key: %p" % [ payload_key ]
	    self.log.debug "mac key: %p" % [ mac_key ]
	end


	### (Undocumented)
	def self::payload_key_nonce( version, index )

		return PAYLOAD_KEY_BOX_NONCE_PREFIX + [index].pack( 'Q>' )
	end

	### Create a new Message for the given +recipients+ using the specified
	### +sender_key+.
	def initialize( data, header=nil, from: nil, to: [], **options )
		@data       = readable_source( data )
		@header     = header
		@sender_key = from
		@recipients = to
		@options    = options
	end


	### (Undocumented)
	def decrypt

	end


	#######
	private
	#######

	### Convert the given +data+ source into an object that supports #read or #readpartial if it
	### isn't already one.
	def readable_source( data )
		return data if data.respond_to?( :read ) || data.respond_to?( :readpartial )
		return StringIO.new( data ) if data.respond_to?( :to_str )
		raise ArgumentError, "don't know how to read from a %p" % [ data.class ]
	end

end # class Saltpack::Message

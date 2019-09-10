# -*- ruby -*-
# frozen_string_literal: true

require 'msgpack'
require 'rbnacl'
require 'loggability'

require 'saltpack' unless defined?( Saltpack )
require 'saltpack/refinements'


using Saltpack::Refinements


# Header for a saltpack message.
#
# Refs:
# - https://saltpack.org/encryption-format-v2
class Saltpack::Header
	extend Loggability


	# The header format name field value
	FORMAT_NAME = 'saltpack'

	# The header format major version field value
	FORMAT_MAJOR_VERSION = 2

	# The header format minor version field value
	FORMAT_MINOR_VERSION = 0

	# Version header Array
	FORMAT_VERSION = [ FORMAT_MAJOR_VERSION, FORMAT_MINOR_VERSION ].freeze

	# Mode names to numeric values
	MODES = {
		encryption: 0,
		attached_signing: 1,
		detached_signing: 2,
		signcryption: 4
	}.freeze
	MODE_NAMES = MODES.invert.freeze

	# The nonce used to create the sender key secret box
	SENDER_KEY_SECRETBOX_NONCE = "saltpack_sender_key_sbox".b

	# The nonce prefix used to create the recipients list
	PAYLOAD_KEY_BOX_NONCE_PREFIX = "saltpack_recipsb".b

	# The nonce prefix used for the payload packets
	PAYLOAD_NONCE_PREFIX = "saltpack_ploadsb".b

	# The 32-byte zero string used to create the MAC keys
	ZEROS_32 = RbNaCl::Util.zeros( 32 )


	# Log to the Saltpack logger
	log_to :saltpack


	# [
	#     format name,
	#     version,
	#     mode,
	#     ephemeral public key,
	#     sender secretbox,
	#     recipients list,
	# ]

	### Parse the (already once-decoded) data in the specified +source+ as a
	### Saltpack header and return it as a Saltpack::Header. Raises a
	### Saltpack::Error if the +source+ cannot be parsed.
	def self::parse( source, recipient_key )
		source = StringIO.new( source ) unless
			source.respond_to?( :read ) || source.respond_to?( :readpartial )
		unpacker = MessagePack::Unpacker.new( source )
		self.log.debug "Unpacker is: %p" % [ unpacker ]

		encoded_header = unpacker.read
		header_hash = RbNaCl::Hash.sha512( encoded_header )
		parts = MessagePack.unpack( encoded_header )

		raise Saltpack::MalformedMessage, "header is not an Array" unless parts.is_a?( Array )
		raise Saltpack::UnsupportedFormat, parts[0] unless
			parts[0] == FORMAT_NAME
		raise Saltpack::UnsupportedVersion, parts[1] unless
			parts[1] == FORMAT_VERSION

		return new( *parts, header_hash: header_hash )
	end


	### Generate a header
	def self::generate( sender_key, *recipient_public_keys, hide_recipients: false )


	end


	### Create a new header with the given 
	def initialize( **fields )
		@format_name      = FORMAT_NAME
		@format_version   = FORMAT_VERSION

		@mode             = :encryption

		@payload_key      = RbNaCl::Random.random_bytes( RbNaCl::SecretBox.key_bytes )
		@ephemeral_key    = RbNaCl::PrivateKey.generate
		@sender_key       = nil

		@recipients       = []
	end



	### (Undocumented)
	def to_s
		result = String.new( encoding: 'binary' )

		# 1. Generate a random 32-byte payload key
		# 2. Generate a random ephemeral keypair
		# 3. Encrypt the sender's long-term public key using crypto_secretbox with the
		#    payload key and the nonce saltpack_sender_key_sbox, to create the sender
		#    secretbox.
		box = RbNaCl::SecretBox.new( self.payload_key )
		sender_secretbox = box.encrypt( SENDER_KEY_SECRETBOX_NONCE, self.sender_key.public_key )

		# 4. For each recipient, encrypt the payload key using crypto_box with the
		#    recipient's public key, the ephemeral private key, and the nonce
		#    saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian unsigned recipient
		#    index, where the first recipient is index zero. Pair these with the
		#    recipients' public keys, or null for anonymous recipients, and collect the
		#    pairs into the recipients list.
		recipients = self.recipient_public_keys.map.with_index do |recipient_key, i|
			box = RbNaCl::Box.new( recipient_key, ephemeral_key )
			nonce = PAYLOAD_KEY_BOX_NONCE_PREFIX + [i].pack( 'Q>' )
			encrypted_key = box.encrypt( nonce, self.payload_key )

			[ hide_recipients ? nil : recipient_key, encrypted_key ]
		end

		# 5. Collect the format name, version, and mode into a list, followed by the
		# ephemeral public key, the sender secretbox, and the nested recipients list.
		header = [
			FORMAT_NAME,
			[ FORMAT_MAJOR_VERSION, FORMAT_MINOR_VERSION ],
			MODES[:encryption],
			ephemeral_key.public_key,
			sender_secretbox,
			recipients,
		]

		# 6. Serialize the list from #5 into a MessagePack array object.
		header_bytes = MessagePack.pack( header )

		# 7. Take the crypto_hash (SHA512) of the bytes from #6. This is the header hash.
		header_hash = RbNaCl::Hash.sha512( header_bytes )

		# 8. Serialize the bytes from #6 again into a MessagePack bin object. These
		# twice-encoded bytes are the header packet.
		dblenc_header_bytes = MessagePack.pack( header_bytes )
		result << dblenc_header_bytes

		# After generating the header, the sender computes each recipient's MAC key,
		# which will be used below to authenticate the payload:
		recipient_mac_keys = recipient_public_keys.map.with_index do |recipient_key, i|
			Saltpack.calculate_recipient_hash( header_hash, i,
				[recipient_key, self.sender_key],
				[recipient_key, ephemeral_key]
			)
		end
	end

end # class Saltpack::Header


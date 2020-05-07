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
	rescue MessagePack::MalformedFormatError => err
		self.log.error "%p while parsing the header: %s" % [ err.class, err.message ]
		raise Saltpack::MalformedMessage, "malformed msgpack data: %s" % [ err.message ]
	end


	### Generate a header
	def self::generate( sender_key, *recipient_public_keys, hide_recipients: false )


	end


	### Create a new header with the given
	def initialize( **fields )
		@format_name        = FORMAT_NAME
		@format_version     = FORMAT_VERSION

		@mode               = :encryption

		@payload_key        = RbNaCl::Random.random_bytes( RbNaCl::SecretBox.key_bytes )
		@ephemeral_key      = RbNaCl::PrivateKey.generate
		@sender_key         = nil

		@recipients         = []
		@hide_recipients    = true

		@recipient_mac_keys = nil
		@hash               = nil
		@data               = nil

		fields.each do |name, value|
			self.public_send( "#{name}=", value )
		end
	end


	######
	public
	######

	##
	# The format name used in the header
	attr_reader :format_name

	##
	# The [major, minor] version tuple used in the header
	attr_reader :format_version

	##
	# The mode being used; one of the keys of MODES
	attr_reader :mode

	##
	# The random payload key
	attr_accessor :payload_key

	##
	# The RbNaCl::PrivateKey used only for this message to encrypt/sign its
	# internals
	attr_accessor :ephemeral_key

	##
	# The RbNaCl::PrivateKey/PublicKey of the sender
	attr_accessor :sender_key

	##
	# The public keys of each of the message's recipients.
	attr_reader :recipients

	##
	# Whether to include the recipients' public key in the recipients tuples of the
	# message.
	attr_accessor :hide_recipients


	### Set the mode as either a Symbol or as an Integer.
	def mode=( new_mode )
		if MODES.key?( new_mode )
			@mode = new_mode
		elsif MODE_NAMES.key?( new_mode )
			@mode = MODE_NAMES[ new_mode ]
		else
			raise ArgumentError, "invalid mode %p" % [ new_mode ]
		end
	end


	### Return the mode as an Integer.
	def numeric_mode
		return MODES[ self.mode ]
	end


	### Return the #sender_key after checking to be sure the PrivateKey is
	### available.
	def sender_private_key
		key = self.sender_key or raise Saltpack::KeyError, "sender key is not set"
		raise Saltpack::KeyError, "sender private key not available" unless
			key && key.respond_to?( :public_key )
		return key
	end


	### Return either the #sender_key, or the public half of the #send_key if it's a
	### PrivateKey.
	def sender_public_key
		key = self.sender_key or raise Saltpack::KeyError, "sender key is not set"
		return key.public_key if key.respond_to?( :public_key )
		return key
	end


	### Calculate all the header values and freeze it.
	def finalize
		return if self.frozen?

		# 5. Collect the format name, version, and mode into a list, followed by the
		# ephemeral public key, the sender secretbox, and the nested recipients list.
		header_parts = [
			self.format_name,
			self.format_version,
			self.numeric_mode,
			self.ephemeral_key.public_key.to_bytes,
			self.sender_secretbox,
			self.recipient_tuples( hide_recipients: self.hide_recipients ),
		]

		# 6. Serialize the list from #5 into a MessagePack array object.
		header_bytes = MessagePack.pack( header_parts )

		# 7. Take the crypto_hash (SHA512) of the bytes from #6. This is the header hash.
		@hash = RbNaCl::Hash.sha512( header_bytes )

		# 8. Serialize the bytes from #6 again into a MessagePack bin object. These
		# twice-encoded bytes are the header packet.
		@data = MessagePack.pack( header_bytes )

		# After generating the header, the sender computes each recipient's MAC key,
		# which will be used below to authenticate the payload:
		@recipient_mac_keys = self.recipients.map.with_index do |recipient_key, i|
			Saltpack.calculate_recipient_hash(
				@hash, i,
				[recipient_key, self.sender_private_key],
				[recipient_key, self.ephemeral_key]
			)
		end

		self.freeze
	end


	### Overloaded -- also freeze the recipients when the header is frozen.
	def freeze
		@recipients.freeze
		super
	end


	### Return the SHA612 hash of the single-messagepacked header.
	def hash
		self.finalize
		return @hash
	end


	### Return the header as a binary String.
	def data
		self.finalize
		return @data
	end
	alias_method :to_s, :data


	### The MAC keys used to hash/validate message parts.
	def recipient_mac_keys
		self.finalize
		return @recipient_mac_keys
	end


	### Generate an Array of header tuples from the #recipients keys and return it.
	### If +hide_recipients+ is true, don't include the public keys in the tuples.
	def recipient_tuples( hide_recipients: true )
		# 4. For each recipient, encrypt the payload key using crypto_box with the
		#    recipient's public key, the ephemeral private key, and the nonce
		#    saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian unsigned recipient
		#    index, where the first recipient is index zero. Pair these with the
		#    recipients' public keys, or null for anonymous recipients, and collect the
		#    pairs into the recipients list.
		return self.recipients.map.with_index do |recipient_key, i|
			box = RbNaCl::Box.new( recipient_key, self.ephemeral_key )
			nonce = PAYLOAD_KEY_BOX_NONCE_PREFIX + [ i ].pack( 'Q>' )
			encrypted_key = box.encrypt( nonce, self.payload_key )

			[ hide_recipients ? nil : recipient_key, encrypted_key ]
		end
	end


	### Return the sender secretbox
	def sender_secretbox
		# 1. Generate a random 32-byte payload key
		# 2. Generate a random ephemeral keypair
		# 3. Encrypt the sender's long-term public key using crypto_secretbox with the
		#    payload key and the nonce saltpack_sender_key_sbox, to create the sender
		#    secretbox.
		box = RbNaCl::SecretBox.new( self.payload_key )
		return box.encrypt( SENDER_KEY_SECRETBOX_NONCE, self.sender_public_key )
	end

end # class Saltpack::Header


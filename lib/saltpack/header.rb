# -*- ruby -*-
# frozen_string_literal: true

require 'msgpack'
require 'rbnacl'

require 'saltpack' unless defined?( Saltpack )


# Header for a saltpack message.
#
# Refs:
# - https://saltpack.org/encryption-format-v2
class Saltpack::Header

	# The header format name field value
	FORMAT_NAME = 'saltpack'

	# The header format major version field value
	FORMAT_MAJOR_VERSION = 2

	# The header format minor version field value
	FORMAT_MINOR_VERSION = 0

	# Version header Array
	FORMAT_VERSION = [ FORMAT_MAJOR_VERSION, FORMAT_MINOR_VERSION ].freeze

	# Mode names to numeric values
	MODE_VALUES = {
		encryption: 0,
		attached_signing: 1,
		detached_signing: 2,
		signcryption: 4
	}.freeze
	MODE_NAMES = MODE_VALUES.invert.freeze

	# The prefix for the nonces used for encrypting payload keys
	HEADER_PAYLOAD_NONCE_PREFIX = 'saltpack_recipsb'.b


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
	def self::parse( source )
		header_hash = RbNaCl::Hash.sha512( source )

		parts = MessagePack.unpack( source )
		raise Saltpack::MalformedMessage, "header is not an Array" unless parts.is_a?( Array )

		format_name,
			version,
			mode,
			ephemeral_pubkey,
			sender_secretbox,
			recipient_pairs,
			_ = *parts
		version_major, version_minor = *version

		raise Saltpack::UnsupportedFormat, format_name unless
			format_name == FORMAT_NAME
		raise Saltpack::UnsupportedVersion, "%d.%d" % [major_version, minor_version] unless
			major_version == FORMAT_MAJOR_VERSION &&
			minor_version == FORMAT_MINOR_VERSION

		instance = new( eph_pubkey, secretbox, mode )
		recipient_pairs.each do |pubkey, box|
			instance.add_recipient( pubkey, box )
		end

		return instance
	rescue MessagePack::MalformedFormatError => err
		raise Saltpack::MalformedMessage, "error while unpacking: #{err.message}"
	end


	### Generate a header
	def self::generate( sender_public_key, *recipient_public_keys )
		payload_key = RbNaCl::Random.random_bytes( RbNaCl::SecretBox.key_bytes )
		sender_secretbox = RbNaCl::SimpleBox.from_secret_key( payload_key )

		ephemeral_keypair = RbNaCl::PrivateKey.generate
		recipients = recipient_public_keys.map.with_index do |recipient_key, i|
			box = RbNaCl::Box.new( recipient_key, ephemeral_keypair )
			nonce = HEADER_PAYLOAD_NONCE_PREFIX + [i].pack( 'Q>' )
			encrypted_key = box.encrypt( nonce, payload_key )

			# :TODO: Doesn't handle anonymous recipients
			[ recipient_key, encrypted_key ]
		end

		
	end


	### Create a new Header for a saltpack message with the given +ephemeral_key+
	### and +sender_secretbox+.
	def initialize( ephemeral_key, sender_secretbox, mode )
		@ephemeral_key = ephemeral_key
		@sender_secretbox = sender_secretbox
	end


	######
	public
	######



end # class Saltpack::Header


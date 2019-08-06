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

		return new( *parts, header_hash: header_hash )
	end


	### Generate a header
	def self::generate( sender_key, *recipient_public_keys, hide_recipients: false )
		result = String.new( encoding: 'binary' )

		# 1. Generate a random 32-byte payload key
		payload_key = RbNaCl::Random.random_bytes( RbNaCl::SecretBox.key_bytes )

		# 2. Generate a random ephemeral keypair
		ephemeral_key = RbNaCl::PrivateKey.generate

		# 3. Encrypt the sender's long-term public key using crypto_secretbox with the
		# payload key and the nonce saltpack_sender_key_sbox, to create the sender
		# secretbox.
		sender_public = sender_key.public_key
		box = RbNaCl::SecretBox.new( payload_key )
		sender_secretbox = box.encrypt( SENDER_KEY_SECRETBOX_NONCE, sender_public )

		# 4. For each recipient, encrypt the payload key using crypto_box with the
		# recipient's public key, the ephemeral private key, and the nonce
		# saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian unsigned recipient
		# index, where the first recipient is index zero. Pair these with the
		# recipients' public keys, or null for anonymous recipients, and collect the
		# pairs into the recipients list.
		recipients = recipient_public_keys.map.with_index do |recipient_key, i|
			box = RbNaCl::Box.new( recipient_key, ephemeral_key )
			nonce = PAYLOAD_KEY_BOX_NONCE_PREFIX + [i].pack( 'Q>' )
			encrypted_key = box.encrypt( nonce, payload_key )

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
			self.calculate_recipient_hash( header_hash, i,
				[recipient_key, sender_key],
				[recipient_key, ephemeral_key]
			)
		end

	end


	### Calculate a MAC hash for the 
	def self::calculate_recipient_hash( header_hash, index, keypair1, keypair2 )
		mac_key_nonce_prefix = header_hash[0, 16]

		# 9. Concatenate the first 16 bytes of the header hash from step 7 above, with the
		# recipient index from step 4 above. This is the basis of each recipient's MAC
		# nonce.
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


	### (Undocumented)
	def initialize( format_name, version, mode=MODES[:encryption], ephemeral_pubkey, sender_secretbox, *recipient_pairs, header_hash: nil )
		raise Saltpack::UnsupportedFormat, format_name unless
			format_name == FORMAT_NAME
		raise Saltpack::UnsupportedVersion, "%d.%d" % [version.map(&:to_s).join('.')] unless
			version == FORMAT_VERSION

		@mode = mode
		@ephemeral_pubkey = ephemeral_pukey
		@sender_secretbox = sender_secretbox
		@recipients = recipient_pairs
		@header_hash = header_hash
	end


end # class Saltpack::Header


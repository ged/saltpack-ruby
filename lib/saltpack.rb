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

	# The Base64 alphabet
	B64ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	# The Base62 alphabet
	B62ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	# The Base85 alphabet
	B85ALPHABET = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
	    "[\\]^_`abcdefghijklmnopqrstu"

	# The default options for the ::encrypt/::decrypt methods.
	DEFAULT_ENCRYPTION_OPTIONS = {
		chunk_size: 10 ** 6,
		visible_recipients: false,
	}

	# The default options used by the ::armor/::dearmor methods.
	DEFAULT_ARMOR_OPTIONS = {
		alphabet: B62ALPHABET,
		block_size: 32,
		char_block_size: 43,
		raw: false,
		shift: false,
		message_type: 'MESSAGE',
	}


	# Create a logger for this library
	log_as :saltpack


	require 'saltpack/errors'

	autoload :Header, 'saltpack/header'
	autoload :Message, 'saltpack/message'
	autoload :Payload, 'saltpack/payload'
	autoload :Recipient, 'saltpack/recipient'


	### Return the index of the specified +char+ in +alphabet+, raising an
	### appropriate error if it is not found.
	def self::get_char_index( alphabet, char )
        rval = alphabet.index( char ) or
			raise IndexError, "Could not find %p in alphabet %p." % [ char, alphabet ]
		return rval
	end


	### Return the minimum number of characters needed to encode +bytes_size+ bytes
	### using the given +alphabet+.
	def self::character_block_size( alphabet_size, bytes_size )
	    return ( 8 * bytes_size / Math.log2(alphabet_size) ).ceil
	end


	### Return the maximum number of bytes needed to encode +chars_size+ characters
	### using the given +alphabet+.
	def self::max_bytes_size( alphabet_size, chars_size )
	    return ( Math.log2(alphabet_size) / 8 * chars_size ).floor
	end


	### Return the number of bits left over after using an alphabet of the specified
	### +alphabet_size+ to encode a payload of +bytes_size+ with +chars_size+
	### characters.
	def self::extra_bits( alphabet_size, chars_size, bytes_size )
	    total_bits = ( Math.log2(alphabet_size) * chars_size ).floor
	    return total_bits - 8 * bytes_size
	end


	###############
	module_function
	###############


	### Encrypt the given +message+ for the given +recipient_public_keys+ using the
	### +sender_key+.
	def encrypt( message, sender_key, *recipient_public_keys, **options )
		msg = Saltpack::Message.new( message, sender_key, *recipient_public_keys, **options )
		return msg.to_s
	end


	### (Undocumented)
	def decrypt( message, recipient_key )
		Saltpack::Header.parse( message, recipient_key )
	end


	### Return the +input_bytes+ ascii-armored using the specified +options+
	def armor( input, **options )
		options = Saltpack::DEFAULT_ARMOR_OPTIONS.merge( options )

		output = input.chars.each_slice( options[:block_size] ).
			map( &:join ).
			each_with_object( String.new(encoding: 'us-ascii') ) do |chunk, buf|
				buf << Saltpack.encode_block( chunk, options[:alphabet], options[:shift] )
			end

		self.log.debug "Armor output: %p" % [ output ]

		return output.chars.each_slice( 43 ).map( &:join ).
			join( ' ' ) if options[:raw]

		words = output.chars.each_slice( 15 ).map( &:join )
		sentences = words.each_slice( 200 )

		joined = sentences.map {|words| words.join(' ') }.join( "\n" )
		header = "BEGIN SALTPACK %s. " % [ options[:message_type] ]
		footer = ". END SALTPACK %s." % [ options[:message_type] ]

		return header + joined + footer
	end


	### Decode the ascii-armored data from the specified +input_chars+ using
	### the given +options+.
	def dearmor( input_chars, **options )
		options = Saltpack::DEFAULT_ARMOR_OPTIONS.merge( options )

		unless options[:raw]
			_header, input_chars, _footer = input_chars.split( '.', 3 )
			self.log.debug "Stripped input: %p" % [ input_chars ]
		end

		chunks = input_chars.gsub( /\p{Space}+/, '' ).chars.
			each_slice( options[:char_block_size] ).
			map( &:join )

		output = String.new( encoding: 'binary' )
		chunks.each do |chunk|
			output << Saltpack.decode_block( chunk, options[:alphabet], options[:shift] )
		end

		return output
	end


	### Encode a single block of ascii-armored output from +bytes_block+ using the
	### specified +alphabet+ and +shift+.
	def encode_block( bytes_block, alphabet=Saltpack::B62ALPHABET, shift=false )
		block_size = Saltpack.character_block_size( alphabet.length, bytes_block.length )
		extra = Saltpack.extra_bits( alphabet.length, block_size, bytes_block.length )

		# Convert the bytes into an integer, big-endian.
		bytes_int = bytes_block.unpack1( 'H*' ).hex

		# Shift left by the extra bits.
		bytes_int <<= extra if shift

		# Convert the result into our base.
		places = []
		( 0 ... block_size ).each do |place|
			rem = bytes_int % alphabet.length
			places.unshift( rem )
			bytes_int /= alphabet.length
		end

		return places.map {|i| alphabet[i] }.join
	end


	### Decode the specified ascii-armored +chars_block+ using the specified
	### +alphabet+ and +shift+.
	def decode_block( chars_block, alphabet=Saltpack::B62ALPHABET, shift=false )
	    bytes_size = Saltpack.max_bytes_size( alphabet.length, chars_block.length )
	    expected_block_size = Saltpack.character_block_size( alphabet.length, bytes_size )

		self.log.debug "For %p with an alphabet of %d chars: bytes_size=%d; expected_block_size=%d" %
			[ chars_block, alphabet.length, bytes_size, expected_block_size ]

		raise ArgumentError, "illegal block size %d, expected %d" %
			[ chars_block.length, expected_block_size ] unless
				chars_block.length == expected_block_size

	    extra = Saltpack.extra_bits( alphabet.length, chars_block.length, bytes_size )

	    # Convert the chars to an integer.
	    bytes_int = Saltpack.get_char_index( alphabet, chars_block[0] )
		chars_block[ 1.. ].chars.each do |char|
	        bytes_int *= alphabet.length
	        bytes_int += Saltpack.get_char_index( alphabet, char )
		end

	    # Shift right by the extra bits.
	    bytes_int >>= extra if shift

		return [ bytes_int.to_s(16) ].pack( 'H*' )
	end


	### Return a table of the most efficient number of characters to use between 1
	### and +chars_size_upper_bound+ using an alphabet of +alphabet_size+. Each row
	### of the resulting Array will be a tuple of:
	###
	###     [ character_size, byte_size, efficiency ]
	def efficient_chars_sizes( alphabet_size, chars_size_upper_bound=50 )
	    out = []
	    max_efficiency = 0.0

		( 1..chars_size_upper_bound ).each do |chars_size|
			bytes_size = Saltpack.max_bytes_size( alphabet_size, chars_size )
			efficiency = bytes_size / chars_size.to_f
			self.log.debug "Efficiency for %d/%d: %0.3f" % [ bytes_size, chars_size, efficiency ]

			if efficiency > max_efficiency
				out << [ chars_size, bytes_size, efficiency ]
				max_efficiency = efficiency
			end
		end

		return out
	end

end # module Saltpack


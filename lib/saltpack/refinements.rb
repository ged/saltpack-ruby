# -*- ruby -*-
# frozen_string_literal: true

require 'rbnacl'

require 'saltpack' unless defined?( Saltpack )


module Saltpack::Refinements

	refine RbNaCl::Box do

		### Get the shared key for the box derived from the specified +public_key+ and
		### +private_key+.
		def self::beforenm( public_key, private_key )
			key = RbNaCl::Utils.zeros( RbNaCl::Box::BEFORENMBYTES )
			self.box_curve25519xsalsa20poly1305_beforenm( key, public_key, private_key ) or
				return nil

			return key
		end


		### Decrypt the specified +num_bytes+ of +ciphertext+ using the given +nonce+
		### and +beforenm+.
		def self::open_afternm( ciphertext, beforenm, nonce, num_bytes )
			message = RbNaCl::Utils.zeros( num_bytes )
			# m,c,clen,n,k
			self.box_curve25519xsalsa20poly1305_open_afternm( message,
				ciphertext, ciphertext.bytesize, nonce, beforenm ) or return nil

			return message
		end

	end # refine RbNaCl::Box

end # module Saltpack::Refinements


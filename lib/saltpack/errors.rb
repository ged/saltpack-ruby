# -*- ruby -*-
# frozen_string_literal: true

require 'e2mmap'

require 'saltpack' unless defined?( Saltpack )


module Saltpack
	extend Exception2MessageMapper

	def_exception :Error, "saltpack error"

	def_exception :KeyError, "missing/malformed key error"

	def_exception :MalformedMessage, "malformed saltpack message", Saltpack::Error
	def_exception :HMACError, "HMAC mismatch", Saltpack::Error

	def_exception :UnsupportedFormat, "unrecognized format name", Saltpack::Error
	def_exception :UnsupportedVersion, "incompatible version", Saltpack::Error

end # module Saltpack


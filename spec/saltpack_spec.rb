#!/usr/bin/env rspec -cfd
#encoding: utf-8

require_relative 'spec_helper'

require 'rspec'
require 'saltpack'

describe Saltpack do

	KEY1_PRIVATE = '82d2cd66f092bd818e083e6739b8d15c58d04b73dff5d1bc95c26b0ace849bb3'
	KEY1_PUBLIC  = '864a7cc8e98e956afa59ad3a7c9bd6ee578a2c1ce5ea6c450120ac6cdd727ee2'

	KEY2_PRIVATE = 'c4ac045f627ed4203a62fad6ee1aeb1ad59c1ed389143e14857a79d011daa7e5'
	KEY2_PUBLIC  = 'a123fb8b2de9eb142d5c8283b0bfc6076bc94d5a24039e8d485cae2d81e18293'

	KEYBASE_TEST_MESSAGE    = read_test_data( 'msg1.txt' )
	KEYBASE_TEST_CIPHERTEXT = read_test_data( 'msg1-ciphertext.txt' )

	KEYBASE_TEST_CIPHERTEXT_CORRUPT = KEYBASE_TEST_CIPHERTEXT.sub( /7/, 'h' )

	MALFORMED_MESSAGE = \
		#    badness here ↓
		"\xc4\x97\x96\xa8XXXXpack\x92\x01\x00\x00\xc4 \xf6\xa9\x9e\xe2\xac7\x8c.B" \
		"o\x02-\x8b}^\xf0\x90\xee4_C\xeb\xc9\x842\x1fe\xbf\xd8\x18\x0bb\xc402\xe9" \
		"\xc6c\xcf;=;\xfd\x17\xc5\xc1\x04\"\xa7\xc9\xe9\xb0*\xc2\xbfa\xa0<\xc4 T" \
		"\x7f\xc4-z\x8d\xa4\x07\xd6\xa1\xa1\xecP\xf5\x1b\n\xc2\xdc\x952\xf09\x91" \
		"\x92\xc0\xc40\xd0\xf3\xdcM[\x94\xb0F\xa0l\x109\xd64\xd6\x89\x7f\x12.\x13" \
		"/C\x83\xd6\xba\xbaQ\xf1W\x990\x94\x83\x10fh\x9c\xa8$]\x7fn\x93*\x99\x83" \
		"\xe4\x0e\x92\x91\xc4 y\xe1*\xbda\x9bE\x85+7\xfd\xfasE\xf6\xaa\x9f\x97o" \
		"\xa4\xfeB\xf5r\xcb\x01\x8a\xd9\xa5d\xbc\xa6\xc4\x10:\x0b\x8f\xbf\xfa>#" \
		"\xaa\xe3ax\xfb\xd2?M\x9c".b

	BAD_VERSION_MESSAGE = \
		#                  badness here ↓
		"\xc4\x97\x96\xa8saltpack\x92\xff\x00\x00\xc4 \xf6\xa9\x9e\xe2\xac7\x8c.B" \
		"o\x02-\x8b}^\xf0\x90\xee4_C\xeb\xc9\x842\x1fe\xbf\xd8\x18\x0bb\xc402\xe9" \
		"\xc6c\xcf;=;\xfd\x17\xc5\xc1\x04\"\xa7\xc9\xe9\xb0*\xc2\xbfa\xa0<\xc4 T" \
		"\x7f\xc4-z\x8d\xa4\x07\xd6\xa1\xa1\xecP\xf5\x1b\n\xc2\xdc\x952\xf09\x91" \
		"\x92\xc0\xc40\xd0\xf3\xdcM[\x94\xb0F\xa0l\x109\xd64\xd6\x89\x7f\x12.\x13" \
		"/C\x83\xd6\xba\xbaQ\xf1W\x990\x94\x83\x10fh\x9c\xa8$]\x7fn\x93*\x99\x83" \
		"\xe4\x0e\x92\x91\xc4 y\xe1*\xbda\x9bE\x85+7\xfd\xfasE\xf6\xaa\x9f\x97o" \
		"\xa4\xfeB\xf5r\xcb\x01\x8a\xd9\xa5d\xbc\xa6\xc4\x10:\x0b\x8f\xbf\xfa>#" \
		"\xaa\xe3ax\xfb\xd2?M\x9c".b


	describe "encryption" do

		xit "can encrypt and decrypt with defaults" do
			result = described_class.encrypt( KEYBASE_TEST_MESSAGE )
			expect( described_class.decrypt(result) ).to eq( KEYBASE_TEST_MESSAGE )
		end


		xit "can decrypt with a secret key" do
			ciphertext_binary = described_class.dearmor( KEYBASE_TEST_CIPHERTEXT )
			result = described_class.decrypt( ciphertext_binary, KEY2_PRIVATE )
			expect( result ).to eq( KEYBASE_TEST_MESSAGE )
		end


		xit "errors when the message armor has been tampered with" do
			ciphertext_binary = described_class.dearmor( KEYBASE_TEST_CIPHERTEXT_CORRUPT )
			expect {
				described_class.decrypt( ciphertext_binary, KEY2_PRIVATE )
			}.to raise_error( Saltpack::HMACError )
		end


		xit "errors when the message is malformed" do
			expect {
				described_class.decrypt( MALFORMED_MESSAGE )
			}.to raise_error( Saltpack::MalformedMessage )
		end


		xit "errors when the message is the wrong version" do
			expect {
				described_class.decrypt( BAD_VERSION_MESSAGE )
			}.to raise_error( Saltpack::UnsupportedVersion )
		end

	end

end


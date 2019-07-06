#!/usr/bin/env rspec -cfd
#encoding: utf-8

require_relative 'spec_helper'

require 'rspec'
require 'saltpack'

describe Saltpack do

	INPUT_STRING = <<~END_PLAINTEXT
		Two roads diverged in a yellow wood, and sorry I could not travel both
		and be one traveller, long I stood, and looked down one as far as I
		could, to where it bent in the undergrowth.
	END_PLAINTEXT

	MESSAGE = 'foo bar'

	KEYBASE_TEST_CIPHERTEXT = <<~END_CYPHERTEXT
	BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiPgBwdlv6bV9N8 dSkCbjKrku2KOWE
	CKyuTXpSz8eiQEL e3MQnnUPheUrja0 Y8Fup2Sq6nJpfDJ DUH4yLqN5VvQAZv 6LiCR5GtOcL0hmT
	jmvskQLPoOpAHxJ 9ogsAlwftLw1WV2 aR1SuuiAJuz6EpP U5UQP9glbDpWhdZ jGONhLE7eGgKaVH
	yLVe6rNWZ1zSMrD hCiTLJI7R1KwHUA AzK0PWx00xArC3A 1xjMUCWAeHGL6E0 An0sR7CxTFor8yQ
	mDfbmMhUKYuFtaU cs51HK5VFmTujND c2u7zCiR99p8MmD QlNIpyzxQjKMF8O KJVouyGur2yAad0
	cNbKnEWtEgdHjcZ n3INBILp0h5k1uB 85PzUtZFSdw2JWb twzlH01O5TLQYjl gqlFyLel494wNiq
	be9wvgTLriGf87k ArswlMWnoco0ov9 Yo7boufHjV4O6xd IQjmBvKRZ8XbzfP tqUjeYOja6RzNLy
	AMnyZ2l9qVGpuzr 00ZebHI7NaHqRxm VCLXjDd8Tu1Xrzy EboJQ6ju0Qqsj1E ELw6WuudzURlLC2
	SXrbic8Kw0S1cQI 5v9o02hAitWUxVz vEsHX8ARAmdxF6j QI3rb8frPEX0f0F 7a8O5Ki0vk4uRI1
	CGPGOA2gvgAqSi8 JXJylLGG8Ifq7fs X6pQZ3UQMu08auk D2e4dkcox1yQrkV TxdvqHMfyIRe2ya
	THLaUOnc3FdC3rN OVBMwQBT16AQBIz 5QGOKSkKqpYeFsI YU1C7sz7zVTvOlx xDsz9YoQ3A4V9NS
	9k0qkyTnojnvyws luQvnshKqQrdx5P 6ZYK75PAcn1xyl3 ZbNw4HUIWSDQrKN 5fS5uUiu64Uj2sQ
	40GK4IfZwgZAhyT XLcKVjSWvkZ125s zTc0YNcka4wM1ke Thm2Y7dMAzfcmhC OlGs4gQMCxjq0LI
	0W3fXOlEkII1Ejp ENaZSMcWlFJm2oi j3xzHMyoI9yIh0a p3xSR3BJ9Gtu9wN kjHNyFsnkP62qhQ
	lvl9Kuq53Fj6u8E fc2DLU9rNtrn03H BJ5wvg. END KEYBASE SALTPACK ENCRYPTED MESSAGE.
	END_CYPHERTEXT

	KEYBASE_TEST_CIPHERTEXT_CORRUPT = <<~END_CYPHERTEXT
	BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiPgBwdlv6bV9N8 dSkCbjKrku2KOWE
	CKyuTXpSz8eiQEL e3MQnnUPheUrja0 Y8Fup2Sq6nJpfDJ DUH4yLqN5VvQAZv 6LiCR5GtOcL0hmT
	jmvskQLPoOpAHxJ 9ogsAlwftLw1WV2 aR1SuuiAJuz6EpP U5UQP9glbDpWhdZ jGONhLE7eGgKaVH
	yLVe6rNWZ1zSMrD hCiTLJI7R1KwHUA AzK0PWx00xArC3A 1xjMUCWAeHGL6E0 An0sR7CxTFor8yQ
	mDfbmMhUKYuFtaU cs51HK5VFmTujND c2u7zCiR99p8MmD QlNIpyzxQjKMF8O KJVouyGur2yAad0
	cNbKnEWtEgdHjcZ n3INBILp0h5k1uB 85PzUtZFSdw2JWb twzlH01O5TLQYjl gqlFyLel494wNiq
	be9wvgTLriGf87k ArswlMWnoco0ov9 Yo7boufHjV4O6xd IQjmBvKRZ8XbzfP tqUjeYOja6RzNLy
	AMnyZ2l9qVGpuzr 00ZebHI7NaHqRxm VCLXjDd8Tu1Xrzy EboJQ6ju0Qqsj1E ELw6WuudzURlLC2
	SXrbic8Kw0S1cQI 5v9o02hAitWUxVz vEsHX8ARAmdxF6j QI3rb8frPEX0f0F 7a8O5Ki0vk4uRI1
	CGPGOA2gvgAqSi8 JXJylLGG8Ifq7fs X6pQZ3UQMu08auk D2e4dkcox1yQrkV TxdvqHMfyIRe2ya
	THLaUOnc3FdC3rN OVBMwQBT16AQBIz 5QGOKSkKqpYeFsI YU1C7sz7zVTvOlx xDsz9YoQ3A4V9NS
	9k0qkyTnojnvyws luQvnshKqQrdx5P 6ZYK75PAcn1xyl3 ZbNw4RX2rVGI15H BxJi4sZxh2w9GQs
	YTJt6IfZwgZAhyT XLcKVjSWvkZ125s zTc0YNcka4wM1ke Thm2Y7dMAzfcmhC OlGs4gQMCxjq0LI
	0W3fXOlEkII1Ejp ENaZSMcWlFJm2oi j3xzHMyoI9yIh0a p3xSR3BJ9Gtu9wN kjHNyFsnkP62qhQ
	lvl9Kuq53Fj6u8E fc2DLU9rNtrn03H BJ5wvg. END KEYBASE SALTPACK ENCRYPTED MESSAGE.
	END_CYPHERTEXT

	KEYBASE_TEST_PLAINTEXT = 'real keybase message'

	KEYBASE_TEST_SECRET_KEY =
	    "f9fc08c9ad53d97859c5fa7e9755e638c5d8942bfc3742b6f27d6147ffdf5389"


	describe "blocks" do

		it "can be round-tripped" do
			blocked = described_class.encode_block( INPUT_STRING )
			unblocked = described_class.decode_block( blocked )

			expect( unblocked ).to eq( INPUT_STRING )
		end

	end


	describe "armoring" do

		it "can be round-tripped" do
			encoded = described_class.armor( INPUT_STRING )
			Saltpack.log.debug "encoded: %p" % [ encoded ]
			decoded = described_class.dearmor( encoded )
			Saltpack.log.debug "decoded: %p" % [ decoded ]

			expect( decoded ).to eq( INPUT_STRING )
		end


		it "can be round-tripped in raw format" do
			encoded = described_class.armor( INPUT_STRING, raw: true )
			decoded = described_class.dearmor( encoded, raw: true )

			expect( decoded ).to eq( INPUT_STRING )
		end

	end


	describe "efficient block sizes" do

		it "can be calculated for a given alphabet size" do
			results = described_class.efficient_chars_sizes( 64 )
			expect( results ).to include( [4, 3, 0.75] )
		end

	end


	describe "encryption" do

		let( :malformed_message ) do
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
		end

		let( :bad_version_message ) do
			#                  badness her" \
			"\xc4\x97\x96\xa8saltpack\x92\xff\x00\x00\xc4 \xf6\xa9\x9e\xe2\xac7\x8c.B" \
			"o\x02-\x8b}^\xf0\x90\xee4_C\xeb\xc9\x842\x1fe\xbf\xd8\x18\x0bb\xc402\xe9" \
			"\xc6c\xcf;=;\xfd\x17\xc5\xc1\x04\"\xa7\xc9\xe9\xb0*\xc2\xbfa\xa0<\xc4 T" \
			"\x7f\xc4-z\x8d\xa4\x07\xd6\xa1\xa1\xecP\xf5\x1b\n\xc2\xdc\x952\xf09\x91" \
			"\x92\xc0\xc40\xd0\xf3\xdcM[\x94\xb0F\xa0l\x109\xd64\xd6\x89\x7f\x12.\x13" \
			"/C\x83\xd6\xba\xbaQ\xf1W\x990\x94\x83\x10fh\x9c\xa8$]\x7fn\x93*\x99\x83" \
			"\xe4\x0e\x92\x91\xc4 y\xe1*\xbda\x9bE\x85+7\xfd\xfasE\xf6\xaa\x9f\x97o" \
			"\xa4\xfeB\xf5r\xcb\x01\x8a\xd9\xa5d\xbc\xa6\xc4\x10:\x0b\x8f\xbf\xfa>#" \
			"\xaa\xe3ax\xfb\xd2?M\x9c".b
		end


		it "can encrypt and decrypt with defaults" do
			result = described_class.encrypt( MESSAGE )
			expect( described_class.decrypt(result) ).to eq( MESSAGE )
		end


		fit "can decrypt with a secret key" do
			cyphertext_binary = described_class.dearmor( KEYBASE_TEST_CIPHERTEXT )
			result = described_class.decrypt( cyphertext_binary, KEYBASE_TEST_SECRET_KEY )
			expect( result ).to eq( KEYBASE_TEST_PLAINTEXT )
		end


		it "errors when the message armor has been tampered with" do
			cyphertext_binary = described_class.dearmor( KEYBASE_TEST_CIPHERTEXT_CORRUPT )
			expect {
				described_class.decrypt( cyphertext_binary, KEYBASE_TEST_SECRET_KEY )
			}.to raise_error( Saltpack::HMACError )
		end


		it "errors when the message is malformed" do
			expect {
				described_class.decrypt( malformed_message )
			}.to raise_error( Saltpack::MalformedMessage )
		end


		it "errors when the message is the wrong version" do
			expect {
				described_class.decrypt( bad_version_message )
			}.to raise_error( Saltpack::UnsupportedVersion )
		end

	end

end


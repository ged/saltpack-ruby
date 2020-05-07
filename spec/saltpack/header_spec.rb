#!/usr/bin/env rspec -cfd

require_relative '../spec_helper'

require 'rbnacl'
require 'msgpack'

require 'saltpack'


describe Saltpack::Header do

	let( :sender_key ) { RbNaCl::PrivateKey.generate }
	let( :sender_public_key ) { sender_key.public_key }

	let( :recipient_keys ) do
		4.times.map { RbNaCl::PrivateKey.generate }
	end
	let( :recipient_public_keys ) do
		recipient_keys.map( &:public_key )
	end


	it "can generate a valid Saltpack header" do
		header = described_class.new( sender_key: sender_key )
		header.recipients.append( *recipient_public_keys )

		data = header.data
		once_unpacked = MessagePack.unpack( data )
		twice_unpacked = MessagePack.unpack( once_unpacked )

		expect( header.hash ).to eq( RbNaCl::Hash.sha512(once_unpacked) )
		expect( twice_unpacked ).to be_an( Array )
		expect( twice_unpacked.length ).to eq( 6 )
	end


	it "can set the mode as a Symbol" do
		header = described_class.new
		header.mode = :detached_signing

		expect( header.mode ).to eq( :detached_signing )
		expect( header.numeric_mode ).to eq( 2 )
	end


	it "can set the mode as an Integer" do
		header = described_class.new
		header.mode = 4

		expect( header.mode ).to eq( :signcryption )
		expect( header.numeric_mode ).to eq( 4 )
	end


	it "raises if the mode is set to an invalid value" do
		header = described_class.new

		expect {
			header.mode = 18
		}.to raise_error( ArgumentError, /invalid/i )
	end


	it "can be parsed from a string" do
		hdr = described_class.parse( "", recipient_keys )

		expect( hdr ).to be_a( described_class )
		expect( hdr.format_name ).to eq( "saltpack" )
		expect( hdr.version ).to eq([ 2, 0 ])
		expect( hdr.numeric_mode ).to eq( 0 )
		expect( hdr.mode ).to eq( :encryption )
		expect( hdr.numeric_mode ).to eq( 0 )
		expect( hdr.ephemeral_public_key ).to match( /\A.{32}\z/n )
		expect( hdr.sender_secretbox ).to be_a( RbNaCl::SecretBox )
		expect( hdr.recipients ).to be_an( Array ).and( all be_a Saltpack::Recipient )
	end


	it "raises an appropriate exception if asked to parse anything other than msgpack format" do
		expect {
			described_class.parse( "\xc1", recipient_keys )
		}.to raise_error( Saltpack::MalformedMessage )
	end

end


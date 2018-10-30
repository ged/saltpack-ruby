#!/usr/bin/env rspec -cfd

require_relative '../spec_helper'

require 'rbnacl'
require 'msgpack'

require 'saltpack'


describe Saltpack::Header do

	it "can be parsed from a string" do
		hdr = described_class.parse( "" )

		expect( hdr ).to be_a( described_class )
		expect( hdr.format_name ).to eq( "saltpack" )
		expect( hdr.version ).to eq([ 2, 0 ])
		expect( hdr.mode ).to eq( 0 )
		expect( hdr.mode ).to eq( :encryption )
		expect( hdr.numeric_mode ).to eq( 0 )
		expect( hdr.ephemeral_public_key ).to match( /\A.{32}\z/n )
		expect( hdr.sender_secretbox ).to be_a( RbNaCl::SecretBox )
		expect( hdr.recipients ).to be_an( Array ).and( all be_a Saltpack::Recipient )
	end


	it "raises an appropriate exception if asked to parse anything other than msgpack format" do
		expect {
			described_class.parse( "foom" )
		}.to raise_error( Saltpack::MalformedMessage )
	end

end


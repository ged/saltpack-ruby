#!/usr/bin/env rspec -cfd

require_relative '../spec_helper'

require 'saltpack'


describe Saltpack::Recipient do

	let( :ephemeral_private_key ) { RbNaCl::PrivateKey.generate }
	let( :ephemeral_public_key ) { ephemeral_private_key.public_key }

	let( :recipient_private_key ) { RbNaCl::PrivateKey.generate }
	let( :recipient_public_key ) { recipient_private_key.public_key }


	it "can be created with a NaCl public key" do
		recipient = described_class.new( recipient_public_key )

		expect( recipient ).to be_a( described_class )
		expect( recipient.payload_key_box ).to be_a( RbNaCl::Box )
	end

end


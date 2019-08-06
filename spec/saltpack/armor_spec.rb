#!/usr/bin/env rspec -cfd

require_relative '../spec_helper'

require 'saltpack/armor'


describe Saltpack::Armor do

	INPUT_STRING = <<~END_PLAINTEXT
		Two roads diverged in a yellow wood, and sorry I could not travel both
		and be one traveller, long I stood, and looked down one as far as I
		could, to where it bent in the undergrowth.
	END_PLAINTEXT


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


	describe "blocks" do

		it "can be round-tripped" do
			blocked = described_class.encode_block( INPUT_STRING )
			unblocked = described_class.decode_block( blocked )

			expect( unblocked ).to eq( INPUT_STRING )
		end

	end


	describe "efficient block sizes" do

		it "can be calculated for a given alphabet size" do
			results = described_class.efficient_chars_sizes( 64 )
			expect( results ).to include( [4, 3, 0.75] )
		end

	end

end


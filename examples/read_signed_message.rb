#!/usr/bin/env ruby

require 'rbnacl'
require 'saltpack'

key1 = RbNaCl::PrivateKey.
	new( ["1e42fd5f0ba92398e6e87b633d06987467f237caac217693c7ee14056f153b3a"].pack('h*') )
key2 = RbNaCl::PrivateKey.
	new( ["3d8ff66ec5d042a41fdcc93e57b909647e9017a6599f8120dd1726a4772a0626"].pack('h*') )


cipher_text = <<END_CIPHERTEXT
BEGIN SALTPACK ENCRYPTED MESSAGE. kcJn5brvybfNjz6 D5litY0cggy6Vip E4QpUu5OvLgbjMk FMaXiSb8GXMyySD
j4jKKy6eshXj7uV eoBntXXaehOWYTX 1jmyakG0jwFTdTl CbhvBEhCKG0ZwEO JQmFeNgmJI94Rjy b8sIO98nc4WrBjN
5NJZQ084gguBURI aSowMUMeZMRGP4J AfJcB9wCPhWGQKU eBxLOaMO8JpLK3t hygE12BhIQaNwZb KLYuAtnrVtMDTDF
E9ElLh18bNEMWDY YFn0kECigyVVlj1 9AoOmC9hdNImVq6 u0yoiRo7XlqAKpn 9mPansw58xROIOB usUbaNKJRNFqPas
JyvvcKw8mOMxIBv dDTkfLWBW2mKwJN QcPMYZOTQ4zsM2q QqZjexbhsqJ80Ll d9A. END SALTPACK ENCRYPTED MESSAGE.
END_CIPHERTEXT

msg = Saltpack::Message.read( cipher_text )
msg.decrypt( key2.private_key )


#!/usr/bin/env ruby

require 'saltpack'


user = ARGV.shift or abort "No username specified."
user = "@#{user}" unless user.start_with?( '@' )


message = <<-END_OF_MESSAGE


END_OF_MESSAGE

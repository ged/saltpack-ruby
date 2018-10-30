# -*- ruby -*-
# frozen_string_literal: true

# Toplevel namespace
module Saltpack

	# Package version
	VERSION = '0.0.1'

	# Version control revision
	REVISION = %q$Revision: e216e8bc10bb $


	require 'saltpack/errors'

	autoload :Header, 'saltpack/header'
	autoload :Recipient, 'saltpack/recipient'

end # module Saltpack


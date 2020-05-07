# -*- encoding: utf-8 -*-
# stub: saltpack 0.1.0.pre.20200506181314 ruby lib

Gem::Specification.new do |s|
  s.name = "saltpack".freeze
  s.version = "0.1.0.pre.20200506181314"

  s.required_rubygems_version = Gem::Requirement.new("> 1.3.1".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Michael Granger".freeze]
  s.date = "2020-05-06"
  s.description = "A Ruby implementation of Saltpack, a modern crypto messaging format based on Dan Bernstein's {NaCl}[https://nacl.cr.yp.to/].".freeze
  s.email = ["ged@faeriemud.org".freeze]
  s.files = [".document".freeze, ".rdoc_options".freeze, ".simplecov".freeze, "ChangeLog".freeze, "History.md".freeze, "LICENSE.txt".freeze, "Manifest.txt".freeze, "README.md".freeze, "Rakefile".freeze, "examples/post_signed_message.rb".freeze, "lib/saltpack.rb".freeze, "lib/saltpack/armor.rb".freeze, "lib/saltpack/errors.rb".freeze, "lib/saltpack/header.rb".freeze, "lib/saltpack/message.rb".freeze, "lib/saltpack/payload.rb".freeze, "lib/saltpack/recipient.rb".freeze, "lib/saltpack/refinements.rb".freeze, "spec/data/msg1-ciphertext.txt".freeze, "spec/data/msg1.txt".freeze, "spec/saltpack/armor_spec.rb".freeze, "spec/saltpack/header_spec.rb".freeze, "spec/saltpack/recipient_spec.rb".freeze, "spec/saltpack_spec.rb".freeze, "spec/spec_helper.rb".freeze]
  s.homepage = "https://hg.sr.ht/~ged/Saltpack".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.0.6".freeze
  s.summary = "A Ruby implementation of Saltpack, a modern crypto messaging format based on Dan Bernstein's {NaCl}[https://nacl.cr.yp.to/].".freeze

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<loggability>.freeze, ["~> 0.14"])
      s.add_runtime_dependency(%q<rbnacl>.freeze, ["~> 5.0"])
      s.add_runtime_dependency(%q<msgpack>.freeze, ["~> 1.2"])
      s.add_development_dependency(%q<hoe-deveiate>.freeze, ["~> 0.10"])
      s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.7"])
      s.add_development_dependency(%q<rdoc-generator-fivefish>.freeze, ["~> 0.3"])
      s.add_development_dependency(%q<rdoc>.freeze, ["~> 6.2"])
    else
      s.add_dependency(%q<loggability>.freeze, ["~> 0.14"])
      s.add_dependency(%q<rbnacl>.freeze, ["~> 5.0"])
      s.add_dependency(%q<msgpack>.freeze, ["~> 1.2"])
      s.add_dependency(%q<hoe-deveiate>.freeze, ["~> 0.10"])
      s.add_dependency(%q<simplecov>.freeze, ["~> 0.7"])
      s.add_dependency(%q<rdoc-generator-fivefish>.freeze, ["~> 0.3"])
      s.add_dependency(%q<rdoc>.freeze, ["~> 6.2"])
    end
  else
    s.add_dependency(%q<loggability>.freeze, ["~> 0.14"])
    s.add_dependency(%q<rbnacl>.freeze, ["~> 5.0"])
    s.add_dependency(%q<msgpack>.freeze, ["~> 1.2"])
    s.add_dependency(%q<hoe-deveiate>.freeze, ["~> 0.10"])
    s.add_dependency(%q<simplecov>.freeze, ["~> 0.7"])
    s.add_dependency(%q<rdoc-generator-fivefish>.freeze, ["~> 0.3"])
    s.add_dependency(%q<rdoc>.freeze, ["~> 6.2"])
  end
end

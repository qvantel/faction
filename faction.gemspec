# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'faction/version'

Gem::Specification.new do |spec|
  spec.name          = "faction"
  spec.version       = Faction::VERSION
  spec.authors       = ["Olli Helenius"]
  spec.email         = ["olli.helenius@onesto.fi"]
  spec.description   = %q{A simple Savon-based client for Atlassian Crowd SOAP API}
  spec.summary       = %q{A simple Savon-based client for Atlassian Crowd SOAP API}
  spec.homepage      = "https://github.com/onesto/faction"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"

  spec.add_dependency 'savon', '< 0.8'
end

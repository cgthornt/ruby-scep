# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'scep/version'

Gem::Specification.new do |spec|
  spec.name          = 'ruby-scep'
  spec.version       = SCEP::VERSION
  spec.authors       = ['Christopher Thornton']
  spec.email         = ['christopher.thornton@onelogin.com']
  spec.summary       = %q{SCEP libraries}
  spec.description   = %q{Makes development of SCEP services easier}
  spec.homepage      = 'https://github.com/cgthornt/scep-gem'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 2.2.0'


  spec.add_dependency 'openssl-extensions'
  spec.add_dependency 'httparty'

  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'codeclimate-test-reporter'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'webmock'
end

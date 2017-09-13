# frozen_string_literal: true

module SCEP
  module PKIOperation
    class VerificationFailed < StandardError; end

    autoload :Base,     'scep/pki_operation/base'
    autoload :Proxy,    'scep/pki_operation/proxy'
    autoload :Request,  'scep/pki_operation/request'
    autoload :Response, 'scep/pki_operation/response'
  end
end

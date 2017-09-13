# frozen_string_literal: true

module SCEP
  # A public / private keypair
  class Keypair
    # @return [OpenSSL::X509::Certificate]
    attr_accessor :certificate
    alias cert certificate

    # @return [OpenSSL::PKey]
    attr_accessor :private_key

    def initialize(certificate, private_key)
      raise ArgumentError, '`certificate` must be an OpenSSL::X509::Certificate' unless
        certificate.is_a?(OpenSSL::X509::Certificate)

      unless certificate.check_private_key(private_key)
        raise ArgumentError, '`private_key` does not match `certificate`'
      end

      @certificate = certificate
      @private_key = private_key
    end

    # Loads a keypair from a file
    # @param [String] certificate_filepath
    # @param [String] private_key_filepath
    # @param [String] private_key_passphrase add this if you
    # @return [Keypair]
    def self.read(certificate_filepath, private_key_filepath, private_key_passphrase = nil)
      x509_cert = OpenSSL::X509::Certificate.new File.read(certificate_filepath.to_s)
      pkey      = read_private_key(File.open(private_key_filepath.to_s).read, private_key_passphrase)
      new(x509_cert, pkey)
    end

    class << self
      private

      def read_private_key(encoded_key, passphrase = nil)
        OpenSSL::PKey.read encoded_key, passphrase
      end
    end
  end
end

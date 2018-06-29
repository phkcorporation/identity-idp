module Encryption
  module Encryptors
    class AttributeEncryptor
      include Encodable

      def initialize
        @aes_cipher = AesCipher.new
        @stale = false
      end

      def encrypt(plaintext)
        unless Figaro.env.attribute_encryption_without_kms == 'true'
          return DeprecatedAttributeEncryptor.new.encrypt(plaintext)
        end

        aes_encrypted_ciphertext = aes_cipher.encrypt(plaintext, current_key)
        encode(aes_encrypted_ciphertext)
      end

      def decrypt(ciphertext)
        return DeprecatedAttributeEncryptor.new.decrypt(ciphertext) if legacy?(ciphertext)
        raise EncryptionError, 'ciphertext invalid' unless valid_base64_encoding?(ciphertext)
        decoded_ciphertext = decode(ciphertext)
        try_decrypt(decoded_ciphertext)
      end

      def stale?
        stale
      end

      private

      attr_reader :aes_cipher
      attr_accessor :stale

      def try_decrypt(decoded_ciphertext)
        all_keys.each do |key|
          try_decrypt_with_key(decoded_ciphertext, key)
        end
        raise EncryptionError, 'unable to decrypt attribute with any key'
      end

      def try_decrypt_with_key(decoded_ciphertext, key)
        self.stale = key != current_key
        aes_cipher.decrypt(decoded_ciphertext, key)
      rescue EncryptionError
        nil
      end

      def legacy?(ciphertext)
        Encryption::KmsClient.looks_like_kms?(ciphertext) || ciphertext.index('.')
      end

      def current_key
        Figaro.env.attribute_encryption_key
      end

      def all_keys
        [current_key].concat(old_keys.collect { |hash| hash['key'] })
      end

      def old_keys
        JSON.parse(Figaro.env.attribute_encryption_key_queue)
      end
    end
  end
end

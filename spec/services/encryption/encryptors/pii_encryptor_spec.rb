require 'rails_helper'

describe Encryption::Encryptors::PiiEncryptor do
  let(:password) { 'password' }
  let(:plaintext) { 'Oooh baby baby' }

  subject { described_class.new(password) }

  describe '#encrypt' do
    it 'returns encrypted text' do
      ciphertext = subject.encrypt(plaintext)

      expect(ciphertext).to_not match plaintext
    end

    it 'uses the user access key encryptor to encrypt the plaintext' do
      salt = '0' * 20
      allow(Devise).to receive(:friendly_token).and_return(salt)

      scrypt_digest = '1' * 64

      scrypt_password = instance_double(SCrypt::Password)
      expect(scrypt_password).to receive(:digest).and_return(scrypt_digest)
      expect(SCrypt::Password).to receive(:new).and_return(scrypt_password)

      cipher = instance_double(Encryption::AesCipher)
      expect(Encryption::AesCipher).to receive(:new).and_return(cipher)
      expect(cipher).to receive(:encrypt).
        with(plaintext, scrypt_digest[0...32]).
        and_return('aes_ciphertext')

      kms_client = instance_double(Encryption::KmsClient)
      expect(Encryption::KmsClient).to receive(:new).and_return(kms_client)
      expect(kms_client).to receive(:encrypt).
        with('aes_ciphertext').
        and_return('kms_ciphertext')

      expected_ciphertext = Base64.strict_encode64('kms_ciphertext')

      ciphertext = subject.encrypt(plaintext)

      expect(ciphertext).to eq({
        encrypted_data: expected_ciphertext,
        salt: salt,
        cost: '800$8$1$',
      }.to_json)
    end
  end

  describe '#decrypt' do
    it 'returns the original text' do
      ciphertext = subject.encrypt(plaintext)
      decrypted_ciphertext = subject.decrypt(ciphertext)

      expect(decrypted_ciphertext).to eq(plaintext)
    end

    it 'requires the same password used for encrypt' do
      ciphertext = subject.encrypt(plaintext)
      new_encryptor = described_class.new('This is not the passowrd')

      expect { new_encryptor.decrypt(ciphertext) }.to raise_error Encryption::EncryptionError
    end

    it 'uses layered AES and KMS to decrypt the contents' do
      salt = '0' * 20
      allow(Devise).to receive(:friendly_token).and_return(salt)

      scrypt_digest = '1' * 64

      scrypt_password = instance_double(SCrypt::Password)
      expect(scrypt_password).to receive(:digest).and_return(scrypt_digest)
      expect(SCrypt::Password).to receive(:new).and_return(scrypt_password)

      kms_client = instance_double(Encryption::KmsClient)
      expect(Encryption::KmsClient).to receive(:new).and_return(kms_client)
      expect(kms_client).to receive(:decrypt).
        with('kms_ciphertext').
        and_return('aes_ciphertext')

      cipher = instance_double(Encryption::AesCipher)
      expect(Encryption::AesCipher).to receive(:new).and_return(cipher)
      expect(cipher).to receive(:decrypt).
        with('aes_ciphertext', scrypt_digest[0...32]).
        and_return(plaintext)

      result = subject.decrypt({
        encrypted_data: Base64.strict_encode64('kms_ciphertext'),
        salt: salt,
        cost: '800$8$1$',
      }.to_json)

      expect(result).to eq(plaintext)
    end
  end
end

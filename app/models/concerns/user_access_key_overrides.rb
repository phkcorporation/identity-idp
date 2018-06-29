# In order to perform scrypt calculation of password in a single
# place for both password and PII encryption, we override
# a few methods to build the encrypted_password via UserAccessKey
#
module UserAccessKeyOverrides
  extend ActiveSupport::Concern

  def valid_password?(password)
    result = Encryption::PasswordVerifier.verify(
      password: password,
      digest: encrypted_password_digest
    )
    log_password_verification_failure unless result
    result
  end

  def password=(new_password)
    @password = new_password
    return if @password.blank?
    self.encrypted_password_digest = Encryption::PasswordVerifier.digest(@password).to_s
  end

  # This is a devise method, which we are overriding. This should not be removed
  # as Devise depends on this for things like building the key to use when
  # storing the user in the session.
  def authenticatable_salt
    return if encrypted_password_digest.blank?
    Encryption::PasswordVerifier::PasswordDigest.parse_from_string(
      encrypted_password_digest
    ).password_salt
  end

  private

  def log_password_verification_failure
    metadata = {
      event: 'Failure to validate password',
      uuid: uuid,
      timestamp: Time.zone.now,
    }
    Rails.logger.info(metadata.to_json)
  end
end

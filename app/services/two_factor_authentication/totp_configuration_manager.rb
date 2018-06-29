module TwoFactorAuthentication
  class TotpConfigurationManager < ConfigurationManager
    def enabled?
      user&.totp_enabled?
    end

    def available?
      true
    end

    def configured?
      user&.totp_enabled?
    end

    ###
    ### Method-specific data management
    ###
    def confirm_configuration(secret, code)
      user.confirm_totp_secret(secret, code)
    end

    def generate_secret
      user.generate_totp_secret
    end

    def save_configuration
      user.save!
      Event.create(user_id: user.id, event_type: :authenticator_enabled)
    end

    def remove_configuration
    end

    def authenticate(code)
      code.match?(pattern_matching_code_format) &&
        user.authenticate_totp(code) 
    end

    private

    def pattern_matching_code_format
      /\A\d{#{code_length}}\Z/
    end

    def code_length
      Devise.otp_length
    end
  end
end

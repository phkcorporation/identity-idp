module TwoFactorAuthentication
  class SmsConfigurationManager < TwoFactorAuthentication::PhoneConfigurationManager
    def available?
      # TODO: check if the phone number disallows SMS
      #   - because Twilio doesn't support SMS to that number, OR
      #   - because the owner of the phone number has texted 'STOP' to us
      # PhoneNumberCapabilities.new(user.phone).sms_only?
      true
    end
    ###
    ### Method-specific data management
    ###
  end
end

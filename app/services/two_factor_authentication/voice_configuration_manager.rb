module TwoFactorAuthentication
  class VoiceConfigurationManager < TwoFactorAuthentication::PhoneConfigurationManager
    def available?
      !PhoneNumberCapabilities.new(user.phone).sms_only?
    end

    ###
    ### Method-specific data management
    ###
  end
end

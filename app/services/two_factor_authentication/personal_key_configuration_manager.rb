module TwoFactorAuthentication
  class PersonalKeyConfigurationManager < TwoFactorAuthentication::ConfigurationManager
    def enabled?
      user.personal_key.present?
    end

    def available?
      true # everyone can have a personal key
    end

    def configured?
      user.personal_key.present?
    end

    def configurable?
      true # we can always create a new personal key
    end

    ###
    ### Method-specific data management
    ###

    delegate :active_profile, to: :user

    def create_new_code(session)
      if active_profile.present?
        Pii::ReEncryptor.new(user: user, user_session: session).perform
        active_profile.personal_key
      else
        PersonalKeyGenerator.new(user).create
      end
    end
  end
end

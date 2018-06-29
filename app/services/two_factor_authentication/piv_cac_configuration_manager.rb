module TwoFactorAuthentication
  class PivCacConfigurationManager < ConfigurationManager
    def enabled?
      user.piv_cac_enabled?
    end

    def available?
      FeatureManagement.piv_cac_enabled? && user.piv_cac_available?
    end

    def configured?
      user.piv_cac_enabled?
    end

    ###
    ### Method-specific data management
    ###

    # we may split the setting and saving into multiple calls:
    #   1. setup configuration
    #   2. check that the configuration is unique
    #   3. save configuration
    def x509_dn_uuid=(uuid)
      user.x509_dn_uuid = uuid
    end

    def save_configuration
      user.save!
      Event.create(user_id: user.id, event_type: :piv_cac_enabled)
    end

    def remove_configuration
      user.update!(x509_dn_uuid: nil)
      Event.create(user_id: user.id, event_type: :piv_cac_disabled)
    end

    def x509_dn_uuid
      user.x509_dn_uuid
    end

    def authenticate(uuid)
      user.confirm_piv_cac?(uuid)
    end

    # OR: This can go in the PivCacSetupForm
    # the real question is if someone else has this configuration already
    def x509_dn_uuid_associated?(uuid)
      if User.find_by(x509_dn_uuid: x509_dn_uuid)
        true
      else
        false
      end
    end
  end
end

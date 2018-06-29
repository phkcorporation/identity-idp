class TotpSetupForm
  def initialize(user, secret, code)
    @user = user
    @secret = secret
    @code = code
    @configuration_manager = TwoFactorAuthentication::TotpConfigurationManager.new(user)
  end

  def submit
    @success = valid_totp_code?

    process_valid_submission if success

    FormResponse.new(success: success, errors: {})
  end

  private

  attr_reader :user, :code, :secret, :success, :configuration_manager

  def valid_totp_code?
    configuration_manager.confirm_configuration(secret, code)
  end

  def process_valid_submission
    configuration_manager.save_configuration
  end
end

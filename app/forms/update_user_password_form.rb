class UpdateUserPasswordForm
  include ActiveModel::Model
  include FormPasswordValidator

  delegate :personal_key, to: :encryptor

  def initialize(user, user_session = nil)
    @user = user
    @user_session = user_session
  end

  def submit(params)
    self.password = params[:password]
    success = valid?
    process_valid_submission if success
    FormResponse.new(success: success, errors: errors.messages)
  end

  private

  attr_reader :user, :user_session

  def process_valid_submission
    update_user_password
    email_user_about_password_change
    encrypt_user_profile_if_active
    increment_password_metrics
  end

  def update_user_password
    attributes = { password: password }
    UpdateUser.new(user: user, attributes: attributes).call
  end

  def email_user_about_password_change
    EmailNotifier.new(user).send_password_changed_email
  end

  def encrypt_user_profile_if_active
    active_profile = user.active_profile
    return if active_profile.blank?

    encryptor.call
  end

  def increment_password_metrics
    PasswordMetricsIncrementer.new(password).increment_password_metrics
  end

  def encryptor
    @_encryptor ||= ActiveProfileEncryptor.new(user, user_session, password)
  end
end

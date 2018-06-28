class SmsController < ApplicationController
  include ActionController::HttpAuthentication::Basic::ControllerMethods
  include SecureHeadersConcern

  # Twilio supports HTTP Basic Auth for request URL
  # https://www.twilio.com/docs/usage/security
  before_action :authenticate

  # Disable CSRF check
  skip_before_action :verify_authenticity_token, only: [:receive]

  def receive
    signature = request.headers[TwilioService::Sms::Request::SIGNATURE_HEADER]
    message = TwilioService::Sms::Request.new(request.url, params, signature)

    handle_result(message, SmsForm.new(message).submit)
  end

  private

  def handle_result(message, result)
    if result.success?
      process_success(message, result)
    else
      process_failure(result)
    end
  end

  def process_success(message, result)
    response = TwilioService::Sms::Response.new(message)
    SmsReplySenderJob.perform_later(response.reply)

    analytics.track_event(
      Analytics::TWILIO_SMS_INBOUND_MESSAGE_RECEIVED,
      result.to_h
    )

    head :accepted
  end

  def process_failure(result)
    analytics.track_event(
      Analytics::TWILIO_SMS_INBOUND_MESSAGE_VALIDATION_FAILED,
      result.to_h
    )

    head :forbidden
  end

  # `http_basic_authenticate_with name` had issues related to testing, so using
  # this method with a before action instead. (The former is a shortcut for the
  # following, which is called internally by Rails.)
  def authenticate
    authenticate_or_request_with_http_basic do |username, password|
      # This comparison uses & so that it doesn't short circuit and
      # uses `secure_compare` so that length information
      # isn't leaked.
      ActiveSupport::SecurityUtils.secure_compare(
        username, Figaro.env.twilio_http_basic_auth_username
      ) & ActiveSupport::SecurityUtils.secure_compare(
        password, Figaro.env.twilio_http_basic_auth_password
      )
    end
  end
end

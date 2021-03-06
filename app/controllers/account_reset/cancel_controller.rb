module AccountReset
  class CancelController < ApplicationController
    def cancel
      if AccountResetService.cancel_request(params[:token])
        handle_success
      else
        handle_failure
      end
      redirect_to root_url
    end

    private

    def handle_success
      analytics.track_event(Analytics::ACCOUNT_RESET, event: :cancel, token_valid: true)
      sign_out if current_user
      flash[:success] = t('devise.two_factor_authentication.account_reset.successful_cancel')
    end

    def handle_failure
      return if params[:token].blank?
      analytics.track_event(Analytics::ACCOUNT_RESET, event: :cancel, token_valid: false)
    end
  end
end

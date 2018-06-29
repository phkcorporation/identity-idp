module Users
  class PivCacAuthenticationSetupController < ApplicationController
    include UserAuthenticator
    include PivCacConcern

    before_action :authenticate_user!
    before_action :confirm_two_factor_authenticated,
                  if: :two_factor_enabled?,
                  except: :redirect_to_piv_cac_service
    before_action :authorize_piv_cac_setup, only: :new
    before_action :authorize_piv_cac_disable, only: :delete

    def new
      if params.key?(:token)
        process_piv_cac_setup
      else
        analytics.track_event(Analytics::USER_REGISTRATION_PIV_CAC_SETUP_VISIT)
        @presenter = PivCacAuthenticationSetupPresenter.new(user_piv_cac_form)
        render :new
      end
    end

    def delete
      analytics.track_event(Analytics::USER_REGISTRATION_PIV_CAC_DISABLED)
      configuration_manager.remove_configuration
      clear_piv_cac_information
      flash[:success] = t('notices.piv_cac_disabled')
      redirect_to account_url
    end

    def redirect_to_piv_cac_service
      create_piv_cac_nonce
      redirect_to PivCacService.piv_cac_service_link(piv_cac_nonce)
    end

    private

    def two_factor_enabled?
      method_manager.two_factor_enabled?
    end

    def process_piv_cac_setup
      result = user_piv_cac_form.submit
      analytics.track_event(Analytics::USER_REGISTRATION_PIV_CAC_ENABLED, result.to_h)
      if result.success?
        process_valid_submission
      else
        process_invalid_submission
      end
    end

    def user_piv_cac_form
      @user_piv_cac_form ||= UserPivCacSetupForm.new(
        user: current_user,
        token: params[:token],
        nonce: piv_cac_nonce
      )
    end

    def process_valid_submission
      flash[:success] = t('notices.piv_cac_configured')
      save_piv_cac_information(
        subject: user_piv_cac_form.x509_dn,
        presented: true
      )
      redirect_to next_step
    end

    def next_step
      return account_url if current_user.phone_enabled?
      account_recovery_setup_url
    end

    def process_invalid_submission
      @presenter = PivCacAuthenticationSetupErrorPresenter.new(user_piv_cac_form)
      clear_piv_cac_information
      render :error
    end

    def authorize_piv_cac_disable
      redirect_to account_url unless configuration_manager.configured?
    end

    def authorize_piv_cac_setup
      redirect_to account_url if configuration_manager.configured?
    end

    def method_manager
      @method_manager ||= TwoFactorAuthentication::MethodManager.new(current_user)
    end

    def configuration_manager
      @configuration_manager ||= method_manager.configuration_manager(:piv_cac)
    end
  end
end

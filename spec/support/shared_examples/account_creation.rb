shared_examples 'csrf error when asking for new personal key' do |sp|
  it 'redirects to sign in page', email: true do
    visit_idp_from_sp_with_loa1(sp)
    register_user
    allow_any_instance_of(Users::PersonalKeysController).
      to receive(:create).and_raise(ActionController::InvalidAuthenticityToken)
    click_on t('users.personal_key.get_another')

    expect(current_path).to eq new_user_session_path
    expect(page).to have_content t('errors.invalid_authenticity_token')
  end
end

shared_examples 'csrf error when acknowledging personal key' do |sp|
  it 'redirects to sign in page', email: true do
    visit_idp_from_sp_with_loa1(sp)
    register_user
    allow_any_instance_of(SignUp::PersonalKeysController).
      to receive(:update).and_raise(ActionController::InvalidAuthenticityToken)
    click_acknowledge_personal_key

    expect(current_path).to eq new_user_session_path
    expect(page).to have_content t('errors.invalid_authenticity_token')
  end
end

shared_examples 'creating an account with the site in Spanish' do |sp|
  it 'redirects to the SP', email: true do
    Capybara.current_session.driver.header('Accept-Language', 'es')
    visit_idp_from_sp_with_loa1(sp)
    register_user
    click_acknowledge_personal_key

    if sp == :oidc
      expect(page.response_headers['Content-Security-Policy']).
        to(include('form-action \'self\' http://localhost:7654'))
    end

    click_on t('forms.buttons.continue')
    expect(current_url).to eq @saml_authn_request if sp == :saml

    if sp == :oidc
      redirect_uri = URI(current_url)

      expect(redirect_uri.to_s).to start_with('http://localhost:7654/auth/result')
    end
  end
end

shared_examples 'creating an account using authenticator app for 2FA' do |sp|
  it 'redirects to the SP', email: true do
    visit_idp_from_sp_with_loa1(sp)
    register_user_with_authenticator_app
    click_acknowledge_personal_key

    if sp == :oidc
      expect(page.response_headers['Content-Security-Policy']).
        to(include('form-action \'self\' http://localhost:7654'))
    end

    click_on t('forms.buttons.continue')
    expect(current_url).to eq @saml_authn_request if sp == :saml

    if sp == :oidc
      redirect_uri = URI(current_url)

      expect(redirect_uri.to_s).to start_with('http://localhost:7654/auth/result')
    end
  end
end

shared_examples 'creating an account using PIV/CAC for 2FA' do |sp|
  it 'redirects to the SP', email: true do
    allow(FeatureManagement).to receive(:prefill_otp_codes?).and_return(true)
    visit_idp_from_sp_with_loa1(sp)
    register_user_with_piv_cac

    expect(page).to have_current_path(account_recovery_setup_path)
    expect(page).to have_content t('instructions.account_recovery_setup.piv_cac_next_step')

    select_2fa_option('sms')
    click_link t('devise.two_factor_authentication.two_factor_choice_cancel')

    expect(page).to have_current_path account_recovery_setup_path

    configure_backup_phone
    click_acknowledge_personal_key

    if sp == :oidc
      expect(page.response_headers['Content-Security-Policy']).
        to(include('form-action \'self\' http://localhost:7654'))
    end

    click_on t('forms.buttons.continue')
    expect(current_url).to eq @saml_authn_request if sp == :saml

    if sp == :oidc
      redirect_uri = URI(current_url)

      expect(redirect_uri.to_s).to start_with('http://localhost:7654/auth/result')
    end
  end
end

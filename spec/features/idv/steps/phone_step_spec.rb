require 'rails_helper'

feature 'idv profile step', :idv_job do
  include IdvStepHelper
  include IdvHelper

  context 'with valid information' do
    it 'allows the user to continue to the phone otp delivery selection step' do
      start_idv_from_sp
      complete_idv_steps_before_phone_step
      fill_out_phone_form_ok
      click_idv_continue

      expect(page).to have_content(t('idv.titles.otp_delivery_method'))
      expect(page).to have_current_path(idv_otp_delivery_method_path)
    end

    it 'redirects to the confirmation step when the phone matches the 2fa phone number' do
      user = user_with_2fa
      start_idv_from_sp
      complete_idv_steps_before_phone_step(user)
      fill_out_phone_form_ok(user.phone)
      click_idv_continue

      expect(page).to have_content(t('idv.titles.session.review'))
      expect(page).to have_current_path(idv_review_path)
    end
  end

  context 'after submitting valid information' do
    it 'is re-entrant before confirming OTP' do
      first_phone_number = '7032231234'
      second_phone_number = '7037897890'

      start_idv_from_sp
      complete_idv_steps_before_phone_step
      fill_out_phone_form_ok(first_phone_number)
      click_idv_continue
      choose_idv_otp_delivery_method_sms

      expect(page).to have_content('+1 703-223-1234')

      click_link t('forms.two_factor.try_again')

      expect(page).to have_content(t('idv.titles.session.phone'))
      expect(page).to have_current_path(idv_phone_path)

      fill_out_phone_form_ok(second_phone_number)
      click_idv_continue
      choose_idv_otp_delivery_method_sms

      expect(page).to have_content('+1 703-789-7890')
    end

    it 'is not re-entrant after confirming OTP' do
      user = user_with_2fa

      start_idv_from_sp
      complete_idv_steps_before_phone_step(user)
      fill_out_phone_form_ok
      click_idv_continue
      choose_idv_otp_delivery_method_sms
      enter_correct_otp_code_for_user(user)

      visit idv_phone_path
      expect(page).to have_content(t('idv.titles.session.review'))
      expect(page).to have_current_path(idv_review_path)

      fill_in 'Password', with: user_password
      click_continue

      # Currently this byasses the confirmation step since that is only
      # accessible once
      visit idv_phone_path
      expect(page).to_not have_current_path(idv_phone_path)
    end
  end

  it 'does not allow the user to advance without completing' do
    start_idv_from_sp
    complete_idv_steps_before_phone_step

    # Try to skip ahead to review step
    visit idv_review_path

    expect(page).to have_current_path(idv_phone_path)
  end

  xcontext 'cancelling IdV' do
    # The phone step does not have any cancel behavior :(
  end

  context "when the user's information cannot be verified" do
    it_behaves_like 'fail to verify idv info', :phone
  end

  context 'when the IdV background job fails' do
    it_behaves_like 'failed idv job', :phone
  end

  context 'after the max number of attempts' do
    it_behaves_like 'verification step max attempts', :phone
    it_behaves_like 'verification step max attempts', :phone, :oidc
    it_behaves_like 'verification step max attempts', :phone, :saml
  end
end

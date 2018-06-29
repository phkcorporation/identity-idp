require 'rails_helper'
require 'axe/rspec'

feature 'Accessibility on IDV pages', :js, idv_job: true do
  describe 'IDV pages' do
    include IdvHelper

    scenario 'home page' do
      sign_in_and_2fa_user

      visit idv_path

      expect(page).to be_accessible
    end

    scenario 'basic info' do
      sign_in_and_2fa_user

      visit idv_session_path

      expect(current_path).to eq idv_session_path
      expect(page).to be_accessible
    end

    scenario 'cancel idv' do
      sign_in_and_2fa_user

      visit idv_cancel_path

      expect(current_path).to eq idv_cancel_path
      expect(page).to be_accessible
    end

    scenario 'phone info' do
      sign_in_and_2fa_user
      visit idv_session_path
      fill_out_idv_form_ok
      click_idv_continue
      click_idv_continue

      expect(current_path).to eq idv_phone_path
      expect(page).to be_accessible
    end

    scenario 'review page' do
      sign_in_and_2fa_user
      visit idv_session_path
      fill_out_idv_form_ok
      click_idv_continue
      click_idv_continue
      click_button t('forms.buttons.continue')

      expect(current_path).to eq idv_review_path
      expect(page).to be_accessible
    end

    scenario 'personal key / confirmation page' do
      sign_in_and_2fa_user
      visit idv_session_path
      fill_out_idv_form_ok
      click_idv_continue
      click_idv_continue
      click_idv_continue
      fill_in :user_password, with: Features::SessionHelper::VALID_PASSWORD
      click_continue

      expect(current_path).to eq idv_confirmations_path
      expect(page).to be_accessible
    end
  end
end

require 'rails_helper'

describe 'users/delete/show.html.slim' do
  let(:user) { build_stubbed(:user, :signed_up) }
  let(:decorated_user) { user.decorate }

  before do
    allow(user).to receive(:decorate).and_return(decorated_user)
    allow(view).to receive(:current_user).and_return(user)
  end

  it 'displays headings' do
    render

    expect(rendered).to have_content(t('users.delete.heading', app: APP_NAME))
    expect(rendered).to have_content(t('users.delete.subheading', app: APP_NAME))
  end

  it 'displays bullets' do
    render

    expect(rendered).to have_content(t('users.delete.bullet_1', app: APP_NAME))
    expect(rendered).to have_content(t(user.decorate.delete_account_bullet_key, app: APP_NAME))
    expect(rendered).to have_content(t('users.delete.bullet_3', app: APP_NAME))
  end

  it 'displays bullets for loa1' do
    allow(decorated_user).to receive(:identity_verified?).and_return(false)
    expect(user.decorate.delete_account_bullet_key).to eq 'users.delete.bullet_2_loa1'
  end

  it 'displays bullets for loa1' do
    allow(decorated_user).to receive(:identity_verified?).and_return(true)
    expect(user.decorate.delete_account_bullet_key).to eq 'users.delete.bullet_2_loa3'
  end

  it 'contains link to delete account button' do
    render

    expect(rendered).to have_button t('users.delete.actions.delete', href: account_delete_path)
  end

  it 'contains link to cancel delete account link' do
    render

    expect(rendered).to have_link(t('users.delete.actions.cancel'), href: account_path)
  end
end

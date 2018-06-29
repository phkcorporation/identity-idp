module AccountRecoverable
  def piv_cac_enabled_but_not_phone_enabled?
    current_user.piv_cac_enabled? && !current_user.phone_enabled?
  end
end

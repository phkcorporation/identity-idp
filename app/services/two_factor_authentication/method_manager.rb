module TwoFactorAuthentication
  class MethodManager
    attr_reader :user

    METHODS = %i[sms voice totp piv_cac personal_key]

    def initialize(user)
      @user = user
    end

    def configuration_managers
      methods.map(&method(:configuration_manager))
    end

    def two_factor_enabled?(desired_methods = [])
      desired_methods = methods unless desired_methods&.any?
      (methods & desired_methods).any? do |method|
        configuration_manager(method).enabled?
      end
    end

    # TODO: allow multiple selection presenters for a single method if that method
    # supports multiple configurations. We really want one presenter per
    # configuration for configured/enabled setups and one presenter per method for
    # configurable methods.

    # Used when presenting the user with a list of options during login
    def enabled_selection_presenters(view)
      promote_preferred(
        configuration_managers.select(&:enabled?).map do |manager|
          manager.selection_presenter(view)
        end
      )
    end

    # Used when presenting the user with a list of options during setup
    def configurable_selection_presenters(view)
      promote_preferred(
        configuration_managers.select(&:configurable?).map do |manager|
          manager.selection_presenter(view)
        end
      )
    end

    def configuration_manager(method)
      puts "Getting method manager for #{method}"
      class_constant(method, 'ConfigurationManager')&.new(user)
    end

    private

    def promote_preferred(set)
      preferred = set.detect(&:preferred?)
      if preferred
        [preferred] + (set - [preferred])
      else
        set
      end
    end

    def class_constant(method, suffix)
      puts "Looking for class TwoFactorAuthentication::#{method.to_s.camelcase}#{suffix}"
      ('TwoFactorAuthentication::' + method.to_s.camelcase + suffix).safe_constantize
    end

    # TODO: filter based on configuration - allow some methods in some environments, etc.
    def methods
      METHODS
    end
  end
end

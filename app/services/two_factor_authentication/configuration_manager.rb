module TwoFactorAuthentication
  class ConfigurationManager
    attr_reader :user

    def initialize(current_user)
      @user = current_user
    end

    # The default is that we can configure the method if it isn't already
    # configurable. `#configured?` isn't defined here.
    def configurable?
      !configured? && available?
    end

    def enabled?
      raise NotImplementedError
    end

    def available?
      raise NotImplementedError
    end

    def configured?
      raise NotImplementedError
    end

    def preferred?
      false
    end

    def method
      @method ||= begin
        self.class.name.demodulize.sub(/ConfigurationManager$/, '').snakecase.to_sym
      end
    end

    def verify_presenter(view_context)
      class_constant('VerifyPresenter')&.new(self, view_context)
    end

    def verify_error_presenter(view_context, form)
      class_constant('VerifyErrorPresenter')&.new(self, view_context, form)
    end

    def setup_presenter(view_context)
      class_constant('SetupPresenter')&.new(self, view_context)
    end

    def setup_error_presenter(view_context, form)
      class_constant('SetupErrorPresenter')&.new(self, view_context, form)
    end

    def selection_presenter(view_context)
      class_constant('SelectionPresenter')&.new(self, view_context)
    end

    def verify_form(data)
      class_constant('VerifyForm')&.new(data.merge(
        user: user,
        configuration_manager: self
      ))
    end

    def setup_form(data)
      class_constant('SetupForm')&.new(data.merge(
        user: user,
        configuration_manager: self
      ))
    end

    private

    def class_constant(suffix)
      ('TwoFactorAuthentication::' + method.to_s.camelcase + suffix).safe_constantize
    end
  end
end

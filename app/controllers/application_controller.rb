# frozen_string_literal: true

class ApplicationController < ActionController::API
  include ActionController::Cookies
  include ActionController::RequestForgeryProtection

  protect_from_forgery(with: :exception) unless Rails.env.test?
  before_action :set_csrf_cookie

  rescue_from ActionController::InvalidAuthenticityToken do
    set_csrf_cookie
    render json: { error: 'InvalidAuthenticityToken' }, status: 403
  end

  def live
    render json: { time: Time.now.utc, app: 'app template' }
  end

  private

  def set_csrf_cookie
    cookies['CSRF-TOKEN'] = { value: form_authenticity_token, path: '/', domain: (ENV['DOMAIN'] || :all) }
  end
end

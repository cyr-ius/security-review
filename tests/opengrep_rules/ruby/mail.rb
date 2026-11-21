# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Password reset links built from the Host header.

class PasswordsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    token = user.generate_reset_token
    # ruleid: secreview.ruby.taint-host-header
    UserMailer.reset(user, "#{request.base_url}/reset/#{token}").deliver_later
    # ok: secreview.ruby.taint-host-header
    UserMailer.reset(user, edit_password_url(token: token, host: ENV.fetch("APP_HOST"))).deliver_later
  end
end

# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data encoded in a URL whose host is fixed.

class ProfilesController < ApplicationController
  def show
    # ok: secreview.ruby.taint-ssrf
    HTTParty.get("https://api.example.com/users/#{CGI.escape(params[:user])}")
  end
end

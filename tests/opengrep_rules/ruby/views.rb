# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data choosing the view or the template rendered.
class PagesController < ApplicationController
  def show
    # ruleid: secreview.ruby.taint-view-injection
    render params[:page]
  end

  def doc
    # ruleid: secreview.ruby.taint-view-injection
    render template: "docs/#{params[:section]}"
  end

  def help
    # ok: secreview.ruby.taint-view-injection
    render "help", locals: { topic: params[:topic] }
  end

  def data
    # ok: secreview.ruby.taint-view-injection
    render json: { topic: params[:topic] }
  end
end

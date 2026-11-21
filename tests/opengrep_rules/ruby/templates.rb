# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data compiled as a template; request data naming a class, a method or a function.
class PreviewsController < ApplicationController
  def create
    body = params[:body]
    # ruleid: secreview.ruby.taint-template-injection
    html = ERB.new(body).result(binding)
    # ruleid: secreview.ruby.taint-template-injection
    render inline: body
    # ok: secreview.ruby.taint-template-injection
    render "preview", locals: { body: body }
    # ok: secreview.ruby.taint-template-injection
    ERB.new(File.read("preview.erb")).result(binding)
  end
end

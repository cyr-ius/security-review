# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.

class UsersController < ApplicationController
  def search
    name = params[:name]
    # ruleid: secreview.ruby.taint-sql
    User.where("name = '#{name}'")
    # ruleid: secreview.ruby.taint-sql
    User.order(params[:sort])
    # ok: secreview.ruby.taint-sql
    User.where("name = ?", name)
    # ok: secreview.ruby.taint-sql
    User.where(name: name)
    # ok: secreview.ruby.taint-sql
    User.where("id = #{params[:id].to_i}")
  end

  def convert
    file = params[:file]
    # ruleid: secreview.ruby.taint-command
    system("convert #{file} out.png")
    # ok: secreview.ruby.taint-command
    system("convert", file, "out.png")
    # ok: secreview.ruby.taint-command
    system("convert #{Shellwords.escape(file)} out.png")
  end

  def clone
    branch = params[:branch]
    # ruleid: secreview.ruby.taint-argument-injection
    system("git", "clone", "--branch", branch, "https://example.com/repo")
    # ok: secreview.ruby.taint-argument-injection
    system("git", "clone", "--branch", "main", "https://example.com/repo")
    # ok: secreview.ruby.taint-argument-injection
    system("git", "clone", "--", branch, "https://example.com/repo")
  end

  def view
    name = params[:name]
    # ruleid: secreview.ruby.taint-view-injection
    render(template: name)
    # ok: secreview.ruby.taint-view-injection
    render(template: "pages/home")
  end

  def dispatch
    # ruleid: secreview.ruby.taint-code-eval
    current_user.public_send(params[:action_name])
    # ruleid: secreview.ruby.taint-code-eval
    klass = params[:type].constantize
    # ok: secreview.ruby.taint-code-eval
    current_user.public_send(:display_name)
  end

  def download
    # ruleid: secreview.ruby.taint-path-traversal
    send_file Rails.root.join("uploads", params[:name]).to_s
    # ruleid: secreview.ruby.taint-path-traversal
    File.read("/srv/reports/#{params[:report]}")
    # ok: secreview.ruby.taint-path-traversal
    File.read("/srv/reports/#{File.basename(params[:report])}")
  end

  def fetch
    url = params[:url]
    # ruleid: secreview.ruby.taint-ssrf
    Net::HTTP.get(URI(url))
    # ruleid: secreview.ruby.taint-ssrf
    HTTParty.get(url)
    # ok: secreview.ruby.taint-ssrf
    HTTParty.get("https://api.example.com/search", query: { q: url })
  end

  def show
    bio = params[:bio]
    # ruleid: secreview.ruby.taint-xss
    @bio = bio.html_safe
    # ruleid: secreview.ruby.taint-xss
    render html: "<p>#{bio}</p>".html_safe
    # ok: secreview.ruby.taint-xss
    @bio = h(bio).html_safe
  end

  def create
    @post = Post.create(params.require(:post).permit(:title))
    # ok: secreview.ruby.taint-open-redirect
    redirect_to @post
    # ok: secreview.ruby.taint-open-redirect
    redirect_to "/posts/#{params[:id]}"
    # ruleid: secreview.ruby.taint-open-redirect
    redirect_to params[:return_to]
  end

  def restore
    # ruleid: secreview.ruby.taint-deserialization
    state = Marshal.load(Base64.decode64(cookies[:state]))
    # ok: secreview.ruby.taint-deserialization
    state = JSON.parse(cookies[:state])
  end
end

# False positives found on a real project (Lobsters)
class ProfilesController < ApplicationController
  def avatar
    user = User.find_by(username: params[:username])
    # ok: secreview.ruby.taint-path-traversal
    File.open("/srv/cache/#{user.username}.png", "wb+")
  end

  def show
    # ok: secreview.ruby.taint-open-redirect
    redirect_to user_path(params[:username])
  end

  def similar
    value = params[:url]
    # ok: secreview.ruby.taint-sql
    Story.where(title: value).or(Story.where(normalized_url: value))
  end
end

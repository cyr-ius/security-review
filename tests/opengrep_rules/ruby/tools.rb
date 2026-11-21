# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data passed as an argument of a program (option injection).
class MirrorsController < ApplicationController
  def create
    url = params[:url]
    # ruleid: secreview.ruby.taint-argument-injection
    system("git", "clone", url, "/srv/mirror")
    # ruleid: secreview.ruby.taint-argument-injection
    Open3.capture2("curl", "-s", url)
    # ruleid: secreview.ruby.taint-argument-injection
    system("git ls-remote #{Shellwords.escape(url)}")
    # ok: secreview.ruby.taint-argument-injection
    system("git", "clone", "--", url, "/srv/mirror")
    # ok: secreview.ruby.taint-argument-injection
    system("git", "clone", "--branch=#{url}", "https://example.com/repo")
    # ok: secreview.ruby.taint-argument-injection
    system("/opt/tools/report", url)
  end
end

# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data appended to a string.

class BuildersController < ApplicationController
  def search
    sql = +"SELECT * FROM users WHERE name = '"
    sql << params[:name] << "'"
    # ruleid: secreview.ruby.taint-sql
    User.find_by_sql(sql)
  end
end

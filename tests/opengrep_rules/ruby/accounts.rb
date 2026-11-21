# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Mass assignment: the whole request, or an entity bound from it, saved as it is.
class AccountsController < ApplicationController
  def update
    user = User.find(params[:id])
    # ruleid: secreview.ruby.taint-mass-assignment
    user.update(params.require(:user).permit!)
    # ruleid: secreview.ruby.taint-mass-assignment
    Account.create(params.to_unsafe_h)
    # ok: secreview.ruby.taint-mass-assignment
    user.update(params.require(:user).permit(:name, :email))
    # ok: secreview.ruby.taint-mass-assignment
    user.update(name: params[:name])
  end
end

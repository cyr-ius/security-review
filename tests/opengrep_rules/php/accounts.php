<?php
// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Mass assignment: the whole request, or an entity bound from it, saved as it is.
class AccountController
{
    public function update(Request $request, User $user)
    {
        // ruleid: secreview.php.taint-mass-assignment
        $user->update($request->all());
        // ruleid: secreview.php.taint-mass-assignment
        $account = Account::create($request->all());
        // ruleid: secreview.php.taint-mass-assignment
        $user->forceFill($_POST)->save();
        // ok: secreview.php.taint-mass-assignment
        $user->update($request->validated());
        // ok: secreview.php.taint-mass-assignment
        $user->update($request->only(['name', 'email']));
        // ok: secreview.php.taint-mass-assignment
        $user->update(['name' => $request->input('name')]);
    }
}

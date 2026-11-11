# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import re

import flask
import ldap3
from flask import Flask, request
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login(conn: ldap3.Connection):
    name = request.form.get("name", "")
    # ruleid: secreview.python.taint-trust-boundary
    flask.session["userid"] = name
    # ok: secreview.python.taint-trust-boundary
    flask.session["theme"] = "dark"
    # ruleid: secreview.python.taint-ldap-injection
    conn.search("ou=people,dc=example,dc=org", f"(uid={name})")
    # ok: secreview.python.taint-ldap-injection
    conn.search("ou=people,dc=example,dc=org", f"(uid={escape_filter_chars(name)})")
    # ok: secreview.python.taint-ldap-injection
    match = re.search(name, "some text")
    return {"match": bool(match)}


@app.route("/signin", methods=["POST"])
def signin(db):
    user = db.execute("SELECT * FROM user WHERE username = ?", (request.form["username"],)).fetchone()
    # ok: secreview.python.taint-trust-boundary
    flask.session["user_id"] = user["id"]
    return {}


def set_csrf(request):
    # ok: secreview.python.taint-trust-boundary
    request.session["csrf"] = request.META["CSRF_COOKIE"]
    # ruleid: secreview.python.taint-trust-boundary
    request.session["agent"] = request.META["HTTP_USER_AGENT"]

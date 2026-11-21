# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Log injection, regular expressions and format strings built from request data.
import json
import logging
import re
import string

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.get("/login")
def login():
    user = request.args["user"]
    # ruleid: secreview.python.taint-log-injection
    logger.warning("failed login for %s", user)
    # ruleid: secreview.python.taint-log-injection
    logging.info(f"login {user}")
    # ok: secreview.python.taint-log-injection
    logger.warning("failed login for %s", user.replace("\n", " ").replace("\r", " "))
    # ok: secreview.python.taint-log-injection
    logger.warning("failed login for %r", repr(user))
    # ok: secreview.python.taint-log-injection
    logger.info("payload %s", json.dumps(user))
    return "ok"


@app.get("/search")
def search(items):
    term = request.args["q"]
    # ruleid: secreview.python.taint-regex-injection
    matcher = re.compile(term)
    # ok: secreview.python.taint-regex-injection
    escaped = re.compile(re.escape(term))
    # ok: secreview.python.taint-regex-injection
    fixed = re.search(r"^[a-z]+$", term)
    return [item for item in items if matcher.search(item) or escaped.search(item) or fixed]


@app.get("/greeting")
def greeting(user):
    template = request.args["template"]
    # ruleid: secreview.python.taint-format-string
    text = template.format(user=user)
    # ruleid: secreview.python.taint-format-string
    other = string.Formatter().format(template, user=user)
    # ok: secreview.python.taint-format-string
    safe = "Hello {name}".format(name=request.args["name"])
    # ok: secreview.python.taint-format-string
    substituted = string.Template(template).safe_substitute(name=user.name)
    return text + other + safe + substituted

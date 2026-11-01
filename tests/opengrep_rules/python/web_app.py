# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import hashlib
import os
import pickle
import shlex
import subprocess
import tarfile
from typing import Annotated

import httpx
import jwt
import requests
import yaml
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from flask import Flask, Markup, redirect, render_template_string, request, send_file
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
api = FastAPI()


@app.route("/users")
def users(cursor):
    name = request.args.get("name")
    # ruleid: secreview.python.taint-sql
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ok: secreview.python.taint-sql
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    # ok: secreview.python.taint-sql
    cursor.execute("SELECT * FROM users WHERE id = " + str(int(request.args["id"])))


@api.get("/items")
async def items(q: str, db, limit: Annotated[str, Query()] = "10"):
    # ruleid: secreview.python.taint-sql
    db.execute("SELECT * FROM items WHERE label = '" + q + "'")
    # ruleid: secreview.python.taint-sql
    db.execute(f"SELECT * FROM items LIMIT {limit}")


def not_a_route(q: str, db):
    # ok: secreview.python.taint-sql
    db.execute("SELECT * FROM items WHERE label = '" + q + "'")


@app.post("/ping")
def ping():
    host = request.form["host"]
    # ruleid: secreview.python.taint-command, secreview.python.subprocess-shell-dynamic
    subprocess.run("ping -c 1 " + host, shell=True)
    # ok: secreview.python.taint-command, secreview.python.subprocess-shell-dynamic
    subprocess.run(["ping", "-c", "1", host])
    # ok: secreview.python.taint-command
    os.system("ping -c 1 " + shlex.quote(host))
    # ok: secreview.python.subprocess-shell-dynamic
    subprocess.run("ls -l", shell=True)


@app.post("/calc")
def calc():
    expression = request.json["expression"]
    # ruleid: secreview.python.taint-code-eval
    return str(eval(expression))


@app.get("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: secreview.python.taint-ssrf
    requests.get(url, timeout=5)
    # ruleid: secreview.python.taint-ssrf
    httpx.post(url)
    # ok: secreview.python.taint-ssrf
    requests.get("https://api.example.com/status", params={"q": url}, timeout=5)


@app.get("/download")
def download():
    name = request.args["file"]
    # ruleid: secreview.python.taint-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.get("/download-safe")
def download_safe():
    name = secure_filename(request.args["file"])
    # ok: secreview.python.taint-path-traversal
    return send_file(os.path.join("/srv/files", name))


@api.get("/report")
def report(name: str):
    # ruleid: secreview.python.taint-path-traversal
    return FileResponse("/srv/reports/" + name)


@app.get("/login")
def login():
    target = request.args.get("next")
    # ruleid: secreview.python.taint-open-redirect
    return redirect(target)


@api.get("/go")
def go(next_url: str):
    # ruleid: secreview.python.taint-open-redirect
    return RedirectResponse(next_url)


@app.get("/home")
def home():
    # ok: secreview.python.taint-open-redirect
    return redirect("/dashboard")


@app.get("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: secreview.python.taint-template-injection
    return render_template_string("<p>Hello " + name + "</p>")


@app.get("/hello-safe")
def hello_safe():
    name = request.args.get("name", "")
    # ok: secreview.python.taint-template-injection
    return render_template_string("<p>Hello {{ name }}</p>", name=name)


@app.get("/banner")
def banner():
    text = request.args.get("text", "")
    # ruleid: secreview.python.taint-xss-markup
    return Markup("<b>" + text + "</b>")


@app.get("/banner-safe")
def banner_safe():
    text = escape(request.args.get("text", ""))
    # ok: secreview.python.taint-xss-markup
    return Markup("<b>" + text + "</b>")


@app.post("/restore")
def restore():
    # ruleid: secreview.python.taint-deserialization
    return pickle.loads(request.data)


def load_cache(path):
    with open(path, "rb") as handle:
        # ok: secreview.python.taint-deserialization
        return pickle.load(handle)


def tls():
    # ruleid: secreview.python.tls-verify-disabled
    requests.get("https://internal.example.com", verify=False)
    # ruleid: secreview.python.tls-verify-disabled
    client = httpx.Client(verify=False)
    # ok: secreview.python.tls-verify-disabled
    requests.get("https://internal.example.com", verify="/etc/ssl/ca.pem")
    return client


def parse(text):
    # ruleid: secreview.python.yaml-unsafe-load
    yaml.load(text)
    # ruleid: secreview.python.yaml-unsafe-load
    yaml.load(text, Loader=yaml.Loader)
    # ok: secreview.python.yaml-unsafe-load
    yaml.load(text, Loader=yaml.SafeLoader)
    # ok: secreview.python.yaml-unsafe-load
    return yaml.safe_load(text)


def claims(token, key):
    # ruleid: secreview.python.jwt-signature-not-verified
    jwt.decode(token, options={"verify_signature": False})
    # ok: secreview.python.jwt-signature-not-verified
    return jwt.decode(token, key, algorithms=["RS256"])


# ruleid: secreview.python.cors-wildcard-credentials
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
# ok: secreview.python.cors-wildcard-credentials
api.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)


def unpack(path, target):
    with tarfile.open(path) as archive:
        # ruleid: secreview.python.archive-extract-unfiltered
        archive.extractall(target)
    with tarfile.open(path) as archive:
        # ok: secreview.python.archive-extract-unfiltered
        archive.extractall(target, filter="data")


def digest(data):
    # ruleid: secreview.python.weak-hash-for-security
    signature = hashlib.md5(data).hexdigest()
    # ok: secreview.python.weak-hash-for-security
    etag = hashlib.md5(data, usedforsecurity=False).hexdigest()
    # ok: secreview.python.weak-hash-for-security
    return signature, etag, hashlib.sha256(data).hexdigest()


@app.get("/session")
def session_cookie(response):
    # ruleid: secreview.python.cookie-insecure
    response.set_cookie("session", "value", secure=False)
    # ok: secreview.python.cookie-insecure
    response.set_cookie("session", "value", secure=True, httponly=True, samesite="Lax")
    return response


if __name__ == "__main__":
    # ruleid: secreview.python.flask-debug-enabled
    app.run(debug=True)
    # ok: secreview.python.flask-debug-enabled
    app.run(debug=os.environ.get("DEBUG") == "1")

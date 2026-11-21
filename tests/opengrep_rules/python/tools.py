# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data passed as an argument of a program (option injection).
import os
import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.post("/mirror")
def mirror():
    url = request.form["url"]
    # ruleid: secreview.python.taint-argument-injection
    subprocess.run(["git", "clone", url, "/srv/mirror"], check=True)
    # ruleid: secreview.python.taint-argument-injection
    subprocess.check_output(["/usr/bin/curl", "-s", url])
    # ruleid: secreview.python.taint-argument-injection
    os.system("git ls-remote " + shlex.quote(url))
    # ruleid: secreview.python.taint-argument-injection
    os.system(f"git ls-remote {shlex.quote(url)}")
    # ok: secreview.python.taint-argument-injection
    subprocess.run(["git", "clone", "--", url, "/srv/mirror"], check=True)
    # ok: secreview.python.taint-argument-injection
    subprocess.run(["git", "clone", "--branch=" + url, "https://example.com/repo"], check=True)
    # ok: secreview.python.taint-argument-injection
    subprocess.run(["git", "clone", f"--branch={url}", "https://example.com/repo"], check=True)
    # ok: secreview.python.taint-argument-injection
    subprocess.run(["/opt/tools/report", url], check=True)
    # ok: secreview.python.taint-argument-injection
    os.system("git ls-remote -- " + shlex.quote(url))
    # ok: secreview.python.taint-argument-injection
    subprocess.run(["git", "clone", "https://example.com/repo"], check=True)
    return "ok"

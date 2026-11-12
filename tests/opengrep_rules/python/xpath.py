# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import elementpath
from flask import Flask, request
from lxml import etree

app = Flask(__name__)
root = etree.parse("users.xml").getroot()


@app.route("/user")
def user():
    name = request.args.get("name", "")
    # ruleid: secreview.python.taint-xpath-injection
    found = root.xpath(f"//user[@name='{name}']/id/text()")
    # ok: secreview.python.taint-xpath-injection
    safe = root.xpath("//user[@name=$name]/id/text()", name=name)
    # ruleid: secreview.python.taint-xpath-injection
    query = etree.XPath("//user[@name='" + name + "']")
    # ruleid: secreview.python.taint-xpath-injection
    nodes = elementpath.select(root, f"/users/user[@name='{name}']")
    # ok: secreview.python.taint-xpath-injection
    every = elementpath.select(root, "/users/user")
    return {"found": found, "safe": safe, "query": str(query), "nodes": len(nodes) + len(every)}


@app.route("/report", methods=["POST"])
def report():
    import codecs
    import pathlib
    import subprocess

    values = request.form.getlist("file")
    name = values[0] if values else ""
    # ruleid: secreview.python.taint-path-traversal
    handle = codecs.open(f"/srv/reports/{name}", "r", "utf-8")
    # ruleid: secreview.python.taint-path-traversal
    target = pathlib.Path("/srv/reports") / name
    # ok: secreview.python.taint-path-traversal
    fixed = pathlib.Path("/srv/reports") / "index.txt"
    query = request.query_string.decode()
    args = ["grep", "-r"]
    args.append(query)
    # ruleid: secreview.python.taint-command
    subprocess.run(" ".join(args), shell=True)
    return {"handle": handle.name, "target": str(target), "fixed": str(fixed)}


@app.route("/files", methods=["POST"])
def files():
    import configparser
    import os
    import pathlib

    name = request.form.get("name", "")
    conf = configparser.ConfigParser()
    conf.add_section("upload")
    conf.set("upload", "name", name)
    stored = conf.get("upload", "name")
    # ruleid: secreview.python.taint-path-traversal
    handle = open("/srv/files/" + stored)
    base = pathlib.Path("/srv/files")
    # ruleid: secreview.python.taint-path-traversal
    target = base / name
    # ok: secreview.python.taint-path-traversal
    index = base / "index.txt"
    # ruleid: secreview.python.taint-path-traversal
    exists = os.path.exists(f"/srv/files/{name}")
    defaults = configparser.ConfigParser()
    defaults.add_section("upload")
    defaults.set("upload", "dir", "/srv/files")
    # ok: secreview.python.taint-path-traversal
    folder = os.listdir(defaults.get("upload", "dir"))
    return {"handle": handle.name, "target": str(target), "index": str(index), "exists": exists, "folder": folder}


@app.route("/employee")
def employee():
    import io

    buffer = io.StringIO()
    buffer.write("//employee[@id='")
    buffer.write(request.args.get("id", ""))
    buffer.write("']")
    # ruleid: secreview.python.taint-xpath-injection
    found = root.xpath(buffer.getvalue())
    fixed = io.StringIO()
    fixed.write("//employee")
    # ok: secreview.python.taint-xpath-injection
    every = root.xpath(fixed.getvalue())
    return {"found": len(found), "every": len(every)}

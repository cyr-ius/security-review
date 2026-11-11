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

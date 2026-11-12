# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import html

from django.http import HttpResponse
from flask import Flask, jsonify, make_response, render_template, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    page = f"<p>Hello {name}</p>"
    # ruleid: secreview.python.taint-xss-response
    return page


@app.get("/greet")
def greet():
    name = request.args.get("name", "")
    # ok: secreview.python.taint-xss-response
    return render_template("greet.html", name=name)


@app.get("/escaped")
def escaped():
    name = request.args.get("name", "")
    # ok: secreview.python.taint-xss-response
    return f"<p>Hello {html.escape(name)}</p>"


@app.get("/api/user")
def user():
    # ok: secreview.python.taint-xss-response
    return jsonify(name=request.args.get("name"))


@app.post("/echo")
def echo():
    # ruleid: secreview.python.taint-xss-response
    return make_response("<p>" + request.form["message"] + "</p>")


def django_view(request):
    # ruleid: secreview.python.taint-xss-response
    return HttpResponse("<p>Hello " + request.GET.get("name", "") + "</p>")

# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data choosing the view or the template rendered.
from django.shortcuts import render
from django.template.loader import get_template
from flask import Flask, render_template, request

app = Flask(__name__)


@app.get("/page")
def page():
    name = request.args.get("page", "home")
    # ruleid: secreview.python.taint-view-injection
    return render_template(name + ".html")


@app.get("/help")
def help_page():
    # ok: secreview.python.taint-view-injection
    return render_template("help.html", topic=request.args.get("topic"))


def django_page(request):
    # ruleid: secreview.python.taint-view-injection
    template = get_template(request.GET["template"])
    # ruleid: secreview.python.taint-view-injection
    return render(request, "pages/%s.html" % request.GET["page"])


def django_help(request):
    # ok: secreview.python.taint-view-injection
    return render(request, "help.html", {"topic": request.GET.get("topic")})

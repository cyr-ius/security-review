# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import ssl

import requests
from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
users = MongoClient().shop.users


@app.route("/login", methods=["POST"])
def login():
    body = request.json
    # ruleid: secreview.python.taint-nosql-injection
    user = users.find_one({"name": body["name"], "password": body["password"]})
    # ruleid: secreview.python.taint-nosql-injection
    users.find({"$where": request.args.get("filter")})
    # ok: secreview.python.taint-nosql-injection
    users.find_one({"name": str(body["name"])})
    # ok: secreview.python.taint-nosql-injection
    users.find_one({"name": request.args.get("name")})
    return {"found": user is not None}


def contexts():
    # ruleid: secreview.python.tls-weak-version
    legacy = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context = ssl.create_default_context()
    # ruleid: secreview.python.tls-weak-version
    context.minimum_version = ssl.TLSVersion.TLSv1_1
    # ok: secreview.python.tls-weak-version
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # ok: secreview.python.tls-weak-version
    negotiated = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    return legacy, context, negotiated


def fetch(url, options):
    # ruleid: secreview.python.http-request-without-timeout
    status = requests.get(url)
    # ok: secreview.python.http-request-without-timeout
    data = requests.post(url, json={}, timeout=10)
    # ok: secreview.python.http-request-without-timeout
    other = requests.get(url, **options)
    return status, data, other

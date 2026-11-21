# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data made safe for its sink: encoded in a URL, quoted as an SQL identifier, cut to a file name.
from pathlib import Path
from urllib.parse import quote

import requests
from flask import Flask, request, send_file
from psycopg import sql

app = Flask(__name__)


@app.get("/profile")
def profile(cursor):
    user = request.args["user"]
    # ok: secreview.python.taint-ssrf
    requests.get(f"https://api.example.com/users/{quote(user)}", timeout=5)
    column = request.args["sort"]
    # ok: secreview.python.taint-sql
    cursor.execute(sql.SQL("SELECT * FROM users ORDER BY {}").format(sql.Identifier(column)))
    # ok: secreview.python.taint-path-traversal
    return send_file(Path("/srv/avatars") / Path(request.args["file"]).name)

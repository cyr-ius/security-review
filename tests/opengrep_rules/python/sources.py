# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data that reaches a view without going through the "request" object.
import os

import tornado.web
from django.views import View
from fastapi import Depends, FastAPI, Request
from flask import Flask
from pydantic import BaseModel

app = Flask(__name__)
api = FastAPI()


class Item(BaseModel):
    name: str


@app.route("/users/<name>")
def flask_segment(name, cursor):
    # ruleid: secreview.python.taint-sql
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")


@api.post("/items")
async def fastapi_model(item: Item, db=Depends(get_db)):
    # ruleid: secreview.python.taint-sql
    db.execute(f"SELECT * FROM items WHERE name = '{item.name}'")


@api.get("/items/{item_id}")
def fastapi_typed(item_id: int, request: Request, db=Depends(get_db), user: User = Depends(me)):
    # ok: secreview.python.taint-sql
    db.execute(f"SELECT * FROM items WHERE id = {item_id} AND owner = '{user.name}'")


def django_view(request, slug):
    # ruleid: secreview.python.taint-command
    os.system("build " + slug)


class ArticleView(View):
    def get(self, request, *args, **kwargs):
        # ruleid: secreview.python.taint-command
        os.system("grep " + self.request.GET["q"])
        # ruleid: secreview.python.taint-command
        os.system("show " + self.kwargs["slug"])


class Handler(tornado.web.RequestHandler):
    def post(self):
        # ruleid: secreview.python.taint-command
        os.system("echo " + self.request.body.decode())


class AuditMiddleware:
    def process_view(self, request, view_func, view_args, view_kwargs):
        # ok: secreview.python.taint-command
        os.system("logger " + view_func.__name__)


class Client:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def run(self, cursor):
        # ok: secreview.python.taint-sql
        cursor.execute("SELECT " + self.kwargs["column"])


@api.post("/tokens")
def create_token(body: TokenCreate, identity: UsersManager, db=Depends(get_db)):
    # ok: secreview.python.taint-sql
    db.execute(f"SELECT * FROM tokens WHERE owner = '{identity.client}'")
    # ruleid: secreview.python.taint-sql
    db.execute(f"SELECT * FROM tokens WHERE label = '{body.name}'")

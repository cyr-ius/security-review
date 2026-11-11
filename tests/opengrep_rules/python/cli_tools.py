# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Remote data outside a web framework is a source (sockets, serverless events, aiohttp, Tornado);
# local data (command line, standard input, environment) is not: no trust boundary is crossed.
import argparse
import os
import pickle
import socket
import sqlite3
import sys

import click
import tornado.web
from aiohttp import web


def main():
    # ok: secreview.python.taint-command
    os.system("convert " + sys.argv[1] + " out.png")
    # ok: secreview.python.taint-command
    os.system("convert input.jpg out.png")
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    args = parser.parse_args()
    # ok: secreview.python.taint-path-traversal
    with open("/srv/reports/" + args.report) as handle:
        print(handle.read())
    expression = input("expression: ")
    # ok: secreview.python.taint-code-eval
    print(eval(expression))


@click.command()
@click.option("--name")
def lookup(name):
    connection = sqlite3.connect("users.db")
    # ok: secreview.python.taint-sql
    connection.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ok: secreview.python.taint-sql
    connection.execute("SELECT * FROM users WHERE name = ?", (name,))


def serve(server: socket.socket):
    client, _ = server.accept()
    data = client.recv(4096)
    # ruleid: secreview.python.taint-deserialization
    return pickle.loads(data)


def handler(event, context):
    # ruleid: secreview.python.taint-command
    os.system("ping -c 1 " + event["host"])
    return {"statusCode": 200}


class SearchHandler(tornado.web.RequestHandler):
    def get(self):
        connection = sqlite3.connect("users.db")
        # ruleid: secreview.python.taint-sql
        connection.execute("SELECT * FROM users WHERE name = '" + self.get_argument("name") + "'")


async def download(request: web.Request):
    # ruleid: secreview.python.taint-path-traversal
    return web.FileResponse(open("/srv/files/" + request.match_info["name"], "rb").name)


def helper(path):
    # ok: secreview.python.taint-path-traversal
    with open(path) as handle:
        return handle.read()


class LocalFileAdapter:
    def send(self, request):
        # ok: secreview.python.taint-path-traversal
        return open(request.url, "rb")

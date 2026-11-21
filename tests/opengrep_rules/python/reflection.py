# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Request data naming a module, a class or a method reached by reflection.
import importlib

from flask import Flask, request

app = Flask(__name__)


class Actions:
    def export(self):
        return "exported"


@app.post("/action")
def action():
    name = request.form["action"]
    # ruleid: secreview.python.taint-unsafe-reflection
    getattr(Actions(), name)()
    # ruleid: secreview.python.taint-unsafe-reflection
    module = importlib.import_module(request.form["plugin"])
    # ruleid: secreview.python.taint-unsafe-reflection
    handler = getattr(module, name)
    handler()
    # ok: secreview.python.taint-unsafe-reflection
    label = getattr(Actions(), name, "unknown")
    # ok: secreview.python.taint-unsafe-reflection
    getattr(Actions(), "export")()
    return str(label)

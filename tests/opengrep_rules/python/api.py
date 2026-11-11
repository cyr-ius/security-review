# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
from fastapi import FastAPI

api = FastAPI()


@api.get("/hello")
def hello(name: str):
    # ok: secreview.python.taint-xss-response
    return f"Hello {name}"

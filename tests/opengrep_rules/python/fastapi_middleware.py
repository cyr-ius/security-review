# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
from fastapi import FastAPI
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()
# ruleid: secreview.python.fastapi-session-cookie-not-secure
app.add_middleware(SessionMiddleware, secret_key=load_secret())
# ok: secreview.python.fastapi-session-cookie-not-secure
app.add_middleware(SessionMiddleware, secret_key=load_secret(), https_only=True)

middleware = [
    # ruleid: secreview.python.fastapi-session-cookie-not-secure
    Middleware(SessionMiddleware, secret_key=load_secret(), same_site="lax"),
    # ok: secreview.python.fastapi-session-cookie-not-secure
    Middleware(SessionMiddleware, secret_key=load_secret(), https_only=True),
]

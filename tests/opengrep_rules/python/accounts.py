# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import hmac

from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from flask import Flask, request

from .models import ApiToken, User
from .rules import OIDC_CLIENT_SECRET, detection_signature, select

app = Flask(__name__)


@app.route("/users", methods=["POST"])
def create_user():
    data = request.get_json()
    # ruleid: secreview.python.taint-mass-assignment
    user = User(**data)
    # ok: secreview.python.taint-mass-assignment
    safe = User(name=data["name"], email=data["email"])
    for key, value in request.json.items():
        # ruleid: secreview.python.taint-mass-assignment
        setattr(user, key, value)
    # ok: secreview.python.taint-mass-assignment
    options = dict(**data)
    return {"id": user.id, "safe": safe.id, "options": options}


@csrf_exempt
# ruleid: secreview.python.django-csrf-exempt
def webhook(request):
    return JsonResponse({})


# ok: secreview.python.django-csrf-exempt
def profile(request):
    return JsonResponse({})


def verify(signature, body, key, name, token_hash, rule):
    expected_signature = hmac.new(key, body, "sha256").hexdigest()
    # ruleid: secreview.python.non-constant-time-compare
    if signature != expected_signature:
        return False
    # ok: secreview.python.non-constant-time-compare
    if signature is None or signature == "":
        return False
    # ruleid: secreview.python.non-constant-time-compare
    if signature == hmac.new(key, body, "sha256").hexdigest():
        return True
    # ok: secreview.python.non-constant-time-compare
    if name == OIDC_CLIENT_SECRET:
        return False
    # ok: secreview.python.non-constant-time-compare
    rows = select(ApiToken).where(ApiToken.token_hash == token_hash)
    # ok: secreview.python.non-constant-time-compare
    if detection_signature(rule) == signature:
        return rows
    # ok: secreview.python.non-constant-time-compare
    return hmac.compare_digest(signature, expected_signature)


def set_language(request):
    next_url = request.POST.get("next")
    if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    # ok: secreview.python.taint-open-redirect
    return HttpResponseRedirect(next_url)


def change_password(request):
    # ok: secreview.python.taint-open-redirect
    return HttpResponseRedirect(reverse("admin:user_change", args=(request.POST.get("id"),)))


def leave(request):
    # ruleid: secreview.python.taint-open-redirect
    return HttpResponseRedirect(request.GET.get("next"))


def add_another(request):
    # ok: secreview.python.taint-open-redirect
    return HttpResponseRedirect(request.path + "?saved=1")

# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
# Password reset links built from the Host header, and mail headers built from request data.
import os
import smtplib
from email.message import EmailMessage
from email.mime.text import MIMEText

from django.core.mail import send_mail
from flask import Flask, request

app = Flask(__name__)
BASE_URL = os.environ["BASE_URL"]


@app.post("/password-reset")
def password_reset(user, token):
    link = f"{request.host_url}reset?token={token}"
    # ruleid: secreview.python.taint-host-header
    send_mail("Reset your password", f"Open {link}", "noreply@example.com", [user.email])
    # ok: secreview.python.taint-host-header
    send_mail("Reset your password", f"Open {BASE_URL}/reset?token={token}", "noreply@example.com", [user.email])


def django_reset(request, user, token):
    host = request.META["HTTP_HOST"]
    # ruleid: secreview.python.taint-host-header
    send_mail("Reset", f"https://{host}/reset/{token}", "noreply@example.com", [user.email])
    # ok: secreview.python.taint-host-header
    send_mail("Reset", request.build_absolute_uri(f"/reset/{token}"), "noreply@example.com", [user.email])


@app.post("/contact")
def contact():
    message = MIMEText(request.form["body"])
    # ruleid: secreview.python.taint-mail-header
    message["Subject"] = request.form["subject"]
    # ok: secreview.python.taint-mail-header
    message["Reply-To"] = request.form["email"].replace("\n", "").replace("\r", "")
    modern = EmailMessage()
    # ok: secreview.python.taint-mail-header
    modern["Subject"] = request.form["subject"]
    smtplib.SMTP("localhost").send_message(message)
    return "sent"

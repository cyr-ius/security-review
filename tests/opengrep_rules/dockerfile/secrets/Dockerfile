# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
FROM python:3.14-slim
# ruleid: secreview.dockerfile.secret-in-env
ENV DB_PASSWORD=hunter2hunter2
# ruleid: secreview.dockerfile.secret-in-env
ARG NPM_TOKEN=npm_0123456789abcdef
# ok: secreview.dockerfile.secret-in-env
ARG NPM_TOKEN
# ok: secreview.dockerfile.secret-in-env
ENV PASSWORD_FILE=/run/secrets/db_password
# ok: secreview.dockerfile.secret-in-env
ENV LOG_LEVEL=info
USER app
CMD ["app"]

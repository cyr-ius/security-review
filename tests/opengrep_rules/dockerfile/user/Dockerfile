# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
FROM python:3.14-slim
# ok: secreview.dockerfile.user-root
USER root
RUN apt-get update && apt-get install -y curl
USER app
# ok: secreview.dockerfile.runs-as-root
ENTRYPOINT ["app"]

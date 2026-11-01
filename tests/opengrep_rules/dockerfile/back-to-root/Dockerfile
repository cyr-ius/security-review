# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
FROM python:3.14-slim
USER app
RUN pip install --user app
# ruleid: secreview.dockerfile.user-root
USER root
CMD ["app"]

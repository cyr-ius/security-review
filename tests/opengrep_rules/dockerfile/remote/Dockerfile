# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
FROM debian:12-slim
# ruleid: secreview.dockerfile.add-remote-url
ADD https://example.com/tool.tar.gz /opt/
# ok: secreview.dockerfile.add-remote-url
ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://example.com/tool.tar.gz /opt/
# ok: secreview.dockerfile.add-remote-url
ADD tool.tar.gz /opt/
# ruleid: secreview.dockerfile.curl-pipe-shell
RUN curl -fsSL https://example.com/install.sh | sh
# ok: secreview.dockerfile.curl-pipe-shell
RUN curl -fsSLo install.sh https://example.com/install.sh && sha256sum -c install.sh.sha256 && sh install.sh
USER app
CMD ["tool"]

# Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
import random
import secrets
import string


def reset_token():
    # ruleid: secreview.python.insecure-random-for-secret
    token = "".join(random.choice(string.ascii_letters) for _ in range(32))
    # ruleid: secreview.python.insecure-random-for-secret
    session_key = random.getrandbits(128)
    # ok: secreview.python.insecure-random-for-secret
    api_key = secrets.token_urlsafe(32)
    # ok: secreview.python.insecure-random-for-secret
    delay = random.uniform(0.5, 1.5)
    return token, session_key, api_key, delay


def parse(document: bytes):
    from lxml import etree

    # ruleid: secreview.python.xxe-entities-enabled
    parser = etree.XMLParser(resolve_entities=True)
    # ok: secreview.python.xxe-entities-enabled
    safe = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(document, parser), safe


def sax(handler):
    import xml.sax
    from xml.sax.handler import feature_external_ges, feature_namespaces

    reader = xml.sax.make_parser()
    # ruleid: secreview.python.xxe-entities-enabled
    reader.setFeature(feature_external_ges, True)
    # ok: secreview.python.xxe-entities-enabled
    reader.setFeature(feature_namespaces, True)
    return reader

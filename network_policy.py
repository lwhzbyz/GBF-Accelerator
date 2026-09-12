"""Shared host and HTTP cache rules for the proxy, certificates and PAC."""
import re
import urllib.parse

CDN_HOSTS = frozenset(
    [f"prd-game-a{suffix}-granbluefantasy.akamaized.net" for suffix in ("", "1", "2", "3", "4", "5")]
    + ["gbf.akamaized.net", "granbluefantasy.akamaized.net"]
)
GAME_HOSTS = frozenset({"game.granbluefantasy.jp", "gbf.game.mbga.jp"})
MITM_HOSTS = CDN_HOSTS | GAME_HOSTS
STATIC_PREFIXES = ("/assets/", "/assets_en/", "/sound/", "/img/", "/css/", "/js/", "/font/")
STATIC_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".mp3", ".wav", ".ogg", ".m4a", ".mp4", ".webm",
    ".js", ".css", ".woff", ".woff2", ".ttf", ".otf", ".wasm",
})
HOP_HEADERS = frozenset({
    "connection", "proxy-connection", "keep-alive", "te", "trailer",
    "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization",
})
SENSITIVE_QUERY_KEYS = frozenset({"token", "access_token", "authorization", "auth", "session", "sessionid", "signature"})


def normalize_host(host):
    return host.lower().rstrip(".")


def should_mitm(host, port=443):
    return port == 443 and normalize_host(host) in MITM_HOSTS


def cache_control(value):
    directives = {}
    for part in value.lower().split(","):
        name, _, argument = part.strip().partition("=")
        if name:
            directives[name] = argument.strip('" ')
    return directives


def versioned_path(path):
    return bool(re.match(r"^/assets(?:_en)?/\d{8,}/", path))


def cacheable_request(method, url, headers):
    fields = {k.lower(): v for k, v in headers.items()}
    parts = urllib.parse.urlsplit(url)
    try:
        host = normalize_host(parts.hostname or "")
        if parts.scheme != "https" or (parts.port or 443) != 443 or host not in MITM_HOSTS:
            return False
    except ValueError:
        return False
    if method.upper() not in ("GET", "HEAD") or parts.username or parts.password or parts.fragment:
        return False
    if any(k in fields for k in ("cookie", "authorization", "range", "if-range",
                                 "if-match", "if-unmodified-since", "if-modified-since")):
        return False
    if "no-store" in cache_control(fields.get("cache-control", "")):
        return False
    if any(k.lower() in SENSITIVE_QUERY_KEYS for k, _ in urllib.parse.parse_qsl(parts.query)):
        return False
    path = urllib.parse.unquote(parts.path)
    if "\\" in path or any(segment in (".", "..") for segment in path.split("/")):
        return False
    extension = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return path.startswith(STATIC_PREFIXES) and extension in STATIC_EXTENSIONS


def end_to_end_headers(headers):
    fields = {k.lower(): v for k, v in headers.items()}
    connection_tokens = {v.strip().lower() for v in fields.get("connection", "").split(",")}
    return {k: v for k, v in fields.items() if k not in HOP_HEADERS and k not in connection_tokens}


def wants_refresh(headers):
    fields = {k.lower(): v for k, v in headers.items()}
    directives = cache_control(fields.get("cache-control", ""))
    return ("no-cache" in directives or "no-store" in directives
            or directives.get("max-age") == "0" or fields.get("pragma", "").lower() == "no-cache")


def encoding_quality(value, encoding):
    if value is None:
        return 1.0
    weights = {}
    for item in value.lower().split(","):
        pieces = [part.strip() for part in item.split(";")]
        if not pieces[0]:
            continue
        weight = 1.0
        for param in pieces[1:]:
            if param.startswith("q="):
                try:
                    weight = float(param[2:])
                    if not 0 <= weight <= 1:
                        weight = 0.0
                except ValueError:
                    weight = 0.0
        weights[pieces[0]] = weight
    if encoding in weights:
        return weights[encoding]
    if encoding == "identity":
        return 0.0 if weights.get("*") == 0 else 1.0
    return weights.get("*", 0.0)

"""Loopback GBF cache proxy; direct, HTTP(S) proxy and SOCKS5 uplinks."""
import asyncio
import base64
from dataclasses import dataclass
from http import HTTPStatus
from http.cookiejar import CookieJar
import ipaddress
import ssl
import sys
import threading
import urllib.parse

import httpx
from cache_manager import cache_manager, representation
from cert_manager import get_server_ssl_context
from config_manager import config_manager, normalize_upstream
from network_policy import cacheable_request, end_to_end_headers, normalize_host, should_mitm

LISTEN_HOST = config_manager.config.get("listen_host", "127.0.0.1")
LISTEN_PORT = config_manager.get_listen_port()
UPSTREAM_PROXY = config_manager.get_effective_upstream_proxy()
MAX_HEADERS_BYTES = 65536
MAX_HEADER_COUNT = 128
MAX_BODY_BYTES = 32 * 1024 * 1024
http_client = None
proxy_server_instance = proxy_loop = proxy_thread = proxy_stop_event = None
proxy_ready_event = threading.Event()
PROXY_STATS = {"hits": 0, "ram_hits": 0, "downloads": 0, "apis": 0,
               "is_running": False, "last_error": ""}


class NoCookies(CookieJar):
    """Reuse TCP connections, never browser identity."""
    def extract_cookies(self, response, request):
        pass

    def add_cookie_header(self, request):
        pass

    def set_cookie(self, cookie, *args, **kwargs):
        pass


class HTTPError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


@dataclass
class Response:
    status_code: int
    headers: httpx.Headers
    content: bytes
    reason_phrase: str = ""


def format_log(level, color, message):
    if sys.stdout is not None:
        try:
            print(f"[{level}] {message}", flush=True)
        except (OSError, UnicodeError):
            pass


async def init_http_client(*, transport=None, verify=None):
    global http_client
    upstream = normalize_upstream(UPSTREAM_PROXY)
    verify = config_manager.config.get("verify_upstream_tls", True) if verify is None else verify
    http_client = httpx.AsyncClient(
        proxy=None if upstream == "direct" else upstream, verify=verify,
        trust_env=False, cookies=NoCookies(), transport=transport,
        timeout=httpx.Timeout(20.0, connect=8.0), follow_redirects=False,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=50),
    )


async def close_http_client():
    global http_client
    if http_client is not None:
        client, http_client = http_client, None
        try:
            await asyncio.wait_for(client.aclose(), 3)
        except (TimeoutError, OSError):
            pass


async def _line(reader, timeout=15):
    try:
        return await asyncio.wait_for(reader.readline(), timeout)
    except (ValueError, asyncio.LimitOverrunError):
        raise HTTPError(431, "HTTP line too long") from None


async def _exact(reader, count, timeout=30):
    try:
        return await asyncio.wait_for(reader.readexactly(count), timeout)
    except asyncio.IncompleteReadError:
        raise HTTPError(400, "Incomplete HTTP body") from None


async def read_http_request(reader, writer=None):
    try:
        first = await _line(reader, 30)
    except TimeoutError:
        return None  # An idle keep-alive connection has no failed request to answer.
    if not first:
        return None
    try:
        method, target, version = first.decode("ascii").strip().split()
    except (UnicodeError, ValueError):
        raise HTTPError(400, "Invalid request line") from None
    if version not in ("HTTP/1.0", "HTTP/1.1") or not method.isalpha():
        raise HTTPError(400, "Unsupported HTTP request")
    headers, total, count = {}, len(first), 0
    while True:
        line = await _line(reader)
        if line == b"\r\n":
            break
        total, count = total + len(line), count + 1
        if total > MAX_HEADERS_BYTES or count > MAX_HEADER_COUNT:
            raise HTTPError(431, "Too many HTTP headers")
        if not line or not line.endswith(b"\r\n") or line[:1] in (b" ", b"\t") or b":" not in line:
            raise HTTPError(400, "Invalid HTTP header")
        key, value = line[:-2].decode("iso-8859-1").split(":", 1)
        if not key or any(not (c.isascii() and (c.isalnum() or c in "!#$%&'*+-.^_`|~")) for c in key):
            raise HTTPError(400, "Invalid header name")
        key, value = key.lower(), value.strip()
        if any(c in value for c in "\r\n\x00"):
            raise HTTPError(400, "Invalid header value")
        if key in headers:
            if key in ("host", "content-length", "transfer-encoding", "authorization"):
                raise HTTPError(400, "Ambiguous HTTP framing or identity")
            headers[key] += ("; " if key == "cookie" else ", ") + value
        else:
            headers[key] = value
    transfer = headers.get("transfer-encoding", "").lower()
    if transfer and (transfer != "chunked" or "content-length" in headers):
        raise HTTPError(400, "Unsupported or ambiguous transfer encoding")
    try:
        length = int(headers.get("content-length", "0"))
    except ValueError:
        raise HTTPError(400, "Invalid Content-Length") from None
    if length < 0 or length > MAX_BODY_BYTES:
        raise HTTPError(413, "Request body exceeds limit")
    if method.upper() == "CONNECT" and (length or transfer):
        raise HTTPError(400, "CONNECT cannot carry a request body")
    expect = headers.pop("expect", "").lower()
    if expect:
        if expect != "100-continue" or writer is None:
            raise HTTPError(417, "Unsupported expectation")
        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        await writer.drain()
    if not transfer:
        body = await _exact(reader, length) if length else b""
    else:
        chunks, size = [], 0
        while True:
            line = await _line(reader)
            try:
                raw_size = line.strip().split(b";", 1)[0]
                if not raw_size or any(c not in b"0123456789abcdefABCDEF" for c in raw_size):
                    raise ValueError()
                chunk_size = int(raw_size, 16)
            except ValueError:
                raise HTTPError(400, "Invalid chunk size") from None
            if not chunk_size:
                while True:
                    trailer = await _line(reader)
                    if trailer == b"\r\n":
                        break
                    total, count = total + len(trailer), count + 1
                    if total > MAX_HEADERS_BYTES or count > MAX_HEADER_COUNT:
                        raise HTTPError(431, "Trailers exceed limit")
                    if not trailer or b":" not in trailer or not trailer.endswith(b"\r\n"):
                        raise HTTPError(400, "Invalid trailer")
                    name = trailer.split(b":", 1)[0].lower()
                    if name in (b"content-length", b"transfer-encoding", b"host", b"authorization", b"cookie"):
                        raise HTTPError(400, "Forbidden trailer")
                break
            size += chunk_size
            if size > MAX_BODY_BYTES:
                raise HTTPError(413, "Request body exceeds limit")
            chunks.append(await _exact(reader, chunk_size))
            if await _exact(reader, 2) != b"\r\n":
                raise HTTPError(400, "Invalid chunk terminator")
        body = b"".join(chunks)
    return method.upper(), target, version, headers, body


async def send_response(writer, status, headers, body, *, method="GET", close=False):
    incoming = httpx.Headers(headers)
    fields = end_to_end_headers(incoming)
    cookies = incoming.get_list("set-cookie")
    fields.pop("set-cookie", None)
    if status in (204, 304) or status < 200:
        fields.pop("content-length", None)
        body = b""
    elif method != "HEAD" or "content-length" not in fields:
        fields["content-length"] = str(len(body))
    fields["connection"] = "close" if close else "keep-alive"
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = "Response"
    lines = [f"HTTP/1.1 {status} {reason}", *[f"{k}: {v}" for k, v in fields.items()]]
    lines.extend(f"Set-Cookie: {value}" for value in cookies)
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1"))
    if method != "HEAD":
        writer.write(body)
    await writer.drain()


async def fetch_upstream(method, url, headers, body):
    fields = end_to_end_headers(headers)
    for name in ("host", "content-length"):
        fields.pop(name, None)
    request = http_client.build_request(method, url, headers=fields, content=body)
    upstream = await http_client.send(request, stream=True)
    try:
        maximum = max(1, min(512, int(config_manager.config.get("max_response_mb", 64)))) * 1024 * 1024
        chunks, size = [], 0
        async for chunk in upstream.aiter_raw():
            size += len(chunk)
            if size > maximum:
                raise HTTPError(502, "Upstream response exceeds configured limit")
            chunks.append(chunk)
        return Response(upstream.status_code, upstream.headers, b"".join(chunks), upstream.reason_phrase)
    finally:
        await upstream.aclose()


def _etag_matches(condition, etag):
    return bool(condition and (condition.strip() == "*" or (etag and any(
        value.strip().removeprefix("W/") == etag.removeprefix("W/") for value in condition.split(",")))))


def preserve_cookies(fields, original):
    result = httpx.Headers(fields)
    cookies = original.get_list("set-cookie")
    result.pop("set-cookie", None)
    return httpx.Headers([*result.multi_items(), *[("set-cookie", cookie) for cookie in cookies]])


async def handle_http(req, writer, target_host=None):
    method, target, version, headers, body = req
    close = version == "HTTP/1.0" or "close" in headers.get("connection", "").lower()
    if target_host:
        if not target.startswith("/") or target.startswith("//") or "#" in target:
            raise HTTPError(400, "MITM requests must use origin-form targets")
        host_header = headers.get("host", target_host).lower()
        if host_header not in (target_host, target_host + ":443"):
            raise HTTPError(400, "Host differs from CONNECT target")
        url = f"https://{target_host}{target}"
    else:
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise HTTPError(400, "Expected absolute HTTP URL")
        url = target
    # HTTPX normalizes the exact URL used for the upstream request and cache key.
    url = str(httpx.URL(url))
    eligible = cacheable_request(method, url, headers)
    if eligible:
        cached = await asyncio.to_thread(cache_manager.get_cache, url, headers)
        if cached:
            chosen = representation(*cached, headers.get("accept-encoding"))
            if chosen:
                fields, data = chosen
                status = 304 if _etag_matches(headers.get("if-none-match"), fields.get("etag")) else 200
                await send_response(writer, status, fields, data, method=method, close=close)
                PROXY_STATS["hits"] += 1
                PROXY_STATS["ram_hits"] += fields.get("x-cache-source") == "RAM"
                format_log("CACHE", "", f"{method} {urllib.parse.urlsplit(url).hostname}{urllib.parse.urlsplit(url).path}")
                return not close
    candidate = None
    upstream_headers = dict(headers)
    if eligible and method == "GET" and not any(k in headers for k in ("if-none-match", "if-modified-since")):
        candidate = await asyncio.to_thread(cache_manager.get_cache, url, headers, True)
        if candidate and representation(*candidate, headers.get("accept-encoding")):
            if candidate[0].get("etag"):
                upstream_headers["if-none-match"] = candidate[0]["etag"]
            elif candidate[0].get("last-modified"):
                upstream_headers["if-modified-since"] = candidate[0]["last-modified"]
            else:
                candidate = None
        else:
            candidate = None
    response = await fetch_upstream(method, url, upstream_headers, body)
    if response.status_code == 304 and candidate is not None:
        fields, data = candidate
        fields = {k: v for k, v in fields.items() if k not in ("age", "x-proxy-cache", "x-cache-source", "content-length")}
        # The origin's validation replaces the legacy placeholder policy.
        if fields.get("cache-control") == "no-cache" and candidate[0].get("x-cache-source") == "LEGACY":
            fields.pop("cache-control", None)
        fields.update(end_to_end_headers(response.headers))
        merged = preserve_cookies(fields, response.headers)
        response = Response(200, merged, data)
    if eligible and method == "GET" and response.status_code == 200:
        saved = await asyncio.to_thread(cache_manager.save_cache, url, dict(response.headers), response.content, headers)
        if saved:
            PROXY_STATS["downloads"] += 1
        else:
            await asyncio.to_thread(cache_manager.invalidate, url)
    elif eligible and method == "GET" and response.status_code != 304:
        await asyncio.to_thread(cache_manager.invalidate, url)
    fields, data = response.headers, response.content
    if eligible and response.status_code == 200 and method != "HEAD":
        chosen = representation(dict(fields), data, headers.get("accept-encoding"))
        if chosen is None:
            await send_response(writer, 406, {}, b"", method=method, close=close)
            return not close
        fields, data = chosen
        fields = preserve_cookies(fields, response.headers)
    close = close or "close" in response.headers.get("connection", "").lower()
    await send_response(writer, response.status_code, fields, data, method=method, close=close)
    PROXY_STATS["apis"] += not eligible
    parts = urllib.parse.urlsplit(url)
    format_log("FETCH" if eligible else "BYPASS", "", f"{response.status_code} {method} {parts.hostname}{parts.path}")
    return not close


async def open_target_tunnel(host, port, *, proxy_tls_context=None):
    """Return a raw target stream through the configured uplink."""
    upstream = normalize_upstream(UPSTREAM_PROXY)
    if upstream == "direct":
        return await asyncio.wait_for(asyncio.open_connection(host, port), 8)
    parsed = urllib.parse.urlsplit(upstream)
    proxy_port = parsed.port or {"http": 80, "https": 443, "socks5": 1080, "socks5h": 1080}[parsed.scheme]
    tls = (proxy_tls_context or ssl.create_default_context()) if parsed.scheme == "https" else None
    reader, writer = await asyncio.wait_for(asyncio.open_connection(parsed.hostname, proxy_port, ssl=tls,
                                          server_hostname=parsed.hostname if tls else None), 8)
    try:
        if parsed.scheme in ("socks5", "socks5h"):
            credentials = parsed.username is not None
            writer.write(b"\x05\x01\x02" if credentials else b"\x05\x01\x00")
            await writer.drain()
            selected = await _exact(reader, 2, 8)
            if selected != (b"\x05\x02" if credentials else b"\x05\x00"):
                raise HTTPError(502, "SOCKS authentication method rejected")
            if credentials:
                user = urllib.parse.unquote(parsed.username).encode()
                password = urllib.parse.unquote(parsed.password or "").encode()
                if len(user) > 255 or len(password) > 255:
                    raise HTTPError(502, "SOCKS credentials exceed protocol limits")
                writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
                await writer.drain()
                if await _exact(reader, 2, 8) != b"\x01\x00":
                    raise HTTPError(502, "SOCKS authentication failed")
            try:
                address = ipaddress.ip_address(host)
                destination = (b"\x01" if address.version == 4 else b"\x04") + address.packed
            except ValueError:
                domain = host.encode("idna")
                if len(domain) > 255:
                    raise HTTPError(400, "SOCKS target hostname too long")
                destination = b"\x03" + bytes([len(domain)]) + domain
            writer.write(b"\x05\x01\x00" + destination + port.to_bytes(2, "big"))
            await writer.drain()
            result = await _exact(reader, 4, 8)
            if result[:3] != b"\x05\x00\x00":
                raise HTTPError(502, "SOCKS connection rejected")
            length = {1: 4, 4: 16}.get(result[3])
            if result[3] == 3:
                length = (await _exact(reader, 1, 8))[0]
            if length is None:
                raise HTTPError(502, "Invalid SOCKS reply")
            await _exact(reader, length + 2, 8)
        else:
            authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
            if parsed.username is not None:
                raw = urllib.parse.unquote(parsed.username) + ":" + urllib.parse.unquote(parsed.password or "")
                lines.append("Proxy-Authorization: Basic " + base64.b64encode(raw.encode()).decode())
            writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            await writer.drain()
            first = await _line(reader, 8)
            parts = first.split()
            if len(parts) < 2 or parts[1] != b"200":
                raise HTTPError(502, "HTTP upstream CONNECT rejected")
            total = len(first)
            while True:
                line = await _line(reader, 8)
                total += len(line)
                if total > MAX_HEADERS_BYTES or not line:
                    raise HTTPError(502, "Invalid upstream CONNECT headers")
                if line == b"\r\n":
                    break
        return reader, writer
    except BaseException:
        writer.close()
        raise


async def pipe_stream(reader, writer):
    while True:
        data = await reader.read(65536)
        if not data:
            return
        writer.write(data)
        await writer.drain()


async def close_writer(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (TimeoutError, OSError, RuntimeError):
        writer.transport.abort()


async def relay(client_reader, client_writer, upstream_reader, upstream_writer):
    tasks = [asyncio.create_task(pipe_stream(client_reader, upstream_writer)),
             asyncio.create_task(pipe_stream(upstream_reader, client_writer))]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(close_writer(upstream_writer), close_writer(client_writer), return_exceptions=True)


async def handle_passthrough(reader, writer, host, port):
    upstream_reader, upstream_writer = await open_target_tunnel(host, port)
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    await relay(reader, writer, upstream_reader, upstream_writer)


async def handle_mitm_session(reader, writer, host, ssl_context):
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    await asyncio.wait_for(writer.start_tls(ssl_context, ssl_shutdown_timeout=2), 10)
    while True:
        request = await read_http_request(reader, writer)
        if request is None:
            return
        if not await handle_http(request, writer, host):
            return


async def client_handler(reader, writer, ssl_context):
    try:
        request = await read_http_request(reader, writer)
        if request is None:
            return
        method, target, _, _, _ = request
        if method == "CONNECT":
            try:
                parsed = urllib.parse.urlsplit("//" + target)
                host, port = normalize_host(parsed.hostname or ""), parsed.port or 443
                if not host or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or not 1 <= port <= 65535:
                    raise ValueError()
            except ValueError:
                raise HTTPError(400, "Invalid CONNECT authority") from None
            if should_mitm(host, port):
                await handle_mitm_session(reader, writer, host, ssl_context)
            else:
                await handle_passthrough(reader, writer, host, port)
        elif target == "/proxy.pac" and method in ("GET", "HEAD"):
            from app_main import get_pac_content
            await send_response(writer, 200, {"content-type": "application/x-ns-proxy-autoconfig", "cache-control": "no-cache"},
                                get_pac_content(LISTEN_PORT).encode(), method=method, close=True)
        else:
            while await handle_http(request, writer):
                request = await read_http_request(reader, writer)
                if request is None:
                    break
    except asyncio.CancelledError:
        raise
    except (HTTPError, httpx.HTTPError, OSError, ValueError, asyncio.TimeoutError) as exc:
        status = exc.status if isinstance(exc, HTTPError) else 504 if isinstance(exc, (asyncio.TimeoutError, httpx.TimeoutException)) else 502
        try:
            await send_response(writer, status, {"content-type": "text/plain"}, HTTPStatus(status).phrase.encode(), close=True)
        except (OSError, RuntimeError):
            pass
        format_log("ERROR", "", f"{status} {type(exc).__name__}")
    finally:
        await close_writer(writer)


async def main():
    global proxy_loop, proxy_stop_event, proxy_server_instance
    if LISTEN_HOST not in ("127.0.0.1", "::1"):
        raise ValueError("仅允许监听本机回环地址")
    proxy_loop = asyncio.get_running_loop()
    proxy_stop_event = asyncio.Event()
    clients = set()
    server = None
    try:
        await init_http_client()
        ssl_context = get_server_ssl_context()
        def accept(reader, writer):
            task = asyncio.create_task(client_handler(reader, writer, ssl_context))
            clients.add(task)
            task.add_done_callback(clients.discard)
        server = await asyncio.start_server(accept, LISTEN_HOST, LISTEN_PORT)
        proxy_server_instance = server
        PROXY_STATS["is_running"], PROXY_STATS["last_error"] = True, ""
        proxy_ready_event.set()
        format_log("READY", "", f"http://{LISTEN_HOST}:{LISTEN_PORT}; uplink={urllib.parse.urlsplit(UPSTREAM_PROXY).hostname or 'direct'}")
        async with server:
            await proxy_stop_event.wait()
    finally:
        if server:
            server.close()
            await server.wait_closed()
        for task in list(clients):
            task.cancel()
        await asyncio.gather(*list(clients), return_exceptions=True)
        await close_http_client()
        proxy_server_instance = None
        PROXY_STATS["is_running"] = False
        proxy_ready_event.set()


def run_proxy_in_thread():
    try:
        asyncio.run(main())
    except Exception as exc:
        PROXY_STATS["last_error"] = str(exc)
    finally:
        PROXY_STATS["is_running"] = False
        proxy_ready_event.set()


def start_proxy_thread():
    global proxy_thread
    if proxy_thread and proxy_thread.is_alive():
        return
    proxy_ready_event.clear()
    PROXY_STATS["last_error"] = ""
    proxy_thread = threading.Thread(target=run_proxy_in_thread, daemon=True)
    proxy_thread.start()


def stop_proxy_thread():
    global proxy_thread
    if proxy_loop and proxy_loop.is_running() and proxy_stop_event:
        proxy_loop.call_soon_threadsafe(proxy_stop_event.set)
    if proxy_thread and proxy_thread.is_alive():
        proxy_thread.join(timeout=8)
        if proxy_thread.is_alive():
            raise RuntimeError("代理尚未停止，请稍候重试")
    proxy_thread = None


if __name__ == "__main__":
    from app_main import main as cli_main
    cli_main()

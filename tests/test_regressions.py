"""Offline regressions and real loopback TLS/CONNECT tests. No game accounts."""
import asyncio
import atexit
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import zlib

import brotli
import httpx

TEST_PARENT = Path(os.environ.get("GBF_TEST_ROOT", tempfile.gettempdir())).resolve()
TEST_PARENT.mkdir(parents=True, exist_ok=True)
_temp = tempfile.TemporaryDirectory(prefix="gbf-regressions-", dir=TEST_PARENT)
ROOT = Path(_temp.name).resolve()
assert ROOT.is_relative_to(TEST_PARENT) and ROOT != TEST_PARENT
os.environ["GBF_ACCELERATOR_DATA_DIR"] = str(ROOT / "state")
os.environ["TEMP"] = os.environ["TMP"] = str(ROOT)
sys.dont_write_bytecode = True
VIOLATIONS = []


def guard(event, args):
    def within(value):
        return isinstance(value, int) or Path(os.fsdecode(value)).resolve().is_relative_to(ROOT)
    denied = False
    if event == "open" and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        denied = not within(args[0])
    elif event in ("os.mkdir", "os.remove", "os.rmdir", "os.utime"):
        denied = not within(args[0])
    elif event == "os.rename":
        denied = not within(args[0]) or not within(args[1])
    elif event in ("socket.connect", "socket.bind"):
        denied = not isinstance(args[1], tuple) or args[1][0] not in ("127.0.0.1", "::1")
    elif event == "socket.getaddrinfo":
        denied = args[0] not in (None, "127.0.0.1", "::1")
    elif event == "subprocess.Popen" or event in ("winreg.SetValue", "winreg.DeleteValue", "winreg.DeleteKey"):
        denied = True
    if denied:
        VIOLATIONS.append(event)
        raise PermissionError("regressions deny external side effects: " + event)


sys.addaudithook(guard)
import config_manager as config
import cache_manager as cache
import cert_manager as certs
import gbf_proxy as proxy
import network_policy as policy
import system_proxy as pac
from app_main import get_pac_content

HOST = "prd-game-a-granbluefantasy.akamaized.net"
URL = f"https://{HOST}/assets/test.js"
PUBLIC = {"content-type": "application/javascript", "cache-control": "public, max-age=600"}


class Writer:
    def __init__(self): self.data = bytearray()
    def write(self, data): self.data.extend(data)
    async def drain(self): pass
    async def start_tls(self, context, **kwargs): pass
    def close(self): pass
    async def wait_closed(self): pass


def parse_wire(raw):
    if raw.startswith(b"HTTP/1.1 200 Connection Established\r\n\r\n"):
        raw = raw.split(b"\r\n\r\n", 1)[1]
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    fields = [line.split(":", 1) for line in lines[1:]]
    return int(lines[0].split()[1]), httpx.Headers([(k, v.strip()) for k, v in fields]), body


def make_response(body=b"asset", status=200, headers=None):
    return httpx.Response(status, headers=headers or PUBLIC, stream=httpx.ByteStream(body))


async def request(path="/assets/test.js", host=HOST, method="GET", headers=None, body=b""):
    fields = {"Host": host, **(headers or {})}
    if body: fields["Content-Length"] = str(len(body))
    wire = (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n").encode() + body
    reader = asyncio.StreamReader()
    reader.feed_data(wire)
    reader.feed_eof()
    writer = Writer()
    await proxy.handle_mitm_session(reader, writer, host, None)
    return parse_wire(bytes(writer.data))


class CacheTests(unittest.TestCase):
    def setUp(self):
        config.config_manager.config = dict(config.DEFAULT_CONFIG)
        self.path = ROOT / self.id().split(".")[-1]
        self.cm = cache.CacheManager(self.path)

    def tearDown(self): self.assertEqual(VIOLATIONS, [])

    def test_atomic_entry_survives_failed_replace(self):
        self.assertTrue(self.cm.save_cache(URL, {**PUBLIC, "etag": '"old"'}, b"old"))
        with patch.object(cache.os, "replace", side_effect=OSError("injected failure")):
            self.assertFalse(self.cm.save_cache(URL, {**PUBLIC, "etag": '"new"'}, b"new"))
        self.cm.clear_ram_cache()
        headers, body = self.cm.get_cache(URL)
        self.assertEqual((headers["etag"], body), ('"old"', b"old"))
        self.assertFalse(list(self.path.rglob("*.tmp")))

    def test_checksum_corruption_is_miss(self):
        self.cm.save_cache(URL, PUBLIC, b"correct")
        path = self.cm._entry_path(URL)
        path.write_bytes(path.read_bytes()[:-7] + b"corrupt")
        self.cm.clear_ram_cache()
        self.assertIsNone(self.cm.get_cache(URL))
        self.assertFalse(path.exists())

    def test_empty_html_and_bad_compression_rejected(self):
        for data, headers in [(b"", PUBLIC), (b"<html>Error</html>", PUBLIC),
                              (b"\x1f\x8bbroken", {**PUBLIC, "content-encoding": "gzip"}),
                              (b"text", {**PUBLIC, "content-type": "text/html"})]:
            with self.subTest(data=data): self.assertFalse(self.cm.save_cache(URL, headers, data))

    def test_encoded_cache_roundtrips(self):
        content = b"var original=1;" * 10
        for name, data in [("gzip", gzip.compress(content)), ("deflate", zlib.compress(content)), ("br", brotli.compress(content))]:
            with self.subTest(encoding=name):
                self.assertTrue(self.cm.save_cache(URL, {**PUBLIC, "content-encoding": name}, data))
                self.cm.clear_ram_cache()
                headers, body = self.cm.get_cache(URL)
                self.assertEqual(headers["content-encoding"], name)
                self.assertEqual(cache.decode_body(body, name), content)

    def test_decompression_has_output_limit(self):
        content = b"x" * 10000
        for name, data in [("gzip", gzip.compress(content)), ("deflate", zlib.compress(content)), ("br", brotli.compress(content))]:
            with self.subTest(name=name), self.assertRaises(ValueError): cache.decode_body(data, name, 100)

    def test_ram_overwrite_and_small_limit(self):
        self.cm.save_cache(URL, PUBLIC, b"one")
        self.cm.save_cache(URL, PUBLIC, b"two")
        self.assertEqual(self.cm.get_ram_cache_stats(), (1, 3))
        config.config_manager.config["ram_cache_max_mb"] = 0
        self.cm.save_cache(URL, PUBLIC, b"three")
        self.assertEqual(self.cm.get_ram_cache_stats(), (0, 0))

    def test_expiry_age_and_client_refresh(self):
        with patch.object(cache.time, "time", return_value=1000):
            self.cm.save_cache(URL, {**PUBLIC, "cache-control": "max-age=20", "age": "10"}, b"asset")
        with patch.object(cache.time, "time", return_value=1005):
            self.assertEqual(self.cm.get_cache(URL)[0]["age"], "15")
            self.assertIsNone(self.cm.get_cache(URL, {"cache-control": "no-cache"}))
        with patch.object(cache.time, "time", return_value=1011): self.assertIsNone(self.cm.get_cache(URL))

    def test_no_cache_always_revalidates(self):
        self.cm.save_cache(URL, {**PUBLIC, "cache-control": "no-cache, max-age=600"}, b"asset")
        self.assertIsNone(self.cm.get_cache(URL))
        self.assertEqual(self.cm.get_cache(URL, allow_stale=True)[1], b"asset")

    def test_client_max_age_and_min_fresh(self):
        with patch.object(cache.time, "time", return_value=1000):
            self.cm.save_cache(URL, {**PUBLIC, "cache-control": "max-age=60"}, b"asset")
        with patch.object(cache.time, "time", return_value=1020):
            self.assertIsNone(self.cm.get_cache(URL, {"cache-control": "max-age=10"}))
            self.assertIsNone(self.cm.get_cache(URL, {"cache-control": "min-fresh=50"}))
            self.assertEqual(self.cm.get_cache(URL, {"cache-control": "max-age=30"})[1], b"asset")

    def test_heuristic_has_finite_cap(self):
        headers = {"last-modified": "Tue, 15 May 2018 06:23:26 GMT"}
        now = time.time()
        self.assertLessEqual(cache._fresh_until(headers, now) - now, 3600)
        self.assertGreater(cache._fresh_until(headers, now), now)
        self.assertEqual(cache._fresh_until({**headers, "cache-control": "no-cache"}, now), now)

    def test_no_store_private_vary_set_cookie_rejected(self):
        for extra in ({"cache-control": "private"}, {"cache-control": "no-store"}, {"vary": "Cookie"},
                      {"vary": "*"}, {"set-cookie": "synthetic=1"}):
            with self.subTest(extra=extra): self.assertFalse(self.cm.save_cache(URL, {**PUBLIC, **extra}, b"asset"))

    def test_identity_and_encoding_q_zero(self):
        compressed = gzip.compress(b"original")
        result = cache.representation({"content-encoding": "gzip", "etag": '"compressed"'}, compressed, "gzip;q=0, identity")
        self.assertEqual(result[1], b"original")
        self.assertNotIn("content-encoding", result[0])
        self.assertNotIn("etag", result[0])
        self.assertIsNone(cache.representation({}, b"original", "identity;q=0, *;q=0"))
        result = cache.representation({}, b"original", "gzip, identity;q=0")
        self.assertEqual(gzip.decompress(result[1]), b"original")
        self.assertIsNone(cache.representation({"content-encoding": "gzip", "cache-control": "no-transform"}, compressed, "identity"))

    def test_legacy_read_only_revalidation(self):
        legacy = self.path / "legacy"
        body_path = legacy / "assets/test.js"
        body_path.parent.mkdir(parents=True)
        data = zlib.compress(b"legacy")
        body_path.write_bytes(data)
        ext = body_path.with_name(body_path.name + ".ext")
        ext.write_text(json.dumps({"md5": hashlib.md5(data).hexdigest(), "ce": "deflate", "ct": "application/javascript", "ETag": '"legacy"'}))
        before = (body_path.read_bytes(), ext.read_bytes())
        self.cm.set_legacy_base(legacy)
        self.assertIsNone(self.cm.get_cache(URL))
        headers, loaded = self.cm.get_cache(URL, allow_stale=True)
        self.assertEqual((headers["content-encoding"], loaded), ("deflate", data))
        self.assertIsNone(self.cm.get_cache(URL + "?v=2", allow_stale=True))
        self.cm.clear_all_cache()
        self.assertEqual(before, (body_path.read_bytes(), ext.read_bytes()))
        body_path.write_bytes(b"")
        self.assertIsNone(self.cm.get_cache(URL, allow_stale=True))
        self.assertTrue(body_path.exists() and ext.exists())

    def test_clear_only_generated_entries(self):
        self.cm.save_cache(URL, PUBLIC, b"asset")
        unrelated = self.path / "important.txt"
        unrelated.write_text("keep")
        fake = self.path / "entries-v2/aa" / ("a" * 64 + ".gbfcache")
        fake.parent.mkdir(parents=True, exist_ok=True)
        fake.write_text("not an entry")
        self.assertEqual(self.cm.clear_all_cache()[0], 1)
        self.assertTrue(unrelated.exists() and fake.exists())

    def test_old_config_directory_becomes_read_only(self):
        legacy = self.path / "old"
        (legacy / "assets").mkdir(parents=True)
        cfg = config.ConfigManager(ROOT / "absent.json")
        cfg.config["cache_dir"] = str(legacy)
        selected = cfg.get_effective_cache_dir()
        self.assertNotEqual(selected, legacy)
        self.assertEqual(cfg.get_effective_legacy_cache_dir(), legacy)
        self.assertEqual(list(legacy.iterdir()), [legacy / "assets"])

    def test_sensitive_requests_never_hit_public_entry(self):
        self.cm.save_cache(URL, PUBLIC, b"public")
        for fields in ({"cookie": "audit=A"}, {"authorization": "Bearer SYNTHETIC"}, {"range": "bytes=0-1"}):
            self.assertIsNone(self.cm.get_cache(URL, fields))

    def test_policy_scope_and_path_escape(self):
        for host in ("gbf.akamaized.net.attacker.invalid", "notgbf.akamaized.net", "other.akamaized.net"):
            self.assertFalse(policy.should_mitm(host))
        self.assertTrue(policy.should_mitm("gbf.game.mbga.jp"))
        for path in ("/../secret.js", "/assets/%2e%2e/secret.js", "/assets/..\\secret.js", "/rest/file.js"):
            self.assertFalse(policy.cacheable_request("GET", f"https://{HOST}{path}", {}))
        self.assertFalse(policy.cacheable_request("GET", URL + "?access_token=synthetic", {}))


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        config.config_manager.config = dict(config.DEFAULT_CONFIG)
        proxy.UPSTREAM_PROXY = "direct"
        proxy.cache_manager = cache.CacheManager(ROOT / self.id().split(".")[-1])
        self.calls = []
        self.responder = lambda req, n: make_response()
        async def handler(req):
            self.calls.append(req)
            return self.responder(req, len(self.calls))
        await proxy.init_http_client(transport=httpx.MockTransport(handler))
        self.log = patch.object(proxy, "format_log", lambda *args: None)
        self.log.start()

    async def asyncTearDown(self):
        await proxy.close_http_client()
        self.log.stop()
        self.assertEqual(VIOLATIONS, [])

    async def test_miss_ram_disk_hit(self):
        first, second = await request(), await request()
        proxy.cache_manager.clear_ram_cache()
        third = await request()
        self.assertEqual(first[2], second[2])
        self.assertEqual(third[1]["x-cache-source"], "DISK")
        self.assertEqual(len(self.calls), 1)

    async def test_cookies_are_never_injected_between_clients(self):
        self.responder = lambda r, n: make_response(headers={"content-type": "application/json", "set-cookie": "audit_session=A; Path=/; Secure"})
        await request("/rest/session")
        await request("/rest/another")
        self.assertNotIn("cookie", self.calls[1].headers)
        await request("/rest/explicit", headers={"Cookie": "audit_session=B"})
        self.assertEqual(self.calls[2].headers["cookie"], "audit_session=B")
        self.assertEqual(len(proxy.http_client.cookies), 0)

    async def test_no_store_response_is_forwarded_not_replayed(self):
        self.responder = lambda r, n: make_response(str(n).encode(), headers={**PUBLIC, "cache-control": "private, no-store", "vary": "Cookie", "set-cookie": "audit=A"})
        first, second = await request(), await request()
        self.assertEqual((first[2], second[2]), (b"1", b"2"))
        self.assertEqual(second[1]["cache-control"], "private, no-store")
        self.assertNotIn("access-control-allow-origin", second[1])
        self.assertEqual(first[1]["set-cookie"], "audit=A")

    async def test_query_and_host_keys_are_distinct(self):
        self.responder = lambda r, n: make_response(str(r.url).encode())
        one = await request("/assets/a.js?v=1")
        two = await request("/assets/a.js?v=2")
        three = await request("/assets/a.js?v=2", host="prd-game-a1-granbluefantasy.akamaized.net")
        self.assertEqual(len({one[2], two[2], three[2]}), 3)
        self.assertEqual(len(self.calls), 3)

    async def test_unversioned_no_cache_reaches_origin(self):
        self.responder = lambda r, n: make_response(str(n).encode(), headers={**PUBLIC, "cache-control": "no-cache", "etag": f'"{n}"'})
        first = await request("/js/unversioned.js")
        second = await request("/js/unversioned.js", headers={"Cache-Control": "no-cache", "If-None-Match": '"1"'})
        self.assertEqual((first[2], second[2]), (b"1", b"2"))
        self.assertEqual(len(self.calls), 2)

    async def test_stale_conditional_304_refreshes_entry(self):
        self.responder = lambda r, n: (make_response(b"original", headers={**PUBLIC, "cache-control": "max-age=0", "etag": '"v1"'}) if n == 1
                                       else make_response(b"", status=304, headers={"etag": '"v1"', "cache-control": "public, max-age=600"}))
        await request()
        second, third = await request(), await request()
        self.assertEqual(self.calls[1].headers["if-none-match"], '"v1"')
        self.assertEqual((second[0], second[2], third[2]), (200, b"original", b"original"))
        self.assertEqual(len(self.calls), 2)

    async def test_script_body_and_etag_unchanged(self):
        script = b't&&alert(t),a&&window.location.reload()'
        self.responder = lambda r, n: make_response(script, headers={**PUBLIC, "etag": '"original"', "cache-control": "max-age=600, no-transform"})
        for _ in range(2):
            response = await request("/assets/set-error-handler.js")
            self.assertEqual((response[2], response[1]["etag"]), (script, '"original"'))

    async def test_options_and_old_mock_endpoint_reach_origin(self):
        self.responder = lambda r, n: make_response(b"upstream", status=403, headers={"access-control-allow-origin": "https://allowed.invalid"})
        options = await request("/rest/test", method="OPTIONS")
        mocked = await request("/rest/error/js", method="POST", body=b"synthetic")
        self.assertEqual((options[0], mocked[0]), (403, 403))
        self.assertEqual(options[1]["access-control-allow-origin"], "https://allowed.invalid")
        self.assertEqual(len(self.calls), 2)

    async def test_compressed_wire_preserved_and_cache_negotiates(self):
        data = gzip.compress(b"unchanged")
        self.responder = lambda r, n: make_response(data, headers={**PUBLIC, "content-encoding": "gzip", "etag": '"gzip-original"'})
        first = await request(headers={"Accept-Encoding": "gzip"})
        second = await request(headers={"Accept-Encoding": "identity, gzip;q=0"})
        self.assertEqual(first[2], data)
        self.assertEqual(second[2], b"unchanged")
        self.assertNotIn("content-encoding", second[1])
        self.assertNotIn("etag", second[1])
        self.assertEqual(len(self.calls), 1)

    async def test_head_miss_preserves_length_without_body(self):
        self.responder = lambda r, n: make_response(b"", headers={**PUBLIC, "content-length": "1234"})
        result = await request(method="HEAD")
        self.assertEqual((result[0], result[1]["content-length"], result[2]), (200, "1234", b""))
        self.assertEqual(list(proxy.cache_manager.cache_base.rglob("*.gbfcache")), [])

    async def test_head_hit_and_304_framing(self):
        self.responder = lambda r, n: make_response(b"original", headers={**PUBLIC, "etag": '"v1"'})
        await request()
        head = await request(method="HEAD")
        not_modified = await request(headers={"If-None-Match": 'W/"v1", "other"'})
        self.assertEqual((head[1]["content-length"], head[2]), ("8", b""))
        self.assertEqual((not_modified[0], not_modified[2]), (304, b""))
        self.assertNotIn("content-length", not_modified[1])

    async def test_dynamic_multi_cookies_and_cors_preserved(self):
        self.responder = lambda r, n: make_response(b"json", headers=[("content-type", "application/json"), ("set-cookie", "a=1"),
                                               ("set-cookie", "b=2"), ("access-control-allow-origin", "https://allowed.invalid")])
        result = await request("/rest/test")
        self.assertEqual(result[1].get_list("set-cookie"), ["a=1", "b=2"])
        self.assertEqual(result[1]["access-control-allow-origin"], "https://allowed.invalid")

    async def test_static_multiple_set_cookies_are_separate_and_never_stored(self):
        self.responder = lambda r, n: make_response(b"asset", headers=[*PUBLIC.items(),
            ("set-cookie", "a=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT"), ("set-cookie", "b=2")])
        for _ in range(2):
            result = await request()
            self.assertEqual(result[1].get_list("set-cookie"), [
                "a=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT", "b=2"])
        self.assertEqual(len(self.calls), 2)
        self.assertIsNone(proxy.cache_manager.get_cache(URL))

    async def test_legacy_304_promotes_to_new_cache_without_inventing_cors(self):
        legacy = ROOT / "legacy-promotion"
        body = legacy / "assets/test.js"
        body.parent.mkdir(parents=True)
        body.write_bytes(b"old public asset")
        ext = body.with_suffix(".js.ext")
        ext.write_text(json.dumps({"md5": hashlib.md5(body.read_bytes()).hexdigest(),
                                  "ct": "application/javascript", "ETag": '"legacy"'}))
        before = (body.read_bytes(), ext.read_bytes(), body.stat().st_mtime_ns, ext.stat().st_mtime_ns)
        proxy.cache_manager.set_legacy_base(legacy)
        self.responder = lambda r, n: make_response(b"", status=304, headers=PUBLIC)
        first, second = await request(), await request()
        self.assertEqual(self.calls[0].headers["if-none-match"], '"legacy"')
        self.assertEqual((first[0], first[2], second[2]), (200, b"old public asset", b"old public asset"))
        self.assertNotIn("access-control-allow-origin", first[1])
        self.assertEqual(len(self.calls), 1)
        proxy.cache_manager.clear_all_cache()
        self.assertEqual(before, (body.read_bytes(), ext.read_bytes(), body.stat().st_mtime_ns, ext.stat().st_mtime_ns))

    async def test_if_none_match_star_without_etag(self):
        await request()
        result = await request(headers={"If-None-Match": "*"})
        self.assertEqual((result[0], result[2]), (304, b""))
        self.assertEqual(len(self.calls), 1)

    async def test_other_preconditions_reach_origin(self):
        await request()
        self.responder = lambda r, n: make_response(b"", status=412)
        for name, value in (("If-Match", '"another"'), ("If-Unmodified-Since", "Tue, 15 May 2018 06:23:26 GMT")):
            result = await request(headers={name: value})
            self.assertEqual(result[0], 412)
        self.assertEqual(len(self.calls), 3)

    async def test_refresh_404_invalidates_existing_entry(self):
        await request()
        self.responder = lambda r, n: make_response(b"gone", status=404)
        self.assertEqual((await request(headers={"Cache-Control": "no-cache"}))[0], 404)
        self.assertEqual((await request())[0], 404)
        self.assertEqual(len(self.calls), 3)

    async def test_idle_keep_alive_closes_without_spurious_504(self):
        async def timeout(*args, **kwargs): raise TimeoutError()
        writer = Writer()
        with patch.object(proxy, "_line", timeout):
            await proxy.client_handler(asyncio.StreamReader(), writer, None)
        self.assertEqual(bytes(writer.data), b"")

    async def test_header_framing_bounds_for_plain_http(self):
        for value in ("-1", str(proxy.MAX_BODY_BYTES + 1)):
            reader = asyncio.StreamReader()
            reader.feed_data(f"POST http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: {value}\r\n\r\n".encode())
            reader.feed_eof()
            writer = Writer()
            await proxy.client_handler(reader, writer, None)
            self.assertEqual(parse_wire(bytes(writer.data))[0], 413)

    async def test_chunk_trailers_consumed_before_next_request(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"POST /rest/test HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trace: one\r\nX-Other: two\r\n\r\nGET /next HTTP/1.1\r\nHost: test\r\n\r\n")
        reader.feed_eof()
        self.assertEqual((await proxy.read_http_request(reader))[4], b"abc")
        self.assertEqual((await proxy.read_http_request(reader))[1], "/next")

    async def test_ambiguous_framing_rejected(self):
        for fields in (b"Content-Length: 1\r\nContent-Length: 2\r\n", b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n"):
            reader = asyncio.StreamReader()
            reader.feed_data(b"POST / HTTP/1.1\r\n" + fields + b"\r\n")
            reader.feed_eof()
            with self.assertRaises(proxy.HTTPError): await proxy.read_http_request(reader)

    async def test_proxy_auth_and_connection_headers_not_forwarded(self):
        await request("/rest/test", headers={"Proxy-Authorization": "Basic SYNTHETIC", "Connection": "X-Only-Hop", "X-Only-Hop": "remove"})
        self.assertNotIn("proxy-authorization", self.calls[0].headers)
        self.assertNotIn("x-only-hop", self.calls[0].headers)


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        config.config_manager.config = dict(config.DEFAULT_CONFIG)
        proxy.UPSTREAM_PROXY = "direct"
        self.servers, self.tasks = [], set()
        self.original_port = proxy.LISTEN_PORT
        self.log = patch.object(proxy, "format_log", lambda *args: None)
        self.log.start()

    async def asyncTearDown(self):
        for server in self.servers: server.close()
        for server in self.servers: await server.wait_closed()
        for task in list(self.tasks): task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)
        await proxy.close_http_client()
        proxy.LISTEN_PORT = self.original_port
        self.log.stop()
        self.assertEqual(VIOLATIONS, [])

    async def server(self, handler, **kwargs):
        def accept(r, w):
            task = asyncio.create_task(handler(r, w))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        server = await asyncio.start_server(accept, "127.0.0.1", 0, **kwargs)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def test_real_tls_miss_hit_and_mbga_certificate(self):
        context = certs.get_server_ssl_context()
        trust = ssl.create_default_context(cafile=str(certs.CA_CERT_PATH))
        calls = []
        def upstream(req):
            calls.append(req)
            return make_response(b"TLS asset")
        await proxy.init_http_client(transport=httpx.MockTransport(upstream))
        proxy.cache_manager = cache.CacheManager(ROOT / "tls_cache")
        port = await self.server(lambda r, w: proxy.client_handler(r, w, context))
        async def wire(host, path):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            try:
                w.write(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
                await w.drain()
                self.assertIn(b"200 Connection Established", await r.readuntil(b"\r\n\r\n"))
                await w.start_tls(trust, server_hostname=host)
                w.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                await w.drain()
                return parse_wire(await r.read())
            finally:
                w.close()
                await w.wait_closed()
        first = await asyncio.wait_for(wire(HOST, "/assets/wire.js"), 5)
        second = await asyncio.wait_for(wire(HOST, "/assets/wire.js"), 5)
        mbga = await asyncio.wait_for(wire("gbf.game.mbga.jp", "/rest/test"), 5)
        self.assertEqual((first[2], second[2], mbga[0]), (b"TLS asset", b"TLS asset", 200))
        self.assertEqual(len(calls), 2)

    async def test_direct_real_http_ignores_environment_proxy(self):
        async def origin(r, w):
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect")
            await w.drain()
            w.close()
        port = await self.server(origin)
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1"}):
            await proxy.init_http_client()
            response = await proxy.fetch_upstream("GET", f"http://127.0.0.1:{port}/", {}, b"")
        self.assertEqual(response.content, b"direct")

    async def test_direct_tcp_tunnel(self):
        async def echo(r, w):
            w.write(await r.readexactly(4))
            await w.drain()
            w.close()
        destination = await self.server(echo)
        port = await self.server(lambda r, w: proxy.client_handler(r, w, None))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(f"CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
        await w.drain()
        self.assertIn(b"200", await r.readuntil(b"\r\n\r\n"))
        w.write(b"ping")
        await w.drain()
        self.assertEqual(await asyncio.wait_for(r.readexactly(4), 3), b"ping")
        w.close()
        await w.wait_closed()

    async def test_http_connect_proxy_authentication(self):
        captured = []
        async def upstream(r, w):
            captured.append(await r.readuntil(b"\r\n\r\n"))
            w.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await w.drain()
            w.write(await r.readexactly(4))
            await w.drain()
            w.close()
        port = await self.server(upstream)
        proxy.UPSTREAM_PROXY = f"http://audit:synthetic@127.0.0.1:{port}"
        r, w = await proxy.open_target_tunnel("example.invalid", 443)
        w.write(b"ping")
        await w.drain()
        self.assertEqual(await r.readexactly(4), b"ping")
        self.assertIn(b"Proxy-Authorization: Basic ", captured[0])
        self.assertIn(b"CONNECT example.invalid:443", captured[0])
        w.close()
        await w.wait_closed()

    async def test_socks_connect_domain_and_authentication(self):
        captured = []
        async def upstream(r, w):
            self.assertEqual(await r.readexactly(3), b"\x05\x01\x02")
            w.write(b"\x05\x02")
            await w.drain()
            self.assertEqual(await r.readexactly(1), b"\x01")
            user = await r.readexactly((await r.readexactly(1))[0])
            password = await r.readexactly((await r.readexactly(1))[0])
            captured.append((user, password))
            w.write(b"\x01\x00")
            await w.drain()
            self.assertEqual(await r.readexactly(4), b"\x05\x01\x00\x03")
            captured.append(await r.readexactly((await r.readexactly(1))[0]))
            self.assertEqual(await r.readexactly(2), b"\x01\xbb")
            w.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            await w.drain()
            w.write(await r.readexactly(4))
            await w.drain()
            w.close()
        port = await self.server(upstream)
        proxy.UPSTREAM_PROXY = f"socks5://audit:synthetic@127.0.0.1:{port}"
        r, w = await proxy.open_target_tunnel("example.invalid", 443)
        w.write(b"ping")
        await w.drain()
        self.assertEqual(await r.readexactly(4), b"ping")
        self.assertEqual(captured, [(b"audit", b"synthetic"), b"example.invalid"])
        w.close()
        await w.wait_closed()

    async def test_https_proxy_connect_uses_verified_tls(self):
        context = certs.get_server_ssl_context()
        trust = ssl.create_default_context(cafile=str(certs.CA_CERT_PATH))
        # Use the real current certificate hostname while keeping all sockets on loopback.
        calls = []
        async def upstream(r, w):
            calls.append(await r.readuntil(b"\r\n\r\n"))
            w.write(b"HTTP/1.1 200 OK\r\n\r\n")
            await w.drain()
            w.write(await r.readexactly(4))
            await w.drain()
            await proxy.close_writer(w)
        port = await self.server(upstream, ssl=context)
        proxy.UPSTREAM_PROXY = f"https://{HOST}:{port}"
        connect = asyncio.open_connection
        async def loopback(host, port, **kwargs):
            self.assertEqual(kwargs["server_hostname"], HOST)
            return await connect("127.0.0.1", port, **kwargs)
        with patch.object(asyncio, "open_connection", loopback):
            r, w = await proxy.open_target_tunnel("example.invalid", 443, proxy_tls_context=trust)
        w.write(b"ping")
        await w.drain()
        self.assertEqual(await r.readexactly(4), b"ping")
        self.assertIn(b"CONNECT example.invalid:443", calls[0])
        await proxy.close_writer(w)

    async def test_truncated_upstream_body_is_rejected(self):
        async def upstream(r, w):
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\nConnection: close\r\n\r\nshort")
            await w.drain()
            await proxy.close_writer(w)
        port = await self.server(upstream)
        await proxy.init_http_client()
        with self.assertRaises(httpx.RemoteProtocolError):
            await proxy.fetch_upstream("GET", f"http://127.0.0.1:{port}/", {}, b"")

    async def test_occupied_port_owner_is_untouched(self):
        async def echo(r, w):
            w.write(b"alive")
            await w.drain()
            w.close()
        port = await self.server(echo)
        proxy.LISTEN_PORT = port
        with self.assertRaises(OSError): await proxy.main()
        r, w = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await r.readexactly(5), b"alive")
        w.close()
        await w.wait_closed()


class StartupTests(unittest.TestCase):
    def test_startup_options_keep_errors_visible(self):
        import gui_main
        for start, minimized, succeeded, expected in (
                (False, False, False, (0, 0)), (True, True, True, (1, 1)),
                (True, True, False, (1, 0)), (False, True, False, (0, 1)),
                (True, False, True, (1, 0))):
            with self.subTest(start=start, minimized=minimized, succeeded=succeeded):
                app = types.SimpleNamespace(start_proxy=unittest.mock.Mock(), root=types.SimpleNamespace(withdraw=unittest.mock.Mock()))
                with patch.dict(gui_main.gbf_proxy.PROXY_STATS, {"is_running": succeeded}):
                    gui_main.apply_startup_options(app, autostart=start, start_minimized=minimized)
                self.assertEqual((app.start_proxy.call_count, app.root.withdraw.call_count), expected)
        self.assertEqual(VIOLATIONS, [])

    def test_cli_passes_explicit_startup_options_to_gui(self):
        import app_main
        fake_gui = types.SimpleNamespace(main=unittest.mock.Mock())
        with patch.dict(sys.modules, {"gui_main": fake_gui}):
            app_main.main(["--autostart", "--start-minimized"])
        fake_gui.main.assert_called_once_with(autostart=True, start_minimized=True)
        self.assertEqual(VIOLATIONS, [])


class WindowsIntegrationTests(unittest.TestCase):
    def tearDown(self): self.assertEqual(VIOLATIONS, [])

    def fake_registry(self):
        values = {}
        class Key:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        def query(key, name):
            if name not in values: raise FileNotFoundError()
            return values[name]
        reg = types.SimpleNamespace(HKEY_CURRENT_USER=1, KEY_READ=1, KEY_SET_VALUE=2, REG_SZ=1,
              OpenKey=lambda *args: Key(), QueryValueEx=query,
              SetValueEx=lambda key, name, reserved, kind, value: values.__setitem__(name, (value, kind)),
              DeleteValue=lambda key, name: values.pop(name))
        return reg, values

    def test_pac_restores_foreign_local_remote_empty_and_absent(self):
        reg, values = self.fake_registry()
        with patch.object(pac, "winreg", reg, create=True), patch.object(pac, "notify_wininet", lambda: None):
            for initial in [("http://127.0.0.1:8123/proxy.pac", 1), ("https://example.invalid/old.pac", 1), ("", 2), None]:
                values.clear()
                pac._original_pac = pac._installed_pac_url = None
                if initial is not None: values["AutoConfigURL"] = initial
                self.assertTrue(pac.disable_pac_proxy())
                self.assertEqual(values.get("AutoConfigURL"), initial)
                self.assertTrue(pac.enable_pac_proxy())
                self.assertTrue(pac.enable_pac_proxy("http://127.0.0.1:8125/proxy.pac"))
                self.assertTrue(pac.disable_pac_proxy())
                self.assertEqual(values.get("AutoConfigURL"), initial)

    def test_pac_preserves_intervening_external_change(self):
        reg, values = self.fake_registry()
        with patch.object(pac, "winreg", reg, create=True), patch.object(pac, "notify_wininet", lambda: None):
            pac._original_pac = pac._installed_pac_url = None
            pac.enable_pac_proxy()
            values["AutoConfigURL"] = ("http://localhost:9999/proxy.pac", 1)
            pac.disable_pac_proxy()
            self.assertEqual(values["AutoConfigURL"][0], "http://localhost:9999/proxy.pac")

    def test_old_root_cannot_satisfy_current_root_check(self):
        with patch.object(config, "_ca_thumbprint", return_value="AA" * 20), patch.object(config, "_certutil", side_effect=lambda args: args[-1] == config.LEGACY_CA_SHA1):
            self.assertFalse(config.is_ca_installed())
            self.assertTrue(config.is_legacy_ca_installed())

    def test_ca_migration_is_explicit_and_exact(self):
        installed, commands = {config.LEGACY_CA_SHA1}, []
        current = "AA" * 20
        def certutil(args):
            commands.append(args)
            if "-delstore" in args: installed.discard(args[-1]); return True
            if "-addstore" in args: installed.add(current); return True
            return args[-1] in installed
        with patch.object(config, "_ca_thumbprint", return_value=current), patch.object(config, "_certutil", side_effect=certutil):
            self.assertFalse(config.install_ca_certificate(ROOT / "synthetic.crt"))
            self.assertFalse(any("-delstore" in args for args in commands))
            self.assertTrue(config.install_ca_certificate(ROOT / "synthetic.crt", remove_legacy=True))
            self.assertEqual(installed, {current})
            self.assertTrue(all(args[-1] == config.LEGACY_CA_SHA1 for args in commands if "-delstore" in args))

    def test_certificate_routes_and_signed_by_current_ca(self):
        certs.ensure_server_cert()
        from cryptography import x509
        server = x509.load_pem_x509_certificate(certs.SERVER_CERT_PATH.read_bytes())
        ca = x509.load_pem_x509_certificate(certs.CA_CERT_PATH.read_bytes())
        server.verify_directly_issued_by(ca)
        sans = set(server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
        self.assertEqual(sans, set(policy.MITM_HOSTS))
        self.assertIn("gbf.game.mbga.jp", sans)

    def test_changed_ca_key_regenerates_ca_and_leaf(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        directory = ROOT / "ca-key-mismatch"
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(certs, "CERTS_DIR", directory))
            for field, name in (("CA_CERT_PATH", "ca.crt"), ("CA_KEY_PATH", "ca.key"),
                                ("SERVER_CERT_PATH", "server.crt"), ("SERVER_KEY_PATH", "server.key")):
                stack.enter_context(patch.object(certs, field, directory / name))
            certs.ensure_server_cert()
            before = certs.CA_CERT_PATH.read_bytes()
            wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            certs.CA_KEY_PATH.write_bytes(wrong.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            certs.ensure_server_cert()
            self.assertNotEqual(before, certs.CA_CERT_PATH.read_bytes())
            ca = x509.load_pem_x509_certificate(certs.CA_CERT_PATH.read_bytes())
            leaf = x509.load_pem_x509_certificate(certs.SERVER_CERT_PATH.read_bytes())
            leaf.verify_directly_issued_by(ca)

    def test_pac_has_no_broad_akamaized_match(self):
        pac_text = get_pac_content(8124)
        self.assertNotIn('"*granbluefantasy.akamaized.net"', pac_text)
        self.assertNotIn('"*.akamaized.net"', pac_text)
        self.assertIn('host === "' + HOST + '"', pac_text)

    def test_distributed_pac_templates_match_routing(self):
        source = Path(__file__).resolve().parent.parent
        self.assertEqual((source / "proxy.pac").read_text(encoding="utf-8"), get_pac_content(8124))
        profiles = json.loads((source / "SwitchyOmega_GBF.bak").read_text(encoding="utf-8"))
        hosts = {rule["condition"]["pattern"] for rule in profiles["+GBF_AutoSwitch"]["rules"]}
        self.assertTrue(policy.CDN_HOSTS <= hosts)
        self.assertFalse(any("*" in host for host in hosts if "akamaized" in host))


if __name__ == "__main__":
    unittest.main()

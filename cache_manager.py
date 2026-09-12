"""Anonymous public asset cache with atomic entries and a read-only ACGP source."""
from collections import OrderedDict
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import struct
import tempfile
import threading
import time
import urllib.parse
import zlib

import brotli
from config_manager import config_manager
from network_policy import CDN_HOSTS, cacheable_request, cache_control, encoding_quality, end_to_end_headers, wants_refresh, versioned_path

MAGIC = b"GBFC2\x00"
MAX_META_BYTES = 65536
MAX_BODY_BYTES = 64 * 1024 * 1024


def decode_body(data, encoding, limit=MAX_BODY_BYTES):
    encoding = encoding.strip().lower()
    if encoding in ("", "identity"):
        result = data
    elif encoding == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            result = stream.read(limit + 1)
    elif encoding == "deflate":
        result = None
        for window in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                decoder = zlib.decompressobj(window)
                decoded = decoder.decompress(data, limit + 1)
                if len(decoded) > limit:
                    raise ValueError("decoded body exceeds limit")
                if not decoder.eof or decoder.unused_data:
                    raise ValueError("incomplete or trailing deflate data")
                result = decoded
                break
            except zlib.error:
                continue
        if result is None:
            raise ValueError("invalid deflate data")
    elif encoding == "br":
        decoder = brotli.Decompressor()
        chunks, size, pending = [], 0, data
        while True:
            part = decoder.process(pending, output_buffer_limit=limit - size + 1)
            size += len(part)
            if size > limit:
                raise ValueError("decoded body exceeds limit")
            chunks.append(part)
            if decoder.is_finished():
                break
            if decoder.can_accept_more_data():
                raise ValueError("incomplete brotli data")
            pending = b""
        result = b"".join(chunks)
    else:
        raise ValueError("unsupported content encoding")
    if len(result) > limit:
        raise ValueError("decoded body exceeds limit")
    return result


def representation(headers, data, accept_encoding):
    """Select an acceptable representation without changing the resource content."""
    out = dict(headers)
    encoding = out.get("content-encoding", "identity").lower() or "identity"
    if encoding_quality(accept_encoding, encoding) > 0:
        return out, data
    if "no-transform" in cache_control(out.get("cache-control", "")):
        return None
    try:
        decoded = decode_body(data, encoding)
    except (ValueError, OSError, EOFError, zlib.error, brotli.error):
        return None
    if encoding_quality(accept_encoding, "identity") > 0:
        data = decoded
        out.pop("content-encoding", None)
    elif encoding_quality(accept_encoding, "gzip") > 0:
        data = gzip.compress(decoded, mtime=0)
        out["content-encoding"] = "gzip"
    else:
        return None
    # Validators and digests of an encoded representation cannot identify a different one.
    for name in ("etag", "content-md5", "digest", "content-digest", "repr-digest"):
        out.pop(name, None)
    vary = {x.strip() for x in out.get("vary", "").lower().split(",") if x.strip()}
    out["vary"] = ", ".join(sorted(vary | {"accept-encoding"}))
    out["content-length"] = str(len(data))
    return out, data


def _valid_headers(headers):
    return (isinstance(headers, dict) and all(
        isinstance(k, str) and isinstance(v, str) and k and ":" not in k
        and not any(c in k + v for c in "\r\n\x00") for k, v in headers.items()))


def _initial_age(headers, now):
    try:
        apparent = max(0.0, now - parsedate_to_datetime(headers["date"]).timestamp())
    except (KeyError, TypeError, ValueError, OverflowError):
        apparent = 0.0
    try:
        return max(apparent, max(0, int(headers.get("age", "0"))))
    except ValueError:
        return apparent


def _fresh_until(headers, now):
    directives = cache_control(headers.get("cache-control", ""))
    if "no-cache" in directives:
        return now
    try:
        if "s-maxage" in directives or "max-age" in directives:
            lifetime = max(0, int(directives.get("s-maxage", directives.get("max-age"))))
        elif "expires" in headers:
            date = parsedate_to_datetime(headers["date"]).timestamp() if "date" in headers else now
            lifetime = max(0, parsedate_to_datetime(headers["expires"]).timestamp() - date)
        elif "last-modified" in headers:
            date = parsedate_to_datetime(headers["date"]).timestamp() if "date" in headers else now
            modified = parsedate_to_datetime(headers["last-modified"]).timestamp()
            lifetime = min(3600, max(0, date - modified) * 0.1)
        else:
            return now
        return now + max(0, lifetime - _initial_age(headers, now))
    except (ValueError, TypeError, OverflowError):
        return now


class CacheManager:
    def __init__(self, cache_base_dir=None, legacy_base_dir=None):
        self.cache_base = Path(cache_base_dir or config_manager.get_effective_cache_dir()).resolve()
        self.legacy_base = Path(legacy_base_dir).resolve() if legacy_base_dir else config_manager.get_effective_legacy_cache_dir()
        self._lock = threading.RLock()
        self._ram_cache = OrderedDict()
        self._ram_cache_bytes = 0
        self._max_item_bytes = 5 * 1024 * 1024
        self._validate_base(self.cache_base)

    def _validate_base(self, path):
        if (path / "assets").is_dir():
            raise ValueError("该目录是旧缓存，请设为只读 ACGP 来源，另选新缓存目录")
        if self.legacy_base and (path == self.legacy_base or path.is_relative_to(self.legacy_base)):
            raise ValueError("新缓存不能放在只读旧缓存目录内")

    def set_cache_base(self, path):
        with self._lock:
            path = Path(path).resolve()
            self._validate_base(path)
            self.cache_base = path
            self.clear_ram_cache()

    def set_legacy_base(self, path):
        with self._lock:
            legacy = Path(path).resolve() if path else None
            if legacy and (self.cache_base == legacy or self.cache_base.is_relative_to(legacy)):
                raise ValueError("旧缓存不能包含当前写入目录")
            self.legacy_base = legacy
            self.clear_ram_cache()

    def configure_paths(self, cache_path, legacy_path=None):
        candidate = CacheManager(cache_path, legacy_path)
        # An empty UI field explicitly disables the legacy source.
        candidate.legacy_base = Path(legacy_path).resolve() if legacy_path else None
        candidate._validate_base(candidate.cache_base)
        with self._lock:
            self.cache_base, self.legacy_base = candidate.cache_base, candidate.legacy_base
            self.clear_ram_cache()

    def clear_ram_cache(self):
        with self._lock:
            self._ram_cache.clear()
            self._ram_cache_bytes = 0

    def get_ram_cache_stats(self):
        with self._lock:
            return len(self._ram_cache), self._ram_cache_bytes

    def _remember(self, url, meta, data):
        old = self._ram_cache.pop(url, None)
        if old:
            self._ram_cache_bytes -= len(old[1])
        maximum = max(0, int(config_manager.config.get("ram_cache_max_mb", 256))) * 1024 * 1024
        if not config_manager.config.get("enable_ram_cache", True) or len(data) > min(maximum, self._max_item_bytes):
            return
        while self._ram_cache and self._ram_cache_bytes + len(data) > maximum:
            _, (_, removed) = self._ram_cache.popitem(last=False)
            self._ram_cache_bytes -= len(removed)
        self._ram_cache[url] = (meta, data)
        self._ram_cache_bytes += len(data)

    def _entry_path(self, url):
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        path = (self.cache_base / "entries-v2" / digest[:2] / (digest + ".gbfcache")).resolve()
        if not path.is_relative_to(self.cache_base):
            raise ValueError("cache path escapes configured directory")
        return path

    def _legacy_path(self, url):
        if not self.legacy_base:
            return None
        parts = urllib.parse.urlsplit(url)
        if parts.hostname not in CDN_HOSTS or parts.query:
            return None
        path = urllib.parse.unquote(parts.path).lstrip("/")
        if ":" in path or "\\" in path or any(p in (".", "..") for p in path.split("/")):
            return None
        target = (self.legacy_base / path).resolve()
        return target if target.is_relative_to(self.legacy_base) else None

    def _read_legacy(self, url):
        path = self._legacy_path(url)
        if not path or not path.is_file() or not 0 < path.stat().st_size <= MAX_BODY_BYTES:
            return None
        ext = path.with_name(path.name + ".ext")
        if not ext.is_file() or ext.stat().st_size > MAX_META_BYTES:
            return None
        meta = json.loads(ext.read_text(encoding="utf-8-sig"))
        data = path.read_bytes()
        if not isinstance(meta, dict) or meta.get("md5", "").lower() != hashlib.md5(data).hexdigest():
            return None
        headers = {"content-type": meta.get("ct") or "application/octet-stream",
                   "cache-control": "no-cache"}
        if meta.get("ce"):
            headers["content-encoding"] = meta["ce"].lower()
        elif data.startswith(b"\x1f\x8b"):
            headers["content-encoding"] = "gzip"
        if meta.get("ETag"):
            headers["etag"] = meta["ETag"]
        if meta.get("LastModified"):
            headers["last-modified"] = meta["LastModified"]
        if not self.is_valid_cache_content(url, headers, data) or not any(k in headers for k in ("etag", "last-modified")):
            return None
        # Legacy files have no trustworthy freshness policy: validate once with origin.
        return {"headers": headers, "stored_at": time.time(), "expires_at": 0, "initial_age": 0}, data, "LEGACY"

    def _load(self, url):
        if config_manager.config.get("enable_ram_cache", True) and url in self._ram_cache:
            meta, data = self._ram_cache[url]
            self._ram_cache.move_to_end(url)
            return meta, data, "RAM"
        path = self._entry_path(url)
        if not path.is_file():
            return self._read_legacy(url)
        try:
            if path.stat().st_size > MAX_BODY_BYTES + MAX_META_BYTES + 10:
                return None
            with path.open("rb") as handle:
                if handle.read(len(MAGIC)) != MAGIC:
                    raise ValueError("invalid cache magic")
                length = struct.unpack("!I", handle.read(4))[0]
                if length > MAX_META_BYTES:
                    raise ValueError("oversized metadata")
                meta = json.loads(handle.read(length))
                data = handle.read(MAX_BODY_BYTES + 1)
            if (meta["version"] != 2 or meta["url"] != url or len(data) > MAX_BODY_BYTES
                    or meta["size"] != len(data) or meta["sha256"] != hashlib.sha256(data).hexdigest()
                    or not all(math.isfinite(meta[k]) for k in ("stored_at", "expires_at", "initial_age"))
                    or not self.is_valid_cache_content(url, meta["headers"], data)):
                raise ValueError("invalid cache entry")
            self._remember(url, meta, data)
            return meta, data, "DISK"
        except (OSError, ValueError, KeyError, TypeError, struct.error, EOFError, zlib.error, brotli.error):
            if config_manager.config.get("enable_auto_repair", True):
                path.unlink(missing_ok=True)  # Only our single entry, never the legacy source.
            return None

    def get_cache(self, url, request_headers=None, allow_stale=False):
        request_headers = request_headers or {}
        if not cacheable_request("GET", url, request_headers):
            return None
        if not allow_stale and wants_refresh(request_headers):
            return None
        with self._lock:
            try:
                result = self._load(url)
            except (OSError, ValueError, TypeError, AttributeError, EOFError, zlib.error, brotli.error):
                return None
            if result is None:
                return None
            meta, data, source = result
            now = time.time()
            if not allow_stale and now >= meta["expires_at"]:
                return None
            age = meta["initial_age"] + max(0, now - meta["stored_at"])
            if not allow_stale:
                requested = cache_control({k.lower(): v for k, v in request_headers.items()}.get("cache-control", ""))
                try:
                    if "max-age" in requested and age > max(0, int(requested["max-age"])):
                        return None
                    if "min-fresh" in requested and meta["expires_at"] - now < max(0, int(requested["min-fresh"])):
                        return None
                except ValueError:
                    return None
            headers = dict(meta["headers"])
            directives = cache_control(headers.get("cache-control", ""))
            if (config_manager.config.get("enable_browser_cache", False) and versioned_path(urllib.parse.urlsplit(url).path)
                    and now < meta["expires_at"] and "max-age" in directives and "no-cache" not in directives):
                if "immutable" not in directives:
                    headers["cache-control"] += ", immutable"
            headers.update({"age": str(int(age)),
                            "content-length": str(len(data)), "x-proxy-cache": "HIT", "x-cache-source": source})
            return headers, data

    def is_valid_cache_content(self, url, headers, data):
        if not _valid_headers(headers) or not data or len(data) > MAX_BODY_BYTES:
            return False
        fields = {k.lower(): v for k, v in headers.items()}
        if "text/html" in fields.get("content-type", "").lower():
            return False
        try:
            decoded = decode_body(data, fields.get("content-encoding", ""))
        except (ValueError, OSError, EOFError, zlib.error, brotli.error):
            return False
        return bool(decoded) and not decoded[:256].strip().lower().startswith((b"<!doctype html", b"<html", b"<head"))

    def save_cache(self, url, headers, data, request_headers=None):
        if not cacheable_request("GET", url, request_headers or {}) or not self.is_valid_cache_content(url, headers, data):
            return False
        fields = end_to_end_headers(headers)
        directives = cache_control(fields.get("cache-control", ""))
        vary = {x.strip() for x in fields.get("vary", "").lower().split(",") if x.strip()}
        if "private" in directives or "no-store" in directives or "set-cookie" in fields or vary - {"accept-encoding"}:
            return False
        for k in ("content-length", "x-proxy-cache", "x-cache-source"):
            fields.pop(k, None)
        now = time.time()
        meta = {"version": 2, "url": url, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "stored_at": now, "expires_at": _fresh_until(fields, now), "initial_age": _initial_age(fields, now), "headers": fields}
        temporary = None
        with self._lock:
            try:
                self._validate_base(self.cache_base)
                path = self._entry_path(url)
                packed = json.dumps(meta, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
                if len(packed) > MAX_META_BYTES:
                    return False
                path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".write-", suffix=".tmp", delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(MAGIC + struct.pack("!I", len(packed)) + packed + data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
                self._remember(url, meta, data)
                return True
            except (OSError, ValueError, TypeError):
                return False
            finally:
                if temporary is not None:
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        pass  # A locked orphan is not a committed entry and is never read.

    def invalidate(self, url):
        with self._lock:
            old = self._ram_cache.pop(url, None)
            if old:
                self._ram_cache_bytes -= len(old[1])
            try:
                self._entry_path(url).unlink(missing_ok=True)
            except OSError:
                pass

    def clear_all_cache(self):
        with self._lock:
            self.clear_ram_cache()
            deleted, freed = 0, 0
            root = (self.cache_base / "entries-v2").resolve()
            if not root.is_relative_to(self.cache_base):
                raise ValueError("cache path escapes configured directory")
            # Never recurse over arbitrary user files or remove the configured root.
            for path in root.glob("??/" + "?" * 64 + ".gbfcache"):
                if not path.resolve().is_relative_to(root) or path.is_symlink():
                    continue
                try:
                    with path.open("rb") as handle:
                        if handle.read(len(MAGIC)) != MAGIC:
                            continue
                    size = path.stat().st_size
                    path.unlink()
                    deleted, freed = deleted + 1, freed + size
                except OSError:
                    pass
            return deleted, freed


cache_manager = CacheManager()

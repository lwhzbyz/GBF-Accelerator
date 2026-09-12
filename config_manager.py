"""Configuration and explicit Windows certificate integration."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path


def get_base_dir():
    return Path(sys.executable if getattr(sys, "frozen", False) else __file__).parent.resolve()


def get_data_dir():
    return Path(os.environ.get("GBF_ACCELERATOR_DATA_DIR", get_base_dir())).resolve()


CONFIG_FILE = get_data_dir() / "config.json"
DEFAULT_CONFIG = {
    "listen_host": "127.0.0.1", "listen_port": 8124,
    "upstream_proxy": "direct", "cache_dir": "auto", "legacy_cache_dir": "",
    "auto_system_proxy": False, "enable_ram_cache": True, "ram_cache_max_mb": 256,
    "enable_browser_cache": False, "enable_auto_repair": True,
    "verify_upstream_tls": True, "max_response_mb": 64,
}
KNOWN_ACGPOWER_PATHS = [Path(f"{drive}:/{'acgpower/cache/gbf/https'}") for drive in "CDEF"]
PROBE_PROXY_PORTS = [(7897, "Clash Mixed"), (7890, "HTTP"), (10808, "Mixed"), (10809, "HTTP")]
LEGACY_CA_SHA1 = "51E9AA40A64FB8DC63F18F4B1A11B98D1CF8D3FF"


def is_port_open(host, port, timeout=0.3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def normalize_upstream(value):
    value = str(value or "direct").strip()
    if value.lower() == "direct":
        return "direct"
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https", "socks5", "socks5h") or not parsed.hostname:
        raise ValueError("上游必须是 direct 或 http(s)://、socks5(h):// 代理地址")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("上游代理地址不能包含路径、查询或片段")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("上游端口无效")
    return value


def auto_detect_upstream_proxy():
    # A listening port alone does not prove HTTP proxy support.
    for port, _ in PROBE_PROXY_PORTS:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3) as conn:
                conn.settimeout(0.5)
                conn.sendall(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                if conn.recv(32).startswith(b"HTTP/1."):
                    return f"http://127.0.0.1:{port}"
        except OSError:
            pass
    return "direct"


def auto_detect_acgpower_cache():
    base = get_base_dir()
    for path in [p / "cache/gbf/https" for p in (base, base.parent, base.parent.parent)] + KNOWN_ACGPOWER_PATHS:
        if (path / "assets").is_dir():
            return path
    return None


def check_upstream_connectivity(upstream_url):
    try:
        value = normalize_upstream(upstream_url)
        if value == "direct":
            return True, "直连系统网络（可由 UU 等加速器接管，是否覆盖需实测）"
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port or {"http": 80, "https": 443, "socks5": 1080, "socks5h": 1080}[parsed.scheme]
        with socket.create_connection((parsed.hostname, port), timeout=1.5):
            return True, "上游 TCP 端口可达；协议与认证将在连接时验证"
    except (OSError, ValueError) as exc:
        return False, f"上游连接检查失败：{exc}"


def _certutil(arguments):
    if sys.platform != "win32":
        return False
    try:
        result = subprocess.run(["certutil", *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _ca_thumbprint(path=None):
    from cert_manager import CA_CERT_PATH
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    try:
        cert = x509.load_pem_x509_certificate(Path(path or CA_CERT_PATH).read_bytes())
        return cert.fingerprint(hashes.SHA1()).hex().upper()
    except (OSError, ValueError):
        return None


def is_ca_installed():
    thumbprint = _ca_thumbprint()
    return bool(thumbprint and thumbprint != LEGACY_CA_SHA1 and _certutil(["-user", "-verifystore", "Root", thumbprint]))


def is_legacy_ca_installed():
    return _certutil(["-user", "-verifystore", "Root", LEGACY_CA_SHA1])


def remove_legacy_ca_certificate():
    if not is_legacy_ca_installed():
        return True
    return (_certutil(["-delstore", "-user", "Root", LEGACY_CA_SHA1])
            and not is_legacy_ca_installed())


def install_ca_certificate(ca_path, remove_legacy=False):
    thumbprint = _ca_thumbprint(ca_path)
    if not thumbprint or thumbprint == LEGACY_CA_SHA1:
        return False
    if is_legacy_ca_installed():
        if not remove_legacy or not remove_legacy_ca_certificate():
            return False
    return (_certutil(["-addstore", "-user", "Root", str(ca_path)])
            and _certutil(["-user", "-verifystore", "Root", thumbprint]))


def uninstall_ca_certificate():
    thumbprint = _ca_thumbprint()
    if not thumbprint:
        return False, "没有可识别的本机 CA 文件；不会按名称删除证书"
    success = (_certutil(["-delstore", "-user", "Root", thumbprint])
               and not _certutil(["-user", "-verifystore", "Root", thumbprint]))
    return success, "已移除当前 CA 的精确信任" if success else "移除失败或该 CA 未安装"


class ConfigManager:
    def __init__(self, config_path=None):
        self.config_path = Path(config_path or CONFIG_FILE)
        self.config = dict(DEFAULT_CONFIG)
        if self.config_path.is_file():
            with self.config_path.open(encoding="utf-8-sig") as handle:
                loaded = json.load(handle)
            if not isinstance(loaded, dict):
                raise ValueError("config.json 必须是 JSON 对象")
            self.config.update(loaded)

    def save_config(self):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.config_path.parent, delete=False) as handle:
                temporary = Path(handle.name)
                json.dump(self.config, handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.config_path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def get_listen_port(self):
        port = int(self.config.get("listen_port", 8124))
        if not 1 <= port <= 65535:
            raise ValueError("监听端口必须为 1 到 65535")
        return port

    def get_effective_cache_dir(self, interactive=False):
        raw = self.config.get("cache_dir", "auto")
        default = get_data_dir() / "cache"
        path = default if not raw or raw == "auto" else Path(raw)
        if not path.is_absolute():
            path = get_data_dir() / path
        # Prior releases stored an ACGP directory in cache_dir. Import it read-only.
        if (path / "assets").is_dir():
            if not self.config.get("legacy_cache_dir"):
                self.config["legacy_cache_dir"] = str(path.resolve())
            path = get_data_dir() / "download_cache"
        return path.resolve()

    def get_effective_legacy_cache_dir(self):
        raw = self.config.get("legacy_cache_dir")
        if not raw:
            return None
        path = Path(raw)
        return (path if path.is_absolute() else get_data_dir() / path).resolve()

    def get_effective_upstream_proxy(self):
        raw = self.config.get("upstream_proxy", "direct")
        return auto_detect_upstream_proxy() if raw == "auto" else normalize_upstream(raw)


config_manager = ConfigManager()

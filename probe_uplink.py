"""Opt-in public-resource probe. No browser state, OS proxy or root-store writes."""
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import ssl
import time

import httpx

ASSET_HOST = "prd-game-a-granbluefantasy.akamaized.net"
ASSET_PATH = "/assets/img/sp/spacer.png"


async def run_probe(output=None, hold=0):
    from config_manager import config_manager, get_data_dir
    from cert_manager import CA_CERT_PATH
    from cache_manager import CacheManager
    import gbf_proxy as proxy

    output = Path(output or get_data_dir() / "probe_result.json").resolve()
    if output.exists():
        raise ValueError("探测输出已存在，请指定一个新文件")
    # Never use the configured production or legacy cache for diagnostics.
    import tempfile
    get_data_dir().mkdir(parents=True, exist_ok=True)
    cache_path = Path(tempfile.mkdtemp(prefix="probe-cache-", dir=get_data_dir()))
    proxy.cache_manager = CacheManager(cache_path)
    proxy.cache_manager.set_legacy_base(None)
    proxy.LISTEN_HOST, proxy.LISTEN_PORT = "127.0.0.1", 0
    proxy.UPSTREAM_PROXY = config_manager.get_effective_upstream_proxy()
    result = {"started_utc": datetime.now(timezone.utc).isoformat(), "pid": os.getpid(),
              "uplink_scheme": proxy.UPSTREAM_PROXY.split(":", 1)[0],
              "data_dir": str(get_data_dir()), "cache_dir": str(cache_path),
              "dns": {}, "upstream_connections": [], "steps": [],
              "uu_attribution": "Requires independent process/connection evidence; HTTP success alone is insufficient."}
    task = asyncio.create_task(proxy.main())
    try:
        deadline = time.monotonic() + 8
        while not proxy.PROXY_STATS["is_running"]:
            if task.done():
                await task
            if time.monotonic() > deadline:
                raise TimeoutError("Local proxy did not start")
            await asyncio.sleep(0.05)
        port = proxy.proxy_server_instance.sockets[0].getsockname()[1]
        result["local_proxy_port"] = port

        async def record_upstream(response):
            stream = response.extensions.get("network_stream")
            record = {"host": response.request.url.host, "status": response.status_code}
            if stream:
                for key in ("client_addr", "server_addr"):
                    record[key] = stream.get_extra_info(key)
            result["upstream_connections"].append(record)
        proxy.http_client.event_hooks["response"] = [record_upstream]
        trust = ssl.create_default_context(cafile=str(CA_CERT_PATH))
        async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", trust_env=False,
                                     verify=trust, timeout=25, follow_redirects=False) as client:
            for host in (ASSET_HOST, "game.granbluefantasy.jp", "granbluefantasy.jp"):
                addresses = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                result["dns"][host] = sorted({entry[4][0] for entry in addresses})
            reference = None
            for index, label in enumerate(("miss_download", "ram_hit", "disk_hit")):
                if label == "disk_hit":
                    proxy.cache_manager.clear_ram_cache()
                previous = len(result["upstream_connections"])
                start = time.perf_counter()
                response = await client.get("https://" + ASSET_HOST + ASSET_PATH, headers={"Accept-Encoding": "identity"})
                source = response.headers.get("x-cache-source")
                step = {"name": label, "status": response.status_code, "bytes": len(response.content),
                        "source": source, "elapsed_ms": round((time.perf_counter() - start) * 1000, 2),
                        "upstream_requests": len(result["upstream_connections"]) - previous}
                result["steps"].append(step)
                response.raise_for_status()
                if not index:
                    reference = response.content
                    assert reference.startswith(b"\x89PNG\r\n\x1a\n") and step["upstream_requests"] == 1
                else:
                    assert response.content == reference and step["upstream_requests"] == 0
                    assert source == ("RAM" if index == 1 else "DISK")
            # A public, anonymous dynamic-path HEAD proves forwarding without any account APIs.
            response = await client.head("https://game.granbluefantasy.jp/favicon.ico")
            result["steps"].append({"name": "game_head_forward", "status": response.status_code})
            assert response.status_code < 500
            # This host is outside MITM: validate its real server certificate through raw CONNECT.
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", trust_env=False,
                                         verify=True, timeout=25, follow_redirects=False) as tunnel_client:
                response = await tunnel_client.head("https://granbluefantasy.jp/")
                result["steps"].append({"name": "raw_connect_tls_head", "status": response.status_code})
                assert response.status_code < 500
                result["network_steps_finished_utc"] = datetime.now(timezone.utc).isoformat()
                # Write the partial observation before holding so an external monitor can locate this PID.
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                if hold:
                    await asyncio.sleep(hold)
        result["passed"] = True
    except Exception as exc:
        result["passed"] = False
        result["error_type"] = type(exc).__name__
        # No exception text: upstream errors can embed proxy credentials or URL queries.
    finally:
        if proxy.proxy_stop_event:
            proxy.proxy_stop_event.set()
        await asyncio.gather(task, return_exceptions=True)
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        result["local_listener_stopped"] = proxy.proxy_server_instance is None
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        if __import__("sys").stdout is not None:
            print(f"Probe {'passed' if result.get('passed') else 'failed'}: {output}")
    return 0 if result.get("passed") else 1

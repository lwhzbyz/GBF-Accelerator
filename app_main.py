"""CLI entry point. System trust and PAC changes are explicit actions."""
import argparse
import asyncio
import os
import sys
import tempfile
from pathlib import Path

from network_policy import CDN_HOSTS

USAGE_TEXT = """GBF Accelerator 修复版

缓存命中由本机返回；未命中和动态请求经所选上游连接。
direct：使用系统网络，可配合覆盖本进程和目标地址的 UU 等加速器。
http://127.0.0.1:7890：使用提供 HTTP 代理端口的 Clash 等工具。
也支持 HTTPS 代理和 SOCKS5；不会从环境或 Windows 系统设置自动继承代理。

新下载保存在独立缓存目录；ACGP 来源是只读的，首次使用需要源站验证。
不修改游戏脚本，不模拟动态接口或 OPTIONS。
系统 PAC 默认关闭。首次浏览器接入需自行决定是否信任本机 CA；
命令行不会自动安装根证书。测试客户端可以只在自己的 SSLContext 中信任它。

查看 README.md 获取配置、UU 验证和已知限制说明。
"""


def get_pac_content(port=8124):
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid PAC port")
    exact = " ||\n        ".join(f'host === "{host}"' for host in sorted(CDN_HOSTS))
    return f'''function FindProxyForURL(url, host) {{
    host = host.toLowerCase();
    if (host === "granbluefantasy.jp" || dnsDomainIs(host, ".granbluefantasy.jp") ||
        host === "granbluefantasy.com" || dnsDomainIs(host, ".granbluefantasy.com") ||
        host === "mbga.jp" || dnsDomainIs(host, ".mbga.jp") ||
        {exact}) {{
        return "PROXY 127.0.0.1:{port}; DIRECT";
    }}
    return "DIRECT";
}}
'''


def update_pac_file(port=8124):
    from config_manager import get_data_dir
    destination = get_data_dir() / "proxy.pac"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(get_pac_content(port), encoding="utf-8")


def ensure_bundled_files():
    from config_manager import config_manager, get_data_dir
    update_pac_file(config_manager.get_listen_port())
    document = get_data_dir() / "使用说明.txt"
    if not document.exists():
        document.write_text(USAGE_TEXT, encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="GBF local cache proxy")
    parser.add_argument("--gui", action="store_true", help="打开图形界面")
    parser.add_argument("--autostart", action="store_true", help="打开界面并自动启动代理（供登录自启动使用）")
    parser.add_argument("--start-minimized", action="store_true", help="界面就绪后隐藏到托盘；启动失败时保留界面")
    parser.add_argument("--data-dir", type=Path, help="独立的配置、证书和缓存目录")
    parser.add_argument("--port", type=int)
    parser.add_argument("--upstream", help="direct / http(s):// / socks5(h)://")
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--legacy-cache-dir", type=Path, help="只读 ACGP 缓存目录")
    parser.add_argument("--probe", action="store_true", help="使用独立目录验证公共资源下载、缓存和直连隧道")
    parser.add_argument("--probe-output", type=Path, help="探测结果 JSON 文件（不记录 Cookie 或请求正文）")
    parser.add_argument("--probe-hold", type=int, default=0, help="探测连接后保留 0–60 秒以观察本机连接")
    parser.add_argument("--install-ca", action="store_true", help="明确请求安装当前 CA 到当前用户 Root")
    parser.add_argument("--remove-legacy-ca", action="store_true", help="明确请求移除已知公开私钥对应的旧 CA")
    args = parser.parse_args(argv)
    if not 0 <= args.probe_hold <= 60:
        parser.error("--probe-hold 必须为 0 到 60")
    if args.probe and not args.data_dir:
        args.data_dir = Path(tempfile.mkdtemp(prefix="gbf-uplink-probe-"))
    if args.data_dir:
        os.environ["GBF_ACCELERATOR_DATA_DIR"] = str(args.data_dir.resolve())
    from config_manager import config_manager, install_ca_certificate, remove_legacy_ca_certificate, is_legacy_ca_installed
    for field, value in (("listen_port", args.port), ("upstream_proxy", args.upstream),
                         ("cache_dir", args.cache_dir), ("legacy_cache_dir", args.legacy_cache_dir)):
        if value is not None:
            config_manager.config[field] = str(value) if isinstance(value, Path) else value
    config_manager.get_listen_port()
    config_manager.get_effective_upstream_proxy()
    if args.probe:
        from probe_uplink import run_probe
        raise SystemExit(asyncio.run(run_probe(args.probe_output, args.probe_hold)))
    if args.install_ca or args.remove_legacy_ca:
        from cert_manager import ensure_ca, CA_CERT_PATH
        if args.remove_legacy_ca and not remove_legacy_ca_certificate():
            raise SystemExit("旧 CA 移除失败")
        if args.install_ca:
            ensure_ca()
            if not install_ca_certificate(CA_CERT_PATH):
                raise SystemExit("CA 安装未完成；若仍有旧 CA，请先明确移除旧信任")
        return
    if args.gui or args.autostart or args.start_minimized or (getattr(sys, "frozen", False) and len(sys.argv) == 1):
        from gui_main import main as gui_main
        gui_main(autostart=args.autostart, start_minimized=args.start_minimized)
        return
    if is_legacy_ca_installed():
        print("[!] 检测到已知旧 CA 信任。请查看 README 的迁移说明；本次不会修改证书存储。")
    import gbf_proxy
    try:
        asyncio.run(gbf_proxy.main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

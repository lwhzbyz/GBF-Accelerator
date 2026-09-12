# GBF Accelerator · 缓存隔离修复版

碧蓝幻想公共静态资源的本地缓存代理。基于 Sagisawa/GBF-Accelerator 的 `6413c28` 修复；这里描述的是本分支源码及其构建物，不代表上游旧 Release 的行为。

缓存未命中时下载，后续在有效期内从 RAM 或磁盘返回。`direct` 使用系统网络，可以被覆盖本进程和目标地址的 UU 等加速器接管；也可填写 HTTP、HTTPS、SOCKS5 代理地址。

## 使用

Windows 10/11，开发和构建验证使用 Python 3.12。解压本分支构建的便携包，双击 `GBF_Accelerator.exe` 打开界面，检查配置后点击“启动加速”。默认监听 `127.0.0.1:8124`，默认上游 `direct`，不会自动启动服务、设置系统 PAC 或安装根证书。不要与其他程序共用数据目录。

- **新下载缓存目录**：选择本程序的独立目录。清空只处理这里 `entries-v2` 中本程序格式的条目。
- **ACGP 旧缓存来源**：可选的 `cache/gbf/https` 目录，只读使用。旧 `.ext` 的 MD5、编码和内容必须有效，并经源站条件验证后才使用；新记录写到新目录。不会逐个导入整个旧缓存。
- **上游**：UU 场景选择 `direct`。使用 Clash/v2rayN 等时填写其实际监听地址，例如 `http://127.0.0.1:7890`、`socks5://127.0.0.1:10808`。程序不继承环境变量或 Windows 代理，避免意外套用其他上游。自动探测按钮只填写候选地址，保存后生效。
- **浏览器入口**：在 ZeroOmega 等扩展中单独添加 PAC `http://127.0.0.1:8124/proxy.pac`；端口以实际配置为准。也提供可选系统 PAC；正常停止只恢复本次写入前的准确值，其他程序中途修改的值会保留。进程崩溃/强制结束时无法保证执行恢复。
- **HTTPS 信任**：浏览器需要信任这个数据目录中生成的本机 CA。界面显示 SHA-256 指纹，安装按钮会明确说明操作并请求确认。测试工具只在自身 SSLContext 中信任它，不需导入 Windows。不要分享 `certs/ca.key`，也不要在多个安装之间复用 CA 私钥。

使用已存在的 ACGP 时，可以保持 ACGP 的端口和缓存不动，先用独立测试客户端验证本程序。`SwitchyOmega_GBF.bak` 只是新配置模板；直接恢复扩展备份可能覆盖已有设置，建议手工添加独立 PAC 情景模式。

## UU 链路与验证

```text
浏览器或测试客户端 → 本机 GBF 缓存代理
                     ├─ 有效缓存命中 → 本地返回
                     └─ 未命中 / 动态请求 → direct → 系统路由 → UU（若覆盖）→ 源站
```

2026-09-12 在一台 Windows 主机的“碧蓝幻想网页版”加速状态下，已验证公共 CDN 下载、RAM/磁盘命中与游戏主机的匿名 HEAD 转发。实际连接选用了 **UU Wintun Tunnel** 网卡，UU 进程中有对应源端口的转发连接。命中请求没有上游访问。这证明该现场的 Wintun 模式可以接管本程序，不等于所有 UU 节点、模式或其他加速器都支持。

判断 UU 是否接管，应同时观察测试进程的连接、目标路由和 UU 进程的转发记录；UU 界面显示“正在加速”或 HTTP 200 本身都不足以证明。如果加速器只匹配浏览器进程，本程序的出站连接可能不在其范围内。这里没有通过伪装成浏览器或修改系统代理来强行接入。

可重复的探测（只访问公共图片、favicon HEAD 和官网 HEAD，无账号接口）：

```powershell
python app_main.py --probe --upstream direct --probe-output C:\GBF_test\probe.json
```

不指定 `--data-dir` 时自动创建独立临时数据目录，保留结果便于检查。`--probe-output` 必须为新文件。可加 `--probe-hold 35` 保留连接观察；Windows EXE 同样支持这些参数。退出码 0 表示探测断言通过，详细步骤在 JSON 中；其中的 UU 归属仍需结合本机连接证据判断。

## 缓存和转发规则

- 只缓存严格列出的 GBF 主机和静态路径/扩展名，键包含完整来源、路径和查询串。带 Cookie、Authorization、Range、敏感查询参数或不支持的条件请求绕过缓存。
- `private`、`no-store`、Set-Cookie 和无法正确区分的 Vary 响应不存储；多条 Set-Cookie 分别转发。共享连接池不保存或自动补发浏览器 Cookie。
- 遵守源站 Cache-Control、Age、Date、Expires。没有明确有效期但有 Last-Modified 时，以资源年龄的 10% 推算，最多 1 小时；无依据则每次重新验证。`no-cache` 及客户端刷新会到源站验证。
- 正文和元数据在同一文件中 `fsync` 后原子替换；URL 摘要用于内容寻址，正文摘要参与完整性校验。旧缓存始终不写入、不修复、不删除。
- 保留源站压缩表示；gzip/deflate/br 校验有解压大小上限。协商遵守 `q=0` 和 `no-transform`，变换编码时移除不再适用的 ETag/摘要，不改写 JavaScript 或补造 CORS。
- OPTIONS、动态接口和原来的错误上报路径交给上游处理。不承诺所有协议逐字节不变：HTTP/1.x 重新组帧、移除 hop-by-hop 头；非 MITM 主机通过 CONNECT 转发，支持原服务器 TLS 和常规 WebSocket 隧道。
- MITM 范围与证书 SAN 使用同一份严格主机列表，包含 `gbf.game.mbga.jp`。不使用宽泛的 Akamai 子串匹配。

限制：默认请求正文上限 32 MiB，上游响应缓冲上限 64 MiB（配置可调整至 512 MiB）；磁盘缓存无总容量自动淘汰。未完成真实账号、多人战、长时间负载或所有平台兼容测试。MITM 主机上的 WebSocket Upgrade 不支持；常规 `ws.*` 主机走原始 CONNECT。服务只允许回环监听，但没有本机客户端身份认证。

## 旧 CA 迁移

上游历史标签含有公开私钥对应的旧 CA。重新生成磁盘文件不能自动撤销已安装的旧信任。本分支按当前证书的实际指纹核对当前用户 Root，旧名称不会被当成安装成功。

已知旧 CA SHA-1：`51E9AA40A64FB8DC63F18F4B1A11B98D1CF8D3FF`。界面的安装/修复按钮会说明并单独处理这个精确对象，绝不按通用名称批量删除。命令行显式操作为：

```powershell
python app_main.py --data-dir C:\GBF_data --remove-legacy-ca --install-ca
```

这里管理当前用户 Root。若曾由管理员手动装到计算机 Root，需另行核对该存储；不要据当前用户安装成功推断其他存储已清理。本分支回归测试用内存证书存储替身，现场测试没有安装或删除任何 Windows 根证书。

## 开发、回归和构建

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
.\.venv\Scripts\python.exe app_main.py --gui --data-dir C:\GBF_data
.\.venv\Scripts\python.exe build_exe.py --output-dir C:\GBF_build
```

`requirements.txt` 固定直接运行依赖；`requirements-lock.txt` 固定本次 Windows/Python 3.12 构建环境的完整依赖（含 PyInstaller）。构建在新的子目录执行，不结束正在运行的程序，不打包本机 CA、缓存或 config.json。`build-info.json` 记录提交和工作区是否有改动。应在干净提交上构建交付包。

回归只用回环网络和独立临时文件，审计钩子禁止外网、真实注册表写入及子进程。覆盖 Cookie 隔离、缓存边界、旧缓存验证、原子提交故障、编码/解压限制、HTTP 组帧、真实 CONNECT/TLS、HTTP(S)/SOCKS5 上游、PAC 所有权及 CA 对应关系。`test_proxy.py` 是同一套离线回归入口，`debug_proxy.py` 是显式公共网络探测入口。

许可状态：上游固定提交没有 LICENSE 文件；已移除无文件支持的 MIT 徽章。本分支不擅自替上游补定许可证。

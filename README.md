# AegisTunnel VPN

Professional Android VPN and tunneling application inspired by the capabilities of HTTP Custom and DarkTunnel, featuring original cyber-security branding, high-fidelity Material 3 Jetpack Compose UI, and verified support for both 64-bit (`arm64-v8a`) and 32-bit (`armeabi-v7a`) ARM Android architectures.

---

## 1. Architecture Overview

AegisTunnel implements a modular multi-engine VPN architecture running over the standard Android `VpnService` with complete lifecycle state machine and upstream socket protection (`VpnService.protect()`).

```
 +---------------------------------------------------------------+
 |                     Android Device Traffic                     |
 +-------------------------------+-------------------------------+
                                 |
                                 v
                +---------------------------------+
                |   Android VpnService (tun0)     |  MTU 1500, 198.18.0.1/24
                +---------------------------------+
                                 |
                                 v
                +---------------------------------+
                |    HEV SOCKS5 Tunnel (C/lwIP)   |  tun2socks bridge
                +---------------------------------+
                                 |
                     +-----------+-----------+
                     |                       |
                     v (127.0.0.1:10808)     v (127.0.0.1:10809)
         +-----------------------+   +-----------------------+
         |    Xray Core (Go)     |   |   SSH Engine (JSch)   |
         |  VLESS / VMess / TLS  |   | HTTP Custom Injector  |
         | Trojan / Shadowsocks  |   | Payload / Bug Host    |
         +-----------+-----------+   +-----------+-----------+
                     |                           |
                     +-------------+-------------+
                                   | (VpnService.protect())
                                   v
                      Upstream Internet Gateway
```

### Supported Protocol Engines
1. **Xray Core Engine (`libv2ray.aar` / `libgojni.so`)**:
   - Protocols: VLESS, VMess, Trojan, Shadowsocks, SOCKS5.
   - Transports: TCP, WebSocket (WS), gRPC.
   - Security: TLS, Reality (`pbk`, `sid`, `fp`), none.
   - Sniffing & DNS routing.
2. **HEV SOCKS5 Tunnel (`hev-socks5-tunnel.aar` / `libhev-socks5-tunnel.so`)**:
   - High-performance, lightweight tun2socks packet forwarder written in C using a modified lwIP stack.
   - Directly converts raw IP packets from the Android TUN file descriptor into standard TCP/UDP SOCKS5 connections.
3. **SSH Engine (`com.github.mwiede:jsch`) with HTTP Custom Payload Injector**:
   - Upstream socket protection via `VpnService.protect()` to prevent routing loops.
   - In-process RFC 1928 SOCKS5 proxy server bridge.
   - Custom HTTP Injector payload formatting with macro substitution (`[host]`, `[port]`, `[host_port]`, `[crlf]`, `[protocol]`, `[ua]`) for custom bug host and ISP header injection.
   - Remote HTTP proxy tunneling.

---

## 2. ABI & Architecture Verification

AegisTunnel explicitly targets and verifies both ARM architectures:
- **`arm64-v8a`** (64-bit ARM)
- **`armeabi-v7a`** (32-bit ARM)

Native shared object files are packaged under both `lib/arm64-v8a/` and `lib/armeabi-v7a/`:
- `libgojni.so` (Xray Core native Go runtime)
- `libhev-socks5-tunnel.so` (HEV C/lwIP TUN forwarder)

### Verification Command
```bash
unzip -l app/build/outputs/apk/debug/app-debug.apk | grep -E "lib/(arm64-v8a|armeabi-v7a)"
```
Output:
```
33475728  lib/arm64-v8a/libgojni.so
  350976  lib/arm64-v8a/libhev-socks5-tunnel.so
32754404  lib/armeabi-v7a/libgojni.so
  239608  lib/armeabi-v7a/libhev-socks5-tunnel.so
```

---

## 3. Key Features

- **Connection Lifecycle State Machine**:
  `Disconnected` → `Validating` → `RequestingVpnPermission` → `StartingEngine` → `Connecting` → `Connected` → `Reconnecting` → `Stopping`.
- **Zero-Fake Guarantee**:
  - Never displays fabricated server pings, simulated speeds, or fake connection statuses.
  - Latency is measured by initiating an actual TCP socket handshake to the configured host and port.
- **Privacy & Redacted Logging**:
  - In-memory circular log buffer.
  - Automatically redacts passwords, tokens, private keys, and UUIDs using regular expression filters.
  - Zero analytics or traffic logging.
- **DNS & IPv6 Leak Isolation**:
  - Secure tunnel DNS resolver selection (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9, AdGuard, Custom).
  - Strict IPv6 isolation to prevent dual-stack leakage outside the tunnel.
  - Optional LAN subnet bypass (192.168.0.0/16, 10.0.0.0/8).
- **Import & Export**:
  - Supports clipboard & file import for `vmess://`, `vless://`, `trojan://`, `ss://`, `ssh://`, and standard Xray JSON outbounds.
  - Share and export profile configurations to clipboard or Android Share Sheet.

---

## 4. Building and Testing

### Build APK
```bash
gradle :app:assembleDebug
```

### Run Unit and Robolectric Tests
```bash
gradle :app:testDebugUnitTest
```
Tests cover:
- `ConfigParser` (VLESS, Trojan, VMess, SSH, raw JSON)
- `ConfigParser` error handling & syntax validation
- `PayloadInjector` macro string replacement
- `AppLogger` credential and token redaction
- `XrayEngineAdapter` JSON configuration schema generation
- `VpnState` transition properties
- Robolectric resource verification

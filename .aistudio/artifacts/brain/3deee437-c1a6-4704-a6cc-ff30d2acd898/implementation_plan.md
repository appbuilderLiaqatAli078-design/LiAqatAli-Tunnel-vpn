# Custom Tunnel Pro — V2Ray (VLESS / VMess / Trojan / Shadowsocks) Connection & Anti-Brick Fix Plan

## 1. Root Cause Summary (From User Engine Logs Screenshot)
In the user's screenshot (`VLESS [net=ws, sec=tls]` on Cloudflare IP `141.193.213.10, 141.193.213.11` over `H+` mobile data), Xray Core started (`status: 0 - Started successfully, running`), but failed 7 seconds later with:
`Outbound probe to http://cp.cloudflare.com/generate_204 failed: Get "http://cp.cloudflare.com/generate_204": io: read/write on closed pipe`

This occurred due to three interacting issues in `XrayEngineAdapter.kt`:
1. **`routing.domainStrategy = "IPIfNonMatch"` + `sockopt.domainStrategy = "UseIP"` Circular/UDP DNS Failure**:
   - `"IPIfNonMatch"` forced Xray to resolve `cp.cloudflare.com` locally via its internal `dns-in` module (UDP port 53 routed over the WebSocket proxy via XUDP) **before** sending the HTTP request.
   - Cloudflare-fronted VLESS/VMess WebSocket servers (`141.193.213.10`) drop or close UDP/XUDP streams, and `"UseIP"` on `proxyOutbound` caused Xray's dialer to invoke `dns-in` (which itself routed through `proxy`), closing the internal pipe with `io: read/write on closed pipe`.
2. **WebSocket Early Data (`?ed=2048` / `?ed=2560`) & Host Header Handling**:
   - Many Cloudflare VLESS/VMess configs append `?ed=2048` or `?ed=2560` to the WebSocket path. Passing `?ed=2048` raw without extracting `maxEarlyData` / `earlyDataHeaderName` or sending duplicate `host` fields in `wsSettings` can cause certain Xray/v2fly and Cloudflare Worker endpoints to reset the WebSocket stream.
3. **Hard-Failing the Connection on Startup Ping (`verifyTunnelConnectivity`)**:
   - `verifyTunnelConnectivity()` threw an `IllegalStateException` and killed the entire VPN session whenever the startup ping (`measureDelay` / HTTP 204 probe) timed out or failed on slow `H+` mobile networks—even when the Xray engine and HEV tunnel were running and valid.

---

## 2. Planned Changes

### A. Switch Xray Routing & Outbound Domain Strategy to `"AsIs"` (`XrayEngineAdapter.kt`)
- Set `routing.domainStrategy` to **`"AsIs"`** and `proxyOutbound.streamSettings.sockopt.domainStrategy` to **`"AsIs"`**.
- Remove the circular `dns-in -> proxy` routing trap so Xray sends target hostnames directly inside the VLESS/VMess/Trojan TCP stream for the remote V2Ray server to resolve immediately (matching v2rayNG and HTTP Custom behavior).
- Keep `socks-in` sniffing (`http`, `tls`, `quic`) with `routeOnly: true` so TLS SNI and HTTP Host headers are preserved intact without forcing local DNS resolution.

### B. WebSocket Early Data (`?ed=`), TLS ALPN, and Multi-IP Fallback (`XrayEngineAdapter.kt` & `ConfigParser.kt`)
- **WebSocket `?ed=` Parsing**: Automatically detect `?ed=N` (e.g., `?ed=2048` or `?ed=2560`) in WebSocket paths, strip `?ed=N` from the base HTTP path if needed or configure `maxEarlyData` and `earlyDataHeaderName = "Sec-WebSocket-Protocol"` properly in `wsSettings`, and set `headers: { "Host": effectiveWsHost }` cleanly.
- **URL-Decoded Query Parameters (`ConfigParser.kt`)**: Ensure `path`, `sni`, `host`, and `serviceName` in `vless://`, `vmess://`, and `trojan://` URIs are properly URL-decoded (e.g. `%2F` -> `/`, `%3Fed%3D2048` -> `?ed=2048`) and trimmed of accidental whitespace.
- **CDN / Cloudflare Server Address Handling**: If `profile.server` is a domain and `sni`/`wsHost` are blank, preserve the original domain for TLS `serverName` and WS `Host` even if pre-resolved IPs are logged.

### C. Non-Bricking Connectivity Check + SOCKS5 Fallback Probe (`XrayEngineAdapter.kt` & `SshEngineAdapter.kt`)
- **Start HEV Tunnel First & Keep VPN Alive**:
  - Start the Xray loop and attach the HEV TUN-to-SOCKS5 forwarder (`127.0.0.1:10808`) immediately so the tunnel is live right away.
  - Perform a lightweight non-blocking probe first via the local SOCKS5 port (`127.0.0.1:10808` HTTP `generate_204`) with fallback to `controller.measureDelay`.
  - **Never Brick Valid Servers**: If the probe succeeds, log the RTT in ms (`Outbound tunnel verified (RTT: Xms)`). If the probe is slow, blocked by the ISP, or fails on `H+` mobile data while the Xray core loop is actively running, **log a warning (`[WARN] Startup ping check timed out or blocked by network — keeping tunnel connected`) and keep the VPN connected** instead of throwing an exception and disconnecting the user.

---

## 3. Verification Plan
1. Update unit tests in `ExampleUnitTest.kt` to verify `"AsIs"` routing strategy, URL-decoded VLESS/VMess paths (`?ed=2048`), and non-bricking connection behavior.
2. Run `compile_applet` and `gradle :app:testDebugUnitTest` to confirm zero build or test errors.

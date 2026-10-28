# Implementation Plan — VMess Multi-Format Parser Fix, Codebase Audit & Full Custom Tunnel Pro Branding

## 1. Fix VMess Configuration Parser (`ConfigParser.kt`)
Currently, `ConfigParser.parseVmess()` assumes every `vmess://` link is a Base64-encoded JSON object (`JSONObject(decoded)`). When importing links such as the one in your screenshot:
```
vmess://djp2bWVzC0BnZwVrc3Zwbi5rZXZpbnRlY2h0dXRvcmlhbHMuZnVuOjQ0Mz90eXBlPXdzJnBhdGg9L3ZtZXNzJnNlY3VyaXR5PXRscyZ1dWlkPWE0ODFjYzVlLTBlZGYtNDFiYy04NTQwLWM2ODRiMjYwMDk2Mg==
```
the Base64 payload decodes to a URI/query string (`v:vmess...@geeksvpn.kevintechtutorials.fun:443?type=ws&path=/vmess&security=tls&uuid=a481cc5e-0edf-41bc-8540-c684b2600962`), which causes `JSONObject` to fail with `Value v of type java.lang.String cannot be converted to JSONObject`.

### What We Will Change:
- **Multi-Format `parseVmess()` Support**:
  1. **v2rayNG JSON Base64 Format**: When the decoded Base64 string starts with `{`, parse the JSON fields (`add`, `port`, `id`, `aid`, `scy`, `net`, `type`, `host`, `path`, `tls`, `sni`, `alpn`, `fp`, `ps`).
  2. **Base64-Encoded URI / Query-Param Format (Screenshot Format)**: When `vmess://<base64>` decodes to a URI-style string (`[prefix]@host:port?type=ws&path=/vmess&security=tls&uuid=...#remark` or `cipher:uuid@host:port?...`), sanitize any non-printable control characters, extract the server host, port, UUID (from `uuid`/`id` query param or userinfo), network transport (`type`/`net`/`obfs`), WebSocket path (`path`), TLS/security (`security`/`tls`), SNI (`sni`/`peer`), Host header (`host`/`obfsParam`), ALPN, fingerprint, and profile name.
  3. **Standard Xray / V2Ray Plain URI Format**: Support direct `vmess://uuid@host:port?type=ws&security=tls&path=/vmess&sni=...#name` links without Base64 encoding.
  4. **Shadowrocket Mixed Format**: Support `vmess://<base64(cipher:uuid@host:port)>?obfs=websocket&path=/vmess&tls=1&obfsParam=...#remark`.
- **Whitespace & Multi-Line Normalization**: Strip accidental line breaks or spaces inside pasted Base64 payloads across `vmess://`, `vless://`, `trojan://`, `ss://`, `ssh://`, and `.ctp` imports.
- **Import Screen Format Badges**: Add `VMess` alongside `VLESS`, `Trojan`, and `SSH` in the quick-fill/supported formats section of `ImportScreen.kt`.

---

## 2. Complete Removal of Legacy "Aegis" Naming Across Code, UI & Logs
All remaining references to `Aegis`, `AegisVPN`, and `AegisTunnel` will be cleanly migrated to **Custom Tunnel Pro**:
- **Theme & UI (`Theme.kt`, `Color.kt`, `MainActivity.kt`, `ProfileEditScreen.kt`)**:
  - Rename `AegisTunnelTheme` to `CustomTunnelProTheme`.
  - Update default proxy User ID placeholder from `"aegis"` to `"customtunnel"` in `ProfileEditScreen.kt`, `SshProxyHandler.kt`, and `SshSocketFactory.kt`.
- **VPN Service & Engine (`AegisVpnService.kt` & Engine Adapters)**:
  - Update `TAG` to `"CustomTunnelVpnService"`, notification channel ID to `"ctp_vpn_status_channel"`, and all log messages to reference `CustomTunnelVpnService`.
- **Parser & Settings (`ConfigParser.kt`, `SettingsRepository.kt`)**:
  - Update JSON error messages and comments from `"Aegis profile schema"` to `"Custom Tunnel Pro profile schema"`.
  - Migrate `SettingsRepository` SharedPreferences cleanly while preserving existing user settings if already saved.

---

## 3. Codebase Overview & Verification
- Add unit tests in `ExampleUnitTest.kt` and `ExampleRobolectricTest.kt` verifying:
  - The exact `vmess://` URI from your screenshot parses into a valid `VpnProfile` with host `geeksvpn.kevintechtutorials.fun`, port `443`, UUID `a481cc5e-0edf-41bc-8540-c684b2600962`, transport `ws`, path `/vmess`, and security `tls`.
  - Standard v2rayNG JSON `vmess://`, plain `vmess://`, and Shadowrocket `vmess://` formats all parse and generate valid Xray outbound configurations.
- Run `compile_applet` and `gradle :app:testDebugUnitTest` to verify zero compilation or test errors.

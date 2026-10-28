# Custom Tunnel Pro — Glitch/Loop Audit Fixes, Zero-Drain Battery Optimization & Interactive Liquid Wave Plan

## 1. Overview & Strict Safety Guarantees
This update resolves the confirmed background loops, race conditions, and UI glitches found during the codebase audit, significantly boosts battery life (0 FPS idle UI rendering and throttled background notification IPC), and introduces an **interactive finger-swipe liquid wave effect inside the main Connect button and Status/Profile card** that automatically sleeps at **0 FPS** when your finger is lifted.
- **No Removed Features**: All existing VPN engines (Xray-Core VLESS/VMess/Trojan/Shadowsocks, SSH, HevSocks5Tunnel), `.ctp` encryption/locks, profiles, logs, and settings remain 100% intact.

---

## 2. Glitch, Loop & Race Condition Fixes

### A. Always-On 60/120 FPS Animation Loop & Button Label Glitch (`VpnComponents.kt`)
- **Problem**: `rememberInfiniteTransition` inside `ConnectButton` was initialized unconditionally at the top of the composable, causing Android to render animation frames at 60–120 FPS continuously even when the VPN was idle or already connected. Additionally, the button label displayed `"STOPPING"` for all `state.isBusy` states (including `Validating`, `StartingEngine`, and `Connecting`).
- **Fix**:
  - Move the pulse `rememberInfiniteTransition` strictly inside `if (state.isBusy)` so zero animation frames run when idle or connected.
  - Fix the `ConnectButton` label so `VpnState.Stopping` shows `"STOPPING"`, while `Validating`, `StartingEngine`, `Connecting`, `TunnelEstablished`, and `Reconnecting` show `"CONNECTING..."`.

### B. 1-Second System Notification IPC Wakeup Loop (`CustomTunnelVpnService.kt`)
- **Problem**: `startStatsLoop()` called `NotificationManager.notify()` every 1 second (`1000ms`), waking up Android's `system_server` and SystemUI process continuously in the background and lacked `setOnlyAlertOnce(true)`.
- **Fix**:
  - Add `.setOnlyAlertOnce(true)` and `.setSilent(true)` to `NotificationCompat.Builder`.
  - Keep in-app `StateFlow` traffic stats smooth while throttling system notification bar updates to every 5 seconds (and only when speeds or state actually change), drastically reducing background battery drain.

### C. Async Engine Teardown Race Condition (`CustomTunnelVpnService.kt`)
- **Problem**: `cleanup()` launched `serviceScope.launch { currentEngine?.stop(); currentEngine = null }` asynchronously, which could race with a fast reconnect and null out or stop the newly created `currentEngine`.
- **Fix**:
  - Capture `val engineToStop = currentEngine` and set `currentEngine = null` synchronously before launching the coroutine to stop `engineToStop`.
  - Unregister `networkCallback` cleanly inside `onDestroy()` to prevent leaked `ConnectivityManager` callbacks.

### D. SSH SOCKS5 Channel Memory Leak & Handshake Stream Ordering (`SshEngineAdapter.kt`)
- **Problem**: `activeChannels` (`CopyOnWriteArrayList<ChannelDirectTCPIP>`) accumulated every TCP connection over a session without removing closed channels until disconnect, and bound `clientSocket` streams to JSch before writing the SOCKS5 success header (`0x05, 0x00...`).
- **Fix**:
  - Prune closed/disconnected channels (`activeChannels.removeAll { it.isClosed || !it.isConnected }`) whenever a new SOCKS5 channel is opened.
  - Connect the remote `direct-tcpip` channel, send and flush the SOCKS5 success response first, and then attach the client input/output streams so remote server bytes never interleave with the SOCKS5 reply header.

---

## 3. Interactive Zero-Drain Liquid Wave UI (`VpnComponents.kt` & `HomeScreen.kt`)
- **Touch & Swipe Reactive Physics**:
  - Inside both the circular **Connect Button orb** and the **Active Profile / Status Card** on `HomeScreen`, add a custom `Canvas`-drawn dual-sine liquid wave layer (`InteractiveLiquidSurface`).
  - **Finger Drag / Swipe Detection**: Swiping or dragging a finger across the Connect Button or Status Card injects wave velocity, tilt, and ripple amplitude proportional to finger movement (`pointerInput` drag/touch gesture without blocking normal taps/clicks).
  - **Smart Zero-Drain Sleep (0 FPS when idle)**:
    - A coroutine animation loop (`withFrameNanos`) runs **only** when triggered by a touch/swipe or connection state transition, smoothly damping wave energy back to rest over ~1.2 seconds and then **terminating the loop completely (0 FPS, 0% CPU/GPU usage)** until the next touch.

---

## 4. Verification Plan
1. Compile the project using `compile_applet` to ensure zero build or lint issues.
2. Run unit tests (`gradle :app:testDebugUnitTest`) to verify all parser, branding, and regression tests pass.

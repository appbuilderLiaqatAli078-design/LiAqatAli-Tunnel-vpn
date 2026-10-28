# Custom Tunnel Pro — Security, `.ctp` Config Format & Profile Persistence Plan

## 1. Persistent Selected Profile Across App Restarts
- **Root Cause Found**: `VpnViewModel` currently keeps `selectedProfile` only in memory and falls back to `list.first()` whenever the app process is recreated by Android after a few hours in the background.
- **Fix**:
  - Persist `selectedProfileId` on disk whenever the user selects, saves, or imports a profile.
  - On app launch or process recreation, restore the exact previously selected profile by ID (or sync with the active running VPN tunnel profile if connected), only falling back to the first profile if the saved profile was deleted.

## 2. Complete Host Masking Outside Profile Editor
- **Strict Dot Masking (`••••••••••••`)**:
  - Mask server hostnames, IP addresses, SNI, and proxy endpoints as `••••••••••••` across the **Home Screen** active profile card, **Profiles List** cards, **Ping / Diagnostic Logs**, and **VPN Status Notifications**.
  - **Editor Visibility Rules**:
    - For unlocked profiles created by the user, show the real host and credentials inside the **Edit Profile** screen so they can be edited normally.
    - For locked imported `.ctp` profiles, block viewing or copying the host, payload, and credentials in the Editor unless the user unlocks the profile with the creator's unlock password (if enabled).

## 3. Custom `.ctp` Encrypted Configuration Format & Export Security Dialog
- **Custom `.ctp` File Extension**:
  - Export and import files with the `.ctp` extension (`Custom Tunnel Pro` format).
  - Register `.ctp` file associations in `AndroidManifest.xml` so tapping a `.ctp` file in Telegram, WhatsApp, or any File Manager opens and imports directly into Custom Tunnel Pro.
- **User-Selectable Export Locks (Export Dialog)**:
  - **Lock Config (Hide from Editor)**: Prevents recipients from viewing or editing the server host, port, SSH credentials, UUID, or custom HTTP/WebSocket payload.
  - **Expiration Date Lock**: Optional expiry date/time after which the imported `.ctp` profile refuses to connect.
  - **Optional Unlock Password**: Allows the creator to set a password required to import or unlock the configuration in the editor.
  - **Hardware ID (HWID) Lock**: Optional binding to a target device's Hardware ID, plus a quick **Copy My HWID** helper in the app so users can send their HWID to the config creator.
  - **Block Rooted Devices**: Optional toggle on exported `.ctp` files that prevents connection or import on rooted devices.
  - **Custom Creator Note / Message**: Optional locked banner message (e.g., creator branding or support link) shown on the profile card.

## 4. Root-Resistant Encryption & App Source Protection
- **Authenticated `.ctp` Container Encryption**:
  - Encrypt `.ctp` payloads using **AES-256-GCM** with **PBKDF2-HMAC-SHA256** key derivation combining an obfuscated multi-part key, the app's package/signing certificate fingerprint verification, and any optional user unlock password, with tamper-evident header integrity checks.
- **Encrypted Local Profile Storage**:
  - Encrypt `vpn_profiles.json` at rest using Android Keystore AES-GCM so even someone with root access inspecting `/data/data/com.customtunnelpro.vpn/files/` cannot read saved hosts, passwords, or imported `.ctp` configs in plaintext.
- **Anti-Tamper, Root & R8/ProGuard Hardening**:
  - Add comprehensive R8/ProGuard obfuscation rules (`proguard-rules.pro`) to strip debug symbols and obfuscate critical security, crypto, and parser classes.
  - Add runtime root and debugger/hook detection checks to enforce root-locked `.ctp` profiles and prevent runtime credential dumping.

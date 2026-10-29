package com.example.model

enum class ProtocolType(val displayName: String, val badgeColorHex: Long) {
    VMESS("VMess", 0xFF6366F1),
    VLESS("VLESS", 0xFF00E5FF),
    TROJAN("Trojan", 0xFFEC4899),
    SHADOWSOCKS("Shadowsocks", 0xFFF59E0B),
    SOCKS5("SOCKS5", 0xFF10B981),
    SSH("SSH Direct / Injector", 0xFF8B5CF6)
}

enum class LogLevel {
    DEBUG, INFO, WARN, ERROR
}

data class LogEntry(
    val id: Long = System.nanoTime(),
    val timestamp: Long = System.currentTimeMillis(),
    val level: LogLevel = LogLevel.INFO,
    val tag: String,
    val message: String
)

data class TrafficStats(
    val bytesIn: Long = 0L,
    val bytesOut: Long = 0L,
    val speedInBytesPerSec: Long = 0L,
    val speedOutBytesPerSec: Long = 0L,
    val packetsIn: Long = 0L,
    val packetsOut: Long = 0L
)

sealed class VpnState {
    object Disconnected : VpnState()
    data class Validating(val message: String = "Validating configuration...") : VpnState()
    object RequestingVpnPermission : VpnState()
    data class StartingEngine(val engineName: String) : VpnState()
    data class Connecting(val profileName: String, val attempt: Int = 1) : VpnState()
    data class TunnelEstablished(
        val profileName: String,
        val detail: String = "Tunnel established, verifying internet..."
    ) : VpnState()
    data class Connected(
        val profileName: String,
        val connectedSince: Long,
        val engineName: String,
        val isInternetVerified: Boolean = true,
        val verificationDetail: String = "Internet Verified",
        val rttMs: Long? = null
    ) : VpnState()
    data class Reconnecting(
        val attempt: Int,
        val maxAttempts: Int,
        val nextRetryInSeconds: Int
    ) : VpnState()
    object Stopping : VpnState()
    data class Error(
        val message: String,
        val code: String? = null,
        val timestamp: Long = System.currentTimeMillis()
    ) : VpnState()

    val isConnected: Boolean get() = this is Connected
    val isBusy: Boolean get() = this is Validating || this is StartingEngine || this is Connecting || this is TunnelEstablished || this is Reconnecting || this is Stopping
}

enum class SshTunnelMode(
    val displayName: String,
    val badge: String,
    val description: String
) {
    DIRECT("SSH Direct", "DIRECT", "Direct SSH server connection"),
    HTTP_PROXY("SSH HTTP Proxy", "HTTP", "SSH connection through an HTTP proxy"),
    HTTP_CONNECT("SSH HTTP CONNECT", "CONNECT", "Standard RFC 2817 HTTP CONNECT proxy tunnel"),
    CUSTOM_PAYLOAD("SSH Custom Payload", "PAYLOAD", "Custom HTTP injector payload with headers and macros"),
    SSL_TLS("SSH SSL / TLS", "TLS", "SSH over SSL/TLS transport with SNI"),
    WEBSOCKET("SSH WebSocket (WS)", "WS", "SSH over WebSocket HTTP Upgrade transport"),
    SECURE_WEBSOCKET("SSH Secure WebSocket (WSS)", "WSS", "SSH over TLS-encrypted WebSocket transport"),
    SSL_WEBSOCKET("SSH + TLS + WebSocket", "TLS+WS", "Combined TLS, WebSocket, and SSH transport"),
    SOCKS4("SSH SOCKS4 Proxy", "SOCKS4", "SSH connection through an outbound SOCKS4 proxy"),
    SOCKS5("SSH SOCKS5 Proxy", "SOCKS5", "SSH connection through an outbound SOCKS5 proxy with auth"),
    PROXY_CHAIN("SSH Proxy Chaining", "CHAIN", "Multi-hop proxy chain before reaching the SSH server"),
    LOCAL_PORT_FORWARDING("SSH Local Port Forwarding", "PORT-L", "Local TCP port forwarding through SSH"),
    REMOTE_PORT_FORWARDING("SSH Remote Port Forwarding", "PORT-R", "Remote TCP port forwarding from SSH server"),
    DYNAMIC_PORT_FORWARDING("SSH Dynamic SOCKS Forwarding", "DYNAMIC", "Local SOCKS5 proxy routed through SSH tunnel")
}

data class VpnProfile(
    val id: String,
    val name: String,
    val protocol: ProtocolType,
    val server: String,
    val port: Int,
    val password: String = "", // UUID for VMess/VLESS, password for Trojan/Shadowsocks/SSH
    val security: String = "none", // none, tls, reality
    val network: String = "tcp", // tcp, ws, grpc, httpupgrade, xhttp, h2, kcp
    val path: String = "",
    val sni: String = "",
    val wsHost: String = "", // HTTP / WebSocket Host header when distinct from TLS SNI
    val headerType: String = "none", // none, http (for TCP HTTP header obfuscation)
    val grpcMode: String = "gun", // gun, multi
    val grpcAuthority: String = "",
    val publicKey: String = "",
    val shortId: String = "",
    val spiderX: String = "", // REALITY spiderX (spx)
    val fingerprint: String = "chrome",
    val alpn: String = "",
    val flow: String = "",
    val encryption: String = "none",
    // SSH Specific
    val sshUsername: String = "",
    val sshPayload: String = "", // e.g. CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]
    val proxyHost: String = "",
    val proxyPort: Int = 0,
    val sshMode: SshTunnelMode = SshTunnelMode.DIRECT,
    val sshPrivateKey: String = "",
    val sshPassphrase: String = "",
    val sshProxyUser: String = "",
    val sshProxyPass: String = "",
    val sshSni: String = "",
    val sshWsPath: String = "/ssh",
    val sshCustomHeaders: String = "",
    val sshChainProxyHost: String = "",
    val sshChainProxyPort: Int = 0,
    val sshChainProxyType: String = "SOCKS5", // HTTP or SOCKS5
    val sshLocalForwardPort: Int = 10880,
    val sshRemoteForwardHost: String = "127.0.0.1",
    val sshRemoteForwardPort: Int = 80,
    val sshRemoteListenPort: Int = 8080,
    val allowInsecureSsl: Boolean = false,
    // Routing & DNS
    val dnsPrimary: String = "1.1.1.1",
    val dnsSecondary: String = "8.8.8.8",
    val blockIpv6: Boolean = true,
    val perAppProxy: Boolean = false,
    val selectedApps: List<String> = emptyList(),
    val lastPingMs: Long? = null,
    val createdAt: Long = System.currentTimeMillis(),
    // .ctp Security & Lock Properties
    val isLocked: Boolean = false,
    val lockPasswordHash: String = "",
    val expiresAtMillis: Long = 0L,
    val lockedHwid: String = "",
    val blockRoot: Boolean = false,
    val creatorMessage: String = ""
) {
    val maskedEndpoint: String
        get() = "••••••••••••"

    val isExpired: Boolean
        get() = expiresAtMillis > 0L && System.currentTimeMillis() > expiresAtMillis
}

data class AppSettings(
    val theme: String = "system",
    val autoReconnect: Boolean = true,
    val maxRetries: Int = 5,
    val proMode: Boolean = true,
    val defaultDns: String = "1.1.1.1",
    val customDns: String = "8.8.8.8",
    val blockIpv6ByDefault: Boolean = true,
    val bypassLan: Boolean = true
)

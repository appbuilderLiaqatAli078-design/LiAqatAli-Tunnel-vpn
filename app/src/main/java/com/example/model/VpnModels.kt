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
    data class Connected(
        val profileName: String,
        val connectedSince: Long,
        val engineName: String
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
    val isBusy: Boolean get() = this is Validating || this is StartingEngine || this is Connecting || this is Reconnecting || this is Stopping
}

data class VpnProfile(
    val id: String,
    val name: String,
    val protocol: ProtocolType,
    val server: String,
    val port: Int,
    val password: String = "", // UUID for VMess/VLESS, password for Trojan/Shadowsocks/SSH
    val security: String = "none", // none, tls, reality
    val network: String = "tcp", // tcp, ws, grpc
    val path: String = "",
    val sni: String = "",
    val publicKey: String = "",
    val shortId: String = "",
    val fingerprint: String = "chrome",
    val alpn: String = "h2,http/1.1",
    val flow: String = "",
    // SSH Specific
    val sshUsername: String = "",
    val sshPayload: String = "", // e.g. CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]
    val proxyHost: String = "",
    val proxyPort: Int = 0,
    // Routing & DNS
    val dnsPrimary: String = "1.1.1.1",
    val dnsSecondary: String = "8.8.8.8",
    val blockIpv6: Boolean = true,
    val perAppProxy: Boolean = false,
    val selectedApps: List<String> = emptyList(),
    val lastPingMs: Long? = null,
    val createdAt: Long = System.currentTimeMillis()
)

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

package com.example.vpn.engine

import android.util.Base64
import com.example.data.AppLogger
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.vpn.CustomTunnelVpnService
import go.Seq
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.InetAddress

class XrayEngineAdapter : VpnEngineAdapter {
    private val TAG = "XrayEngine"
    private var coreController: CoreController? = null
    private var activeProfile: VpnProfile? = null
    @Volatile
    private var isEngineRunning = false
    @Volatile
    private var lastConnectivityResult: ConnectivityCheckResult? = null
    private val localSocksPort = 10808

    companion object {
        @Volatile
        private var assetsPreparedForDir: String? = null
    }

    override fun getEngineName(): String = "Xray Core Engine"
    override fun getLocalSocksPort(): Int = localSocksPort
    override fun isRunning(): Boolean = isEngineRunning
    override fun getLastConnectivityResult(): ConnectivityCheckResult? = lastConnectivityResult

    override suspend fun start(
        profile: VpnProfile,
        vpnService: CustomTunnelVpnService,
        tunFd: Int
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            validateProfile(profile)
            activeProfile = profile
            lastConnectivityResult = null

            if (tunFd < 0) {
                throw IllegalStateException("Invalid TUN file descriptor: $tunFd")
            }

            AppLogger.i(TAG, "Preparing Xray Core environment and assets")
            try {
                Seq.setContext(vpnService.applicationContext)
            } catch (e: Throwable) {
                AppLogger.w(TAG, "Seq.setContext warning: ${e.message}")
            }
            setupAssets(vpnService)

            val assetPath = vpnService.filesDir.absolutePath
            val xudpKeyFile = File(vpnService.filesDir, ".xray.xudp.basekey")
            if (xudpKeyFile.exists() && xudpKeyFile.length() != 43L) {
                xudpKeyFile.delete()
            }
            val xudpBaseKey = getDeviceIdForXUDPBaseKey()
            Libv2ray.initCoreEnv(assetPath, xudpBaseKey)

            val resolvedIps = resolveServerAddresses(profile.server)
            if (resolvedIps.isNotEmpty()) {
                AppLogger.i(TAG, "Pre-resolved ${profile.server} -> ${resolvedIps.joinToString(", ")}")
            }

            val configJson = buildXrayConfig(profile, localSocksPort, resolvedIps)
            AppLogger.i(
                TAG,
                "Generated Xray configuration for protocol: ${profile.protocol.displayName} " +
                    "[net=${profile.network.ifBlank { "tcp" }}, sec=${profile.security.ifBlank { "none" }}] (port $localSocksPort)"
            )

            val callbackHandler = object : CoreCallbackHandler {
                override fun onEmitStatus(status: Long, msg: String?): Long {
                    AppLogger.d(TAG, "Core callback status: $status - $msg")
                    return 0
                }

                override fun shutdown(): Long {
                    AppLogger.i(TAG, "Core shutdown signal received")
                    return 0
                }

                override fun startup(): Long {
                    AppLogger.i(TAG, "Core startup signal confirmed")
                    return 0
                }
            }

            val controller = Libv2ray.newCoreController(callbackHandler)
            coreController = controller

            AppLogger.i(TAG, "Starting Xray Core loop (protecting via VPN tunnel)...")
            controller.startLoop(configJson, 0)

            if (!controller.isRunning) {
                AppLogger.e(TAG, "Xray core failed to start loop")
                stop()
                throw IllegalStateException("Xray core loop failed to start")
            }

            // Wait for Xray's local SOCKS5 listener on 127.0.0.1:10808 to be ready before attaching HEV
            val socksReady = waitForLocalSocksListener("127.0.0.1", localSocksPort, timeoutMs = 3000)
            if (!socksReady) {
                AppLogger.e(TAG, "Local Xray SOCKS5 listener 127.0.0.1:$localSocksPort did not become ready")
                stop()
                throw IllegalStateException("Local Xray SOCKS5 listener on port $localSocksPort failed to bind")
            }

            vpnService.notifyTunnelEstablished(
                profile.name,
                "Starting TUN packet forwarder..."
            )

            AppLogger.i(TAG, "Starting HEV TUN-to-SOCKS5 forwarder on 127.0.0.1:$localSocksPort (udp=udp)")
            val hevOk = HevTunnelManager.start(
                context = vpnService,
                tunFd = tunFd,
                socksAddress = "127.0.0.1",
                socksPort = localSocksPort,
                udpMode = "udp"
            )

            if (!hevOk) {
                AppLogger.e(TAG, "Failed to start HEV tunnel attached to Xray")
                stop()
                throw IllegalStateException("Failed to start TUN-to-SOCKS5 packet forwarder")
            }

            isEngineRunning = true

            vpnService.notifyTunnelEstablished(
                profile.name,
                "Tunnel established, verifying internet connectivity..."
            )
            AppLogger.i(TAG, "Verifying real outbound connectivity through ${profile.protocol.displayName} server...")
            val checkResult = verifyTunnelConnectivity(controller, profile)
            lastConnectivityResult = checkResult

            if (checkResult.verified) {
                AppLogger.i(TAG, "Xray Engine and HEV forwarder active — internet connectivity verified (${checkResult.diagnosticMessage})")
            } else {
                AppLogger.w(
                    TAG,
                    "Xray Engine and HEV forwarder active, but internet probe did not succeed: ${checkResult.diagnosticMessage}"
                )
            }
            true
        } catch (e: Throwable) {
            val cleanMsg = AppLogger.redact(e.message ?: "Unknown Xray error")
            AppLogger.e(TAG, "Exception starting Xray core: $cleanMsg", e)
            stop()
            throw IllegalStateException(cleanMsg, e)
        }
    }

    override suspend fun recheckConnectivity(): ConnectivityCheckResult? = withContext(Dispatchers.IO) {
        val controller = coreController ?: return@withContext null
        val profile = activeProfile ?: return@withContext null
        if (!isEngineRunning || !controller.isRunning) return@withContext null
        val result = verifyTunnelConnectivity(controller, profile)
        lastConnectivityResult = result
        result
    }

    private fun waitForLocalSocksListener(host: String, port: Int, timeoutMs: Int): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                java.net.Socket().use { sock ->
                    sock.connect(java.net.InetSocketAddress(host, port), 250)
                    return true
                }
            } catch (_: Throwable) {
                try { Thread.sleep(50) } catch (_: InterruptedException) { break }
            }
        }
        return false
    }

    fun verifyTunnelConnectivity(controller: CoreController, profile: VpnProfile): ConnectivityCheckResult {
        val probeUrls = listOf(
            "http://cp.cloudflare.com/generate_204",
            "http://connectivitycheck.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204"
        )

        var lastError: String? = null
        var lastCategory = ProbeFailureCategory.TIMEOUT

        // 1. Probe through the actual local SOCKS5 inbound (exercises HEV -> socks-in -> routing -> proxy)
        for (url in probeUrls.take(2)) {
            val socksOutcome = probeViaLocalSocks(url, timeoutMs = 4500)
            if (socksOutcome.rttMs > 0) {
                val msg = "Verified via SOCKS5 (${socksOutcome.rttMs}ms)"
                AppLogger.i(TAG, "Outbound tunnel verified via SOCKS5 $url (RTT: ${socksOutcome.rttMs}ms)")
                return ConnectivityCheckResult(
                    verified = true,
                    rttMs = socksOutcome.rttMs,
                    endpoint = url,
                    failureCategory = ProbeFailureCategory.NONE,
                    diagnosticMessage = msg
                )
            } else if (socksOutcome.error != null) {
                lastError = socksOutcome.error
                lastCategory = classifyProbeError(socksOutcome.error)
            }
        }

        // 2. Independent check via Xray CoreController.measureDelay
        for (url in probeUrls) {
            try {
                val delayMs = controller.measureDelay(url)
                if (delayMs > 0) {
                    val msg = "Verified (${delayMs}ms)"
                    AppLogger.i(TAG, "Outbound tunnel verified via $url (RTT: ${delayMs}ms)")
                    return ConnectivityCheckResult(
                        verified = true,
                        rttMs = delayMs,
                        endpoint = url,
                        failureCategory = ProbeFailureCategory.NONE,
                        diagnosticMessage = msg
                    )
                }
            } catch (e: Throwable) {
                val msg = AppLogger.redact(e.message ?: e.javaClass.simpleName)
                lastError = msg
                lastCategory = classifyProbeError(msg)
                AppLogger.w(TAG, "Outbound probe to $url failed [${lastCategory.name}]: $msg")
            }
        }

        val diagnostic = summarizeXrayError(lastError, profile)
        return ConnectivityCheckResult(
            verified = false,
            rttMs = null,
            endpoint = null,
            failureCategory = lastCategory,
            diagnosticMessage = diagnostic
        )
    }

    private data class SocksProbeOutcome(val rttMs: Long, val error: String? = null)

    private fun probeViaLocalSocks(urlStr: String, timeoutMs: Int): SocksProbeOutcome {
        return try {
            val startNs = System.nanoTime()
            val proxy = java.net.Proxy(
                java.net.Proxy.Type.SOCKS,
                java.net.InetSocketAddress("127.0.0.1", localSocksPort)
            )
            val conn = (java.net.URL(urlStr).openConnection(proxy) as java.net.HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = false
                requestMethod = "GET"
                setRequestProperty("Connection", "close")
            }
            val code = conn.responseCode
            conn.disconnect()
            if (code in 200..399) {
                SocksProbeOutcome(((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(1L))
            } else {
                SocksProbeOutcome(-1L, "Probe HTTP status $code from $urlStr")
            }
        } catch (e: Throwable) {
            SocksProbeOutcome(-1L, AppLogger.redact(e.message ?: e.javaClass.simpleName))
        }
    }

    fun classifyProbeError(rawError: String?): ProbeFailureCategory {
        if (rawError.isNullOrBlank()) return ProbeFailureCategory.TIMEOUT
        val err = rawError.lowercase()
        return when {
            err.contains("closed pipe") || err.contains("eof") || err.contains("broken pipe") || err.contains("connection reset") ->
                ProbeFailureCategory.CLOSED_PIPE
            err.contains("websocket: bad handshake") || err.contains("unexpected http status") ->
                ProbeFailureCategory.WEBSOCKET_HANDSHAKE
            err.contains("tls:") || err.contains("x509:") || err.contains("certificate") ->
                ProbeFailureCategory.TLS_HANDSHAKE
            err.contains("reality") || err.contains("invalid user") || err.contains("auth") ->
                ProbeFailureCategory.AUTH_OR_PROTOCOL
            err.contains("connection refused") ->
                ProbeFailureCategory.CONNECTION_REFUSED
            err.contains("no such host") || err.contains("unknownhost") || err.contains("lookup ") || err.contains("dns") ->
                ProbeFailureCategory.DNS_FAILURE
            err.contains("timeout") || err.contains("timed out") || err.contains("deadline exceeded") ->
                ProbeFailureCategory.TIMEOUT
            else ->
                ProbeFailureCategory.BLOCKED_PROBE
        }
    }

    fun summarizeXrayError(rawError: String?, profile: VpnProfile): String {
        val err = rawError ?: "Timed out waiting for response through ${profile.server}:${profile.port}"
        val category = classifyProbeError(rawError)
        return when (category) {
            ProbeFailureCategory.WEBSOCKET_HANDSHAKE ->
                "WebSocket handshake rejected by ${profile.server}:${profile.port} (check WS path '${profile.path.ifEmpty { "/" }}' and Host/SNI '${profile.wsHost.ifBlank { profile.sni }}')"
            ProbeFailureCategory.TLS_HANDSHAKE ->
                "TLS/Certificate handshake failed with ${profile.server}:${profile.port} (SNI='${profile.sni.ifBlank { profile.server }}'): $err"
            ProbeFailureCategory.AUTH_OR_PROTOCOL ->
                "Protocol/REALITY handshake failed with ${profile.server}:${profile.port}: $err"
            ProbeFailureCategory.CONNECTION_REFUSED ->
                "Connection refused by remote server ${profile.server}:${profile.port}"
            ProbeFailureCategory.DNS_FAILURE ->
                "DNS lookup failed while probing through ${profile.protocol.displayName} tunnel: $err"
            ProbeFailureCategory.CLOSED_PIPE ->
                "Remote ${profile.protocol.displayName} endpoint closed stream during probe (closed pipe — check UUID, WS Host/SNI, or server status)"
            ProbeFailureCategory.TIMEOUT ->
                "Remote ${profile.protocol.displayName} server ${profile.server}:${profile.port} timed out on connectivity probe"
            else ->
                "Connectivity probe blocked or failed (${profile.protocol.displayName}): $err"
        }
    }

    fun validateProfile(profile: VpnProfile) {
        if (profile.server.isBlank()) {
            throw IllegalArgumentException("${profile.protocol.displayName} server hostname or IP is empty")
        }
        if (profile.port !in 1..65535) {
            throw IllegalArgumentException("Invalid server port: ${profile.port}")
        }

        when (profile.protocol) {
            ProtocolType.VLESS -> {
                if (profile.password.isBlank()) {
                    throw IllegalArgumentException("VLESS configuration is missing UUID")
                }
                val enc = profile.encryption.trim().ifEmpty { "none" }
                if (!enc.equals("none", ignoreCase = true)) {
                    throw IllegalArgumentException("Unsupported VLESS encryption '$enc' (Xray VLESS requires encryption=none)")
                }
                val sec = profile.security.trim().lowercase().ifEmpty { "none" }
                if (sec !in setOf("none", "tls", "reality")) {
                    throw IllegalArgumentException("Unsupported VLESS security '$sec' (expected none, tls, or reality)")
                }
                if (sec == "reality" && profile.publicKey.isBlank()) {
                    throw IllegalArgumentException("VLESS REALITY configuration requires a non-empty publicKey ('pbk')")
                }
                val net = profile.network.trim().lowercase().ifEmpty { "tcp" }
                val supportedNets = setOf("tcp", "ws", "websocket", "grpc", "gun", "httpupgrade", "xhttp", "splithttp", "h2", "http", "kcp")
                if (net !in supportedNets) {
                    throw IllegalArgumentException("Unsupported VLESS transport network '$net'")
                }
                val flow = profile.flow.trim()
                if (flow.isNotEmpty() && !flow.equals("xtls-rprx-vision", ignoreCase = true) && !flow.equals("xtls-rprx-vision-udp443", ignoreCase = true)) {
                    throw IllegalArgumentException("Unsupported VLESS flow '$flow' (only xtls-rprx-vision is supported)")
                }
            }
            ProtocolType.VMESS -> {
                if (profile.password.isBlank()) {
                    throw IllegalArgumentException("VMess configuration is missing UUID")
                }
            }
            ProtocolType.TROJAN, ProtocolType.SHADOWSOCKS -> {
                if (profile.password.isBlank()) {
                    throw IllegalArgumentException("${profile.protocol.displayName} configuration is missing password")
                }
            }
            else -> {}
        }
    }

    private fun getDeviceIdForXUDPBaseKey(): String {
        val seed = ByteArray(32) { i -> ((i * 37 + 0x5A) and 0xFF).toByte() }
        return Base64.encodeToString(seed, Base64.NO_PADDING or Base64.URL_SAFE or Base64.NO_WRAP)
    }

    private fun isIpLiteral(host: String): Boolean {
        val trimmed = host.trim().removePrefix("[")?.removeSuffix("]") ?: return false
        if (trimmed.isEmpty()) return false
        return trimmed.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) || trimmed.contains(":")
    }

    private fun resolveServerAddresses(host: String): List<String> {
        val trimmed = host.trim().removePrefix("[")?.removeSuffix("]") ?: return emptyList()
        if (trimmed.isEmpty() || isIpLiteral(trimmed)) return emptyList()
        return try {
            InetAddress.getAllByName(trimmed)
                .mapNotNull { it.hostAddress }
                .filter { it.isNotBlank() }
                .distinct()
        } catch (e: Exception) {
            AppLogger.w(TAG, "Pre-resolution of $trimmed failed (will rely on Xray DNS): ${e.message}")
            emptyList()
        }
    }

    override suspend fun stop() = withContext(Dispatchers.IO) {
        try {
            AppLogger.i(TAG, "Stopping HEV forwarder and Xray core")
            isEngineRunning = false
            HevTunnelManager.stop()
            coreController?.let {
                if (it.isRunning) {
                    it.stopLoop()
                }
            }
            coreController = null
        } catch (e: Throwable) {
            AppLogger.e(TAG, "Error stopping Xray engine: ${e.message}", e)
        }
    }

    private fun setupAssets(vpnService: CustomTunnelVpnService) {
        val assetDir = vpnService.filesDir
        val dirPath = assetDir.absolutePath
        val geoipFile = File(assetDir, "geoip.dat")
        val geositeFile = File(assetDir, "geosite.dat")
        if (assetsPreparedForDir == dirPath && geoipFile.exists() && geoipFile.length() > 0L && geositeFile.exists() && geositeFile.length() > 0L) {
            return
        }
        listOf("geoip.dat", "geosite.dat").forEach { filename ->
            val target = File(assetDir, filename)
            if (!target.exists() || target.length() == 0L) {
                try {
                    vpnService.assets.open(filename).use { input ->
                        FileOutputStream(target).use { output ->
                            input.copyTo(output)
                        }
                    }
                    AppLogger.d(TAG, "Copied asset $filename (${target.length()} bytes)")
                } catch (e: Exception) {
                    AppLogger.w(TAG, "Could not copy $filename from APK assets: ${e.message}")
                }
            }
        }
        assetsPreparedForDir = dirPath
    }

    private fun normalizePath(rawPath: String): String {
        val trimmed = rawPath.trim()
        if (trimmed.isEmpty()) return "/"
        return if (trimmed.startsWith("/")) trimmed else "/$trimmed"
    }

    private fun formatTcpDnsServer(rawDns: String): String {
        val trimmed = rawDns.trim().ifBlank { "1.1.1.1" }
        if (trimmed.contains("://")) {
            val afterScheme = trimmed.substringAfter("://")
            return if (afterScheme.contains(":")) trimmed else "$trimmed:53"
        }
        return if (trimmed.contains(":")) "tcp://$trimmed" else "tcp://$trimmed:53"
    }

    fun buildXrayConfig(
        profile: VpnProfile,
        localPort: Int,
        resolvedServerIps: List<String> = emptyList()
    ): String {
        validateProfile(profile)

        val root = JSONObject()

        // Log config
        val log = JSONObject().apply {
            put("loglevel", "warning")
        }
        root.put("log", log)

        // Inbounds: local SOCKS5 proxy with UDP & sniffing
        val inbounds = JSONArray()
        val socksInbound = JSONObject().apply {
            put("tag", "socks-in")
            put("port", localPort)
            put("listen", "127.0.0.1")
            put("protocol", "socks")
            put("settings", JSONObject().apply {
                put("auth", "noauth")
                put("udp", true)
                put("userLevel", 8)
            })
            put("sniffing", JSONObject().apply {
                put("enabled", true)
                put("destOverride", JSONArray().put("http").put("tls").put("quic"))
                put("routeOnly", false)
            })
        }
        inbounds.put(socksInbound)
        root.put("inbounds", inbounds)

        val normalizedNetwork = when (profile.network.trim().lowercase()) {
            "", "tcp" -> "tcp"
            "ws", "websocket" -> "ws"
            "grpc", "gun" -> "grpc"
            "httpupgrade" -> "httpupgrade"
            "xhttp", "splithttp" -> "xhttp"
            "h2", "http" -> "h2"
            "kcp" -> "kcp"
            else -> profile.network.trim().lowercase()
        }

        val normalizedSecurity = profile.security.trim().lowercase().ifEmpty { "none" }
        val serverTrimmed = profile.server.trim()
        // Only fall back TLS SNI to profile.server when profile.server is a DNS hostname (RFC 6066 forbids IP literals in SNI)
        val effectiveSni = profile.sni.trim().ifBlank {
            profile.wsHost.trim().ifBlank {
                if (!isIpLiteral(serverTrimmed)) serverTrimmed else ""
            }
        }
        val effectiveWsHost = profile.wsHost.trim().ifBlank {
            profile.sni.trim().ifBlank { serverTrimmed }
        }

        // Outbounds: primary proxy outbound + direct + dns-out + blackhole
        val outbounds = JSONArray()
        val proxyOutbound = JSONObject().apply {
            put("tag", "proxy")
            when (profile.protocol) {
                ProtocolType.VLESS -> {
                    put("protocol", "vless")
                    put("settings", JSONObject().apply {
                        val vnext = JSONArray()
                        val serverObj = JSONObject().apply {
                            put("address", profile.server.trim())
                            put("port", profile.port)
                            val users = JSONArray().put(JSONObject().apply {
                                put("id", profile.password.trim())
                                put("encryption", profile.encryption.trim().ifEmpty { "none" })
                                val flow = profile.flow.trim()
                                if (flow.isNotBlank() && (normalizedNetwork == "tcp" || normalizedNetwork == "xhttp") &&
                                    (normalizedSecurity == "tls" || normalizedSecurity == "reality")
                                ) {
                                    put("flow", flow)
                                }
                                put("level", 8)
                            })
                            put("users", users)
                        }
                        vnext.put(serverObj)
                        put("vnext", vnext)
                    })
                }
                ProtocolType.VMESS -> {
                    put("protocol", "vmess")
                    put("settings", JSONObject().apply {
                        val vnext = JSONArray()
                        val vmessCipher = profile.encryption.trim().lowercase().let {
                            if (it.isEmpty() || it == "none") "auto" else it
                        }
                        val serverObj = JSONObject().apply {
                            put("address", profile.server.trim())
                            put("port", profile.port)
                            val users = JSONArray().put(JSONObject().apply {
                                put("id", profile.password.trim())
                                put("alterId", 0)
                                put("security", vmessCipher)
                                put("level", 8)
                            })
                            put("users", users)
                        }
                        vnext.put(serverObj)
                        put("vnext", vnext)
                    })
                }
                ProtocolType.TROJAN -> {
                    put("protocol", "trojan")
                    put("settings", JSONObject().apply {
                        val servers = JSONArray()
                        servers.put(JSONObject().apply {
                            put("address", profile.server.trim())
                            put("port", profile.port)
                            put("password", profile.password)
                            put("level", 8)
                        })
                        put("servers", servers)
                    })
                }
                ProtocolType.SHADOWSOCKS -> {
                    put("protocol", "shadowsocks")
                    put("settings", JSONObject().apply {
                        val servers = JSONArray()
                        val parts = profile.password.split(":", limit = 2)
                        val method = if (parts.size == 2) parts[0] else "aes-256-gcm"
                        val pass = if (parts.size == 2) parts[1] else profile.password
                        servers.put(JSONObject().apply {
                            put("address", profile.server.trim())
                            put("port", profile.port)
                            put("method", method)
                            put("password", pass)
                            put("level", 8)
                        })
                        put("servers", servers)
                    })
                }
                else -> {
                    put("protocol", "socks")
                    put("settings", JSONObject().apply {
                        val servers = JSONArray().put(JSONObject().apply {
                            put("address", profile.server.trim())
                            put("port", profile.port)
                        })
                        put("servers", servers)
                    })
                }
            }

            // StreamSettings
            val streamSettings = JSONObject().apply {
                put("network", normalizedNetwork)
                when (normalizedSecurity) {
                    "tls" -> {
                        put("security", "tls")
                        put("tlsSettings", JSONObject().apply {
                            if (effectiveSni.isNotBlank()) {
                                put("serverName", effectiveSni)
                            }
                            put("allowInsecure", profile.allowInsecureSsl)
                            val fp = profile.fingerprint.trim().ifEmpty { "chrome" }
                            put("fingerprint", fp)

                            // Resolve ALPN safely: WebSocket and HTTPUpgrade require HTTP/1.1 Upgrade
                            val alpnList = when {
                                normalizedNetwork == "ws" || normalizedNetwork == "httpupgrade" -> {
                                    if (profile.alpn.isBlank() || profile.alpn.equals("h2,http/1.1", ignoreCase = true)) {
                                        listOf("http/1.1")
                                    } else {
                                        profile.alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                                    }
                                }
                                normalizedNetwork == "grpc" || normalizedNetwork == "h2" -> {
                                    if (profile.alpn.isBlank()) {
                                        listOf("h2")
                                    } else {
                                        profile.alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                                    }
                                }
                                profile.alpn.isNotBlank() -> {
                                    profile.alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                                }
                                else -> emptyList()
                            }
                            if (alpnList.isNotEmpty()) {
                                val alpnArray = JSONArray()
                                alpnList.forEach { alpnArray.put(it) }
                                put("alpn", alpnArray)
                            }
                        })
                    }
                    "reality" -> {
                        put("security", "reality")
                        put("realitySettings", JSONObject().apply {
                            put("show", false)
                            if (effectiveSni.isNotBlank()) {
                                put("serverName", effectiveSni)
                            }
                            put("fingerprint", profile.fingerprint.trim().ifEmpty { "chrome" })
                            put("publicKey", profile.publicKey.trim())
                            put("shortId", profile.shortId.trim())
                            put("spiderX", profile.spiderX.trim().ifEmpty { "/" })
                        })
                    }
                    else -> {
                        put("security", "none")
                    }
                }

                when (normalizedNetwork) {
                    "ws" -> {
                        put("wsSettings", JSONObject().apply {
                            put("path", normalizePath(profile.path))
                            if (effectiveWsHost.isNotBlank()) {
                                put("host", effectiveWsHost)
                                put("headers", JSONObject().apply {
                                    put("Host", effectiveWsHost)
                                })
                            }
                        })
                    }
                    "grpc" -> {
                        put("grpcSettings", JSONObject().apply {
                            put("serviceName", profile.path.trim())
                            put("multiMode", profile.grpcMode.equals("multi", ignoreCase = true))
                            if (profile.grpcAuthority.isNotBlank()) {
                                put("authority", profile.grpcAuthority.trim())
                            }
                            put("idle_timeout", 60)
                            put("health_check_timeout", 20)
                        })
                    }
                    "httpupgrade" -> {
                        put("httpupgradeSettings", JSONObject().apply {
                            put("path", normalizePath(profile.path))
                            if (effectiveWsHost.isNotBlank()) {
                                put("host", effectiveWsHost)
                            }
                        })
                    }
                    "xhttp" -> {
                        put("xhttpSettings", JSONObject().apply {
                            put("path", normalizePath(profile.path))
                            if (effectiveWsHost.isNotBlank()) {
                                put("host", effectiveWsHost)
                            }
                            put("mode", "auto")
                        })
                    }
                    "h2" -> {
                        put("httpSettings", JSONObject().apply {
                            put("path", normalizePath(profile.path))
                            if (effectiveWsHost.isNotBlank()) {
                                put("host", JSONArray().put(effectiveWsHost))
                            }
                        })
                    }
                    "tcp" -> {
                        if (profile.headerType.equals("http", ignoreCase = true)) {
                            put("tcpSettings", JSONObject().apply {
                                put("header", JSONObject().apply {
                                    put("type", "http")
                                    put("request", JSONObject().apply {
                                        put("version", "1.1")
                                        put("method", "GET")
                                        put("path", JSONArray().put(normalizePath(profile.path)))
                                        put("headers", JSONObject().apply {
                                            if (effectiveWsHost.isNotBlank()) {
                                                put("Host", JSONArray().put(effectiveWsHost))
                                            }
                                            put(
                                                "User-Agent",
                                                JSONArray().put("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36")
                                            )
                                            put("Accept-Encoding", JSONArray().put("gzip, deflate"))
                                            put("Connection", JSONArray().put("keep-alive"))
                                            put("Pragma", "no-cache")
                                        })
                                    })
                                })
                            })
                        }
                    }
                }

                put("sockopt", JSONObject().apply {
                    // Use pre-resolved IPs from dns.hosts when available so Go on Android does not rely on /etc/resolv.conf
                    put("domainStrategy", if (resolvedServerIps.isNotEmpty()) "UseIP" else "AsIs")
                })
            }
            put("streamSettings", streamSettings)
        }
        outbounds.put(proxyOutbound)

        // Direct outbound
        val directOutbound = JSONObject().apply {
            put("tag", "direct")
            put("protocol", "freedom")
            put("settings", JSONObject().apply {
                put("domainStrategy", "UseIP")
            })
        }
        outbounds.put(directOutbound)

        // DNS outbound: hijacks port-53 queries from TUN so Xray resolves DNS over TCP through the proxy outbound
        val dnsOutbound = JSONObject().apply {
            put("tag", "dns-out")
            put("protocol", "dns")
            put("settings", JSONObject().apply {
                put("network", "tcp")
            })
        }
        outbounds.put(dnsOutbound)

        // Blackhole outbound
        val blockOutbound = JSONObject().apply {
            put("tag", "block")
            put("protocol", "blackhole")
        }
        outbounds.put(blockOutbound)

        root.put("outbounds", outbounds)

        // DNS configuration with pre-resolved server host to prevent DNS bootstrap loop
        val dns = JSONObject().apply {
            put("tag", "dns-in")
            val hosts = JSONObject().apply {
                put("dns.google", "8.8.8.8")
                put("cloudflare-dns.com", "1.1.1.1")
                if (resolvedServerIps.isNotEmpty()) {
                    val serverKey = profile.server.trim()
                    val valueToPut: Any = if (resolvedServerIps.size == 1) {
                        resolvedServerIps[0]
                    } else {
                        JSONArray().apply { resolvedServerIps.forEach { put(it) } }
                    }
                    put(serverKey, valueToPut)
                    if (serverKey.lowercase() != serverKey) {
                        put(serverKey.lowercase(), valueToPut)
                    }
                }
            }
            put("hosts", hosts)

            val primaryDns = profile.dnsPrimary.trim().ifBlank { "1.1.1.1" }
            val primaryTcp = formatTcpDnsServer(primaryDns)
            val servers = JSONArray().put(primaryTcp)
            if (profile.dnsSecondary.isNotBlank()) {
                val secondaryDns = profile.dnsSecondary.trim()
                servers.put(formatTcpDnsServer(secondaryDns))
            }
            servers.put(primaryDns)
            put("servers", servers)
        }
        root.put("dns", dns)

        // Routing configuration:
        // Use "AsIs" so domain names are sent directly to the remote V2Ray server to resolve,
        // avoiding circular or blocked UDP DNS lookups over WebSocket tunnels.
        val routing = JSONObject().apply {
            put("domainStrategy", "AsIs")
            val rules = JSONArray()

            rules.put(JSONObject().apply {
                put("type", "field")
                put("inboundTag", JSONArray().put("socks-in"))
                put("port", "53")
                put("outboundTag", "dns-out")
            })

            rules.put(JSONObject().apply {
                put("type", "field")
                put("inboundTag", JSONArray().put("dns-in"))
                put("outboundTag", "proxy")
            })

            rules.put(JSONObject().apply {
                put("type", "field")
                put("ip", JSONArray().put("geoip:private"))
                put("outboundTag", "direct")
            })

            rules.put(JSONObject().apply {
                put("type", "field")
                put("network", "tcp,udp")
                put("outboundTag", "proxy")
            })

            put("rules", rules)
        }
        root.put("routing", routing)

        return root.toString(2)
    }
}

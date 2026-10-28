package com.example.vpn.engine

import android.util.Base64
import com.example.data.AppLogger
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.vpn.AegisVpnService
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
    private var isEngineRunning = false
    private val localSocksPort = 10808

    override fun getEngineName(): String = "Xray Core Engine"
    override fun getLocalSocksPort(): Int = localSocksPort
    override fun isRunning(): Boolean = isEngineRunning

    override suspend fun start(
        profile: VpnProfile,
        vpnService: AegisVpnService,
        tunFd: Int
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            validateProfile(profile)

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

            vpnService.notifyTunnelEstablished(
                profile.name,
                "Xray transport established, verifying internet connectivity..."
            )
            AppLogger.i(TAG, "Verifying real outbound connectivity through ${profile.protocol.displayName} server...")
            verifyTunnelConnectivity(controller, profile)

            AppLogger.i(TAG, "Xray outbound verified. Starting HEV TUN-to-SOCKS5 forwarder on 127.0.0.1:$localSocksPort (udp=udp)")
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
            AppLogger.i(TAG, "Xray Engine and HEV forwarder active and routing verified traffic")
            true
        } catch (e: Throwable) {
            val cleanMsg = AppLogger.redact(e.message ?: "Unknown Xray error")
            AppLogger.e(TAG, "Exception starting Xray core: $cleanMsg", e)
            stop()
            throw IllegalStateException(cleanMsg, e)
        }
    }

    private fun verifyTunnelConnectivity(controller: CoreController, profile: VpnProfile) {
        val probeUrls = listOf(
            "http://cp.cloudflare.com/generate_204",
            "http://connectivitycheck.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204"
        )
        var lastError: String? = null
        for (url in probeUrls) {
            try {
                val delayMs = controller.measureDelay(url)
                if (delayMs > 0) {
                    AppLogger.i(TAG, "Outbound tunnel verified via $url (RTT: ${delayMs}ms)")
                    return
                }
            } catch (e: Throwable) {
                val msg = AppLogger.redact(e.message ?: e.javaClass.simpleName)
                lastError = msg
                AppLogger.w(TAG, "Outbound probe to $url failed: $msg")
            }
        }

        val diagnostic = summarizeXrayError(lastError, profile)
        throw IllegalStateException(diagnostic)
    }

    private fun summarizeXrayError(rawError: String?, profile: VpnProfile): String {
        val err = rawError ?: "Timed out waiting for response through ${profile.server}:${profile.port}"
        return when {
            err.contains("websocket: bad handshake", ignoreCase = true) ->
                "WebSocket handshake rejected by ${profile.server}:${profile.port} (check WS path '${profile.path.ifEmpty { "/" }}' and Host/SNI '${profile.wsHost.ifBlank { profile.sni }}')"
            err.contains("tls:", ignoreCase = true) || err.contains("x509:", ignoreCase = true) ->
                "TLS/Certificate handshake failed with ${profile.server}:${profile.port} (SNI='${profile.sni.ifBlank { profile.server }}'): $err"
            err.contains("reality", ignoreCase = true) ->
                "REALITY handshake failed with ${profile.server}:${profile.port} (check pbk, sid, and sni): $err"
            err.contains("connection refused", ignoreCase = true) ->
                "Connection refused by remote server ${profile.server}:${profile.port}"
            err.contains("i/o timeout", ignoreCase = true) || err.contains("deadline exceeded", ignoreCase = true) ->
                "Tunnel established locally, but remote ${profile.protocol.displayName} server ${profile.server}:${profile.port} timed out forwarding traffic (check UUID, security=${profile.security}, transport=${profile.network})"
            else ->
                "Remote ${profile.protocol.displayName} server ${profile.server}:${profile.port} failed to forward traffic: $err"
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

    private fun resolveServerAddresses(host: String): List<String> {
        val trimmed = host.trim().removePrefix("[")?.removeSuffix("]") ?: return emptyList()
        if (trimmed.isEmpty()) return emptyList()
        // Check if already IPv4 literal or IPv6 literal
        if (trimmed.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) || trimmed.contains(":")) {
            return emptyList()
        }
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
            AppLogger.i(TAG, "Stopping Xray core and HEV forwarder")
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

    private fun setupAssets(vpnService: AegisVpnService) {
        val assetDir = vpnService.filesDir
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
    }

    private fun normalizePath(rawPath: String): String {
        val trimmed = rawPath.trim()
        if (trimmed.isEmpty()) return "/"
        return if (trimmed.startsWith("/")) trimmed else "/$trimmed"
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
        val effectiveSni = profile.sni.trim().ifBlank {
            profile.wsHost.trim().ifBlank { profile.server.trim() }
        }
        val effectiveWsHost = profile.wsHost.trim().ifBlank {
            profile.sni.trim().ifBlank { profile.server.trim() }
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
                        val serverObj = JSONObject().apply {
                            put("address", profile.server.trim())
                            put("port", profile.port)
                            val users = JSONArray().put(JSONObject().apply {
                                put("id", profile.password.trim())
                                put("alterId", 0)
                                put("security", "auto")
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

        // DNS outbound: hijacks port-53 queries from TUN so Xray resolves DNS over TCP/UDP through the proxy outbound
        val dnsOutbound = JSONObject().apply {
            put("tag", "dns-out")
            put("protocol", "dns")
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
                    if (resolvedServerIps.size == 1) {
                        put(serverKey, resolvedServerIps[0])
                    } else {
                        val ipArr = JSONArray()
                        resolvedServerIps.forEach { ipArr.put(it) }
                        put(serverKey, ipArr)
                    }
                }
            }
            put("hosts", hosts)

            val servers = JSONArray().put(profile.dnsPrimary.ifBlank { "1.1.1.1" })
            if (profile.dnsSecondary.isNotBlank()) {
                servers.put(profile.dnsSecondary)
            }
            put("servers", servers)
        }
        root.put("dns", dns)

        // Routing configuration:
        // 1. Intercept port-53 DNS traffic from socks-in into dns-out
        // 2. Route Xray's internal DNS queries (dns-in) through the VLESS/proxy outbound
        // 3. Bypass private LAN IPs via direct
        // 4. Route all remaining TCP & UDP traffic through proxy
        val routing = JSONObject().apply {
            put("domainStrategy", "IPIfNonMatch")
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

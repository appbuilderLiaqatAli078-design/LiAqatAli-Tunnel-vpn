package com.example.vpn.engine

import com.example.data.AppLogger
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.vpn.AegisVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

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
            AppLogger.i(TAG, "Preparing Xray Core environment and assets")
            setupAssets(vpnService)

            val cachePath = vpnService.cacheDir.absolutePath
            val assetPath = vpnService.filesDir.absolutePath
            Libv2ray.initCoreEnv(assetPath, cachePath)

            val configJson = buildXrayConfig(profile, localSocksPort)
            AppLogger.i(TAG, "Generated Xray configuration for protocol: ${profile.protocol.displayName} (port $localSocksPort)")

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
                return@withContext false
            }

            AppLogger.i(TAG, "Xray core running. Starting HEV TUN-to-SOCKS5 forwarder on 127.0.0.1:$localSocksPort")
            val hevOk = HevTunnelManager.start(
                context = vpnService,
                tunFd = tunFd,
                socksAddress = "127.0.0.1",
                socksPort = localSocksPort
            )

            if (!hevOk) {
                AppLogger.e(TAG, "Failed to start HEV tunnel attached to Xray")
                stop()
                return@withContext false
            }

            isEngineRunning = true
            AppLogger.i(TAG, "Xray Engine and HEV forwarder active and routing traffic")
            true
        } catch (e: Throwable) {
            AppLogger.e(TAG, "Exception starting Xray core: ${e.message}", e)
            stop()
            false
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

    fun buildXrayConfig(profile: VpnProfile, localPort: Int): String {
        val root = JSONObject()

        // Log config
        val log = JSONObject().apply {
            put("loglevel", "warning")
        }
        root.put("log", log)

        // Inbounds: local SOCKS5 proxy
        val inbounds = JSONArray()
        val socksInbound = JSONObject().apply {
            put("tag", "socks-in")
            put("port", localPort)
            put("listen", "127.0.0.1")
            put("protocol", "socks")
            put("settings", JSONObject().apply {
                put("auth", "noauth")
                put("udp", true)
            })
            put("sniffing", JSONObject().apply {
                put("enabled", true)
                put("destOverride", JSONArray().put("http").put("tls"))
            })
        }
        inbounds.put(socksInbound)
        root.put("inbounds", inbounds)

        // Outbounds: primary proxy outbound + direct fallback
        val outbounds = JSONArray()
        val proxyOutbound = JSONObject().apply {
            put("tag", "proxy")
            when (profile.protocol) {
                ProtocolType.VLESS -> {
                    put("protocol", "vless")
                    put("settings", JSONObject().apply {
                        val vnext = JSONArray()
                        val serverObj = JSONObject().apply {
                            put("address", profile.server)
                            put("port", profile.port)
                            val users = JSONArray().put(JSONObject().apply {
                                put("id", profile.password)
                                put("encryption", "none")
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
                            put("address", profile.server)
                            put("port", profile.port)
                            val users = JSONArray().put(JSONObject().apply {
                                put("id", profile.password)
                                put("alterId", 0)
                                put("security", "auto")
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
                            put("address", profile.server)
                            put("port", profile.port)
                            put("password", profile.password)
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
                            put("address", profile.server)
                            put("port", profile.port)
                            put("method", method)
                            put("password", pass)
                        })
                        put("servers", servers)
                    })
                }
                else -> {
                    put("protocol", "socks")
                    put("settings", JSONObject().apply {
                        val servers = JSONArray().put(JSONObject().apply {
                            put("address", profile.server)
                            put("port", profile.port)
                        })
                        put("servers", servers)
                    })
                }
            }

            // StreamSettings
            val streamSettings = JSONObject().apply {
                put("network", profile.network.ifEmpty { "tcp" })
                if (profile.security.equals("tls", ignoreCase = true)) {
                    put("security", "tls")
                    put("tlsSettings", JSONObject().apply {
                        if (profile.sni.isNotBlank()) put("serverName", profile.sni)
                        put("allowInsecure", false)
                        if (profile.alpn.isNotBlank()) {
                            val alpnArray = JSONArray()
                            profile.alpn.split(",").map { it.trim() }.forEach { alpnArray.put(it) }
                            put("alpn", alpnArray)
                        }
                    })
                } else if (profile.security.equals("reality", ignoreCase = true)) {
                    put("security", "reality")
                    put("realitySettings", JSONObject().apply {
                        if (profile.sni.isNotBlank()) put("serverName", profile.sni)
                        if (profile.fingerprint.isNotBlank()) put("fingerprint", profile.fingerprint)
                        if (profile.publicKey.isNotBlank()) put("publicKey", profile.publicKey)
                        if (profile.shortId.isNotBlank()) put("shortId", profile.shortId)
                    })
                }

                if (profile.network.equals("ws", ignoreCase = true)) {
                    put("wsSettings", JSONObject().apply {
                        put("path", profile.path.ifEmpty { "/" })
                        if (profile.sni.isNotBlank()) {
                            put("headers", JSONObject().apply { put("Host", profile.sni) })
                        }
                    })
                } else if (profile.network.equals("grpc", ignoreCase = true)) {
                    put("grpcSettings", JSONObject().apply {
                        put("serviceName", profile.path.ifEmpty { "grpc" })
                    })
                }
            }
            put("streamSettings", streamSettings)
        }
        outbounds.put(proxyOutbound)

        // Direct outbound
        val directOutbound = JSONObject().apply {
            put("tag", "direct")
            put("protocol", "freedom")
            put("settings", JSONObject())
        }
        outbounds.put(directOutbound)

        root.put("outbounds", outbounds)

        // DNS configuration
        val dns = JSONObject().apply {
            val servers = JSONArray().put(profile.dnsPrimary.ifEmpty { "1.1.1.1" })
            if (profile.dnsSecondary.isNotBlank()) servers.put(profile.dnsSecondary)
            put("servers", servers)
        }
        root.put("dns", dns)

        return root.toString(2)
    }
}

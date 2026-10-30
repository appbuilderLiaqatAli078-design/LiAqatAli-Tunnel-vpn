package com.example.vpn.engine

import com.example.data.AppLogger
import com.example.model.SshTunnelMode
import com.example.model.VpnProfile
import com.example.parser.SshTargetParser
import com.example.vpn.CustomTunnelVpnService
import com.example.vpn.engine.ssh.SshSocketFactory
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.UIKeyboardInteractive
import com.jcraft.jsch.UserInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

class SshEngineAdapter : VpnEngineAdapter {
    private val TAG = "SshEngine"
    @Volatile
    private var jschSession: Session? = null
    private var serverSocket: ServerSocket? = null
    @Volatile
    private var isEngineRunning = false
    private val localSocksPort = 10809
    private var serverJob: Job? = null
    private val activeChannels = CopyOnWriteArrayList<ChannelDirectTCPIP>()
    private val engineScope = CoroutineScope(Dispatchers.IO + Job())
    private val reconnectMutex = Mutex()
    private var currentMode: SshTunnelMode = SshTunnelMode.DIRECT
    private var activeProfile: VpnProfile? = null
    private var activeVpnService: CustomTunnelVpnService? = null
    @Volatile
    private var advertisedAuthMethods = ""
    @Volatile
    private var lastConnectivityResult: ConnectivityCheckResult = ConnectivityCheckResult(
        verified = false,
        failureCategory = ProbeFailureCategory.BLOCKED_PROBE,
        diagnosticMessage = "Connectivity check not run yet"
    )

    override fun getEngineName(): String = "SSH Engine (${currentMode.badge})"
    override fun getLocalSocksPort(): Int = localSocksPort
    override fun isRunning(): Boolean = isEngineRunning
    override fun getLastConnectivityResult(): ConnectivityCheckResult = lastConnectivityResult

    override suspend fun recheckConnectivity(): ConnectivityCheckResult = withContext(Dispatchers.IO) {
        val session = jschSession
        val profile = activeProfile
        if (session == null || !session.isConnected || profile == null) {
            return@withContext lastConnectivityResult
        }
        val result = verifySshOutboundForwarding(session, profile)
        lastConnectivityResult = result
        result
    }

    override suspend fun recoverIfStalled(): Boolean = withContext(Dispatchers.IO) {
        if (!isEngineRunning) return@withContext false
        val profile = activeProfile ?: return@withContext false
        val vpnService = activeVpnService ?: return@withContext false

        // 1. Prune any closed or EOF channels
        pruneClosedChannels()

        // 2. Test existing session via lightweight SSH keepalive message
        val current = jschSession
        if (current != null && current.isConnected) {
            try {
                current.sendKeepAliveMsg()
                return@withContext true
            } catch (e: Exception) {
                AppLogger.w(TAG, "SSH keepalive failed during stall recovery (${e.message}); reconnecting session in-place...")
            }
        }

        // 3. Reconnect upstream SSH session in-place without closing TUN or local SOCKS5 server
        reconnectMutex.withLock {
            if (!isEngineRunning) return@withLock false
            val checkAgain = jschSession
            if (checkAgain != null && checkAgain.isConnected) {
                try {
                    checkAgain.sendKeepAliveMsg()
                    return@withLock true
                } catch (_: Exception) {}
            }
            try {
                try { checkAgain?.disconnect() } catch (_: Exception) {}
                val newSession = createAndConnectSession(profile, vpnService)
                jschSession = newSession
                AppLogger.i(TAG, "SSH session seamlessly re-established in-place without dropping VPN tunnel")
                true
            } catch (e: Exception) {
                AppLogger.w(TAG, "In-place SSH session recovery failed: ${e.message}")
                false
            }
        }
    }

    private fun createAndConnectSession(
        effectiveProfile: VpnProfile,
        vpnService: CustomTunnelVpnService
    ): Session {
        val hasPass = effectiveProfile.password.isNotEmpty()
        val hasKey = effectiveProfile.sshPrivateKey.isNotBlank()
        val jsch = JSch()

        if (hasKey) {
            val keyBytes = effectiveProfile.sshPrivateKey.trim().toByteArray(Charsets.UTF_8)
            val passBytes = if (effectiveProfile.sshPassphrase.isNotBlank()) {
                effectiveProfile.sshPassphrase.toByteArray(Charsets.UTF_8)
            } else null
            jsch.addIdentity("user_key", keyBytes, null, passBytes)
            AppLogger.i(TAG, "Configured SSH private key authentication for user '${effectiveProfile.sshUsername}'")
        }

        val customSocketFactory = SshSocketFactory(effectiveProfile, vpnService)
        val session = jsch.getSession(effectiveProfile.sshUsername, effectiveProfile.server, effectiveProfile.port)
        if (hasPass) {
            session.setPassword(effectiveProfile.password)
        }
        session.userInfo = createSshUserInfo(effectiveProfile.password, effectiveProfile.sshPassphrase)
        session.setSocketFactory(customSocketFactory)

        JSch.setLogger(object : com.jcraft.jsch.Logger {
            override fun isEnabled(level: Int): Boolean = level >= com.jcraft.jsch.Logger.INFO
            override fun log(level: Int, message: String?) {
                if (message.isNullOrBlank()) return
                if (message.contains("Authentications that can continue:", ignoreCase = true)) {
                    advertisedAuthMethods = message.substringAfter("Authentications that can continue:", "").trim()
                }
                val sanitized = AppLogger.redact(message)
                when {
                    level >= com.jcraft.jsch.Logger.ERROR -> AppLogger.e(TAG, "[SSH-Handshake] $sanitized")
                    level == com.jcraft.jsch.Logger.WARN -> AppLogger.w(TAG, "[SSH-Handshake] $sanitized")
                    message.contains("version string", ignoreCase = true) ||
                    message.contains("KEXINIT", ignoreCase = true) ||
                    message.contains("NEWKEYS", ignoreCase = true) ||
                    message.contains("Accepting", ignoreCase = true) ||
                    message.contains("Authentication", ignoreCase = true) ||
                    message.contains("Connection established", ignoreCase = true) -> {
                        AppLogger.i(TAG, "[SSH-Handshake] $sanitized")
                    }
                    else -> AppLogger.d(TAG, "[SSH-Handshake] $sanitized")
                }
            }
        })

        val config = java.util.Properties()
        config["StrictHostKeyChecking"] = "no"
        config["PreferredAuthentications"] = if (hasKey) {
            "publickey,password,keyboard-interactive"
        } else {
            "password,keyboard-interactive,publickey"
        }
        session.setConfig(config)
        // JSch timeouts and serverAliveInterval are in milliseconds
        session.timeout = 30_000
        session.serverAliveCountMax = 4

        AppLogger.i(TAG, "Connecting SSH session (handshake and authentication)...")
        session.connect(30_000)

        if (!session.isConnected) {
            throw IllegalStateException("SSH session failed to establish connection to ${effectiveProfile.server}:${effectiveProfile.port}")
        }

        // Send SSH keepalive every 15s to prevent carrier NAT / Cloudflare idle drops
        session.serverAliveInterval = 15_000
        return session
    }

    override suspend fun start(
        profile: VpnProfile,
        vpnService: CustomTunnelVpnService,
        tunFd: Int
    ): Boolean = withContext(Dispatchers.IO) {
        advertisedAuthMethods = ""
        try {
            currentMode = profile.sshMode
            activeVpnService = vpnService

            // Normalize target string if server contains user/pass/port info (e.g. www.openx.com:80@Test:Test1)
            val parsedTarget = if (profile.server.contains("@") || profile.server.startsWith("ssh://", ignoreCase = true) || profile.server.contains(":")) {
                SshTargetParser.parse(profile.server, profile.port)
            } else null

            val effectiveServer = (parsedTarget?.host ?: profile.server).trim()
            val effectivePort = parsedTarget?.port ?: profile.port
            val effectiveUser = (if (profile.sshUsername.isNotBlank() && profile.sshUsername != "root") {
                profile.sshUsername
            } else {
                parsedTarget?.username?.ifBlank { profile.sshUsername.ifBlank { "root" } } ?: profile.sshUsername.ifBlank { "root" }
            }).trim()
            val effectivePass = if (profile.password.isNotBlank()) profile.password else (parsedTarget?.password ?: "")
            val effectiveProfile = profile.copy(
                server = effectiveServer,
                port = effectivePort,
                sshUsername = effectiveUser,
                password = effectivePass
            )
            activeProfile = effectiveProfile

            val hasPass = effectiveProfile.password.isNotEmpty()
            val hasKey = effectiveProfile.sshPrivateKey.isNotBlank()
            AppLogger.i(
                TAG,
                "Initializing SSH [${effectiveProfile.sshMode.displayName}] profile='${effectiveProfile.name}' user='${effectiveProfile.sshUsername}' (password=${if (hasPass) "set" else "empty"}, privateKey=${if (hasKey) "set" else "none"})"
            )
            if (!hasPass && !hasKey) {
                AppLogger.w(TAG, "SSH credentials warning: both password and private key are empty for user '${effectiveProfile.sshUsername}'")
            }

            val session = createAndConnectSession(effectiveProfile, vpnService)
            AppLogger.i(TAG, "SSH session authenticated (${session.serverVersion})")
            jschSession = session

            // 4. Configure Local or Remote Port Forwarding if requested
            if (profile.sshMode == SshTunnelMode.LOCAL_PORT_FORWARDING) {
                try {
                    val bound = session.setPortForwardingL(
                        profile.sshLocalForwardPort,
                        profile.sshRemoteForwardHost.ifBlank { "127.0.0.1" },
                        profile.sshRemoteForwardPort
                    )
                    AppLogger.i(TAG, "Local Port Forwarding active on 127.0.0.1:$bound -> ${profile.sshRemoteForwardHost}:${profile.sshRemoteForwardPort}")
                } catch (e: Exception) {
                    AppLogger.w(TAG, "Local port forwarding note: ${e.message}")
                }
            } else if (profile.sshMode == SshTunnelMode.REMOTE_PORT_FORWARDING) {
                try {
                    session.setPortForwardingR(
                        profile.sshRemoteListenPort,
                        profile.sshRemoteForwardHost.ifBlank { "127.0.0.1" },
                        profile.sshRemoteForwardPort
                    )
                    AppLogger.i(TAG, "Remote Port Forwarding active on remote :${profile.sshRemoteListenPort} -> local ${profile.sshRemoteForwardHost}:${profile.sshRemoteForwardPort}")
                } catch (e: Exception) {
                    AppLogger.w(TAG, "Remote port forwarding rejected by server (server GatewayPorts policy): ${e.message}")
                }
            }

            // 5. Start high-performance local SOCKS5 server on 127.0.0.1:$localSocksPort
            AppLogger.i(TAG, "Starting local SOCKS5 router on 127.0.0.1:$localSocksPort")
            val sSocket = ServerSocket(localSocksPort, 128, InetAddress.getByName("127.0.0.1"))
            serverSocket = sSocket

            startSocksServer(sSocket)

            // 6. Attach HEV SOCKS5 tunnel forwarder to our local SOCKS5 router with mapdns enabled
            // so UDP port-53 DNS requests are mapped in 0.05ms to SOCKS5 domain-name direct-tcpip channels
            val primaryDns = effectiveProfile.dnsPrimary.ifBlank { "1.1.1.1" }
            val hevStarted = HevTunnelManager.start(
                context = vpnService,
                tunFd = tunFd,
                socksAddress = "127.0.0.1",
                socksPort = localSocksPort,
                udpMode = "tcp",
                mapDnsAddress = primaryDns
            )

            if (!hevStarted) {
                AppLogger.e(TAG, "HEV forwarder failed to attach to SSH SOCKS5 port")
                stop()
                throw IllegalStateException("Failed to attach TUN-to-SOCKS5 forwarder to SSH engine")
            }

            isEngineRunning = true

            vpnService.notifyTunnelEstablished(
                effectiveProfile.name,
                "SSH session authenticated, verifying internet forwarding..."
            )
            lastConnectivityResult = verifySshOutboundForwarding(session, effectiveProfile)

            AppLogger.i(TAG, "SSH Tunnel Engine and HEV forwarder running [${profile.sshMode.displayName}]")
            true
        } catch (e: Throwable) {
            val userFriendlyMsg = when {
                e is java.net.ConnectException -> "Connection refused: Unable to connect to ${profile.server}:${profile.port}"
                e is java.net.SocketTimeoutException -> "Connection timed out connecting to ${profile.server}:${profile.port}"
                e.message?.contains("Auth fail", ignoreCase = true) == true ||
                e.message?.contains("Auth cancel", ignoreCase = true) == true -> {
                    val userUsed = activeProfile?.sshUsername ?: profile.sshUsername
                    val passState = if ((activeProfile?.password ?: profile.password).isNotEmpty()) "provided" else "EMPTY"
                    val keyState = if ((activeProfile?.sshPrivateKey ?: profile.sshPrivateKey).isNotBlank()) "provided" else "none"
                    val methodsNote = if (advertisedAuthMethods.isNotBlank()) " (server methods: $advertisedAuthMethods)" else ""
                    "SSH Authentication failed for user '$userUsed'$methodsNote [password=$passState, key=$keyState]: Server rejected credentials or account is expired/disabled"
                }
                e.message?.contains("rekeying", ignoreCase = true) == true -> "SSH key exchange timed out or transport desynchronized: ${e.message}"
                e.message?.contains("400", ignoreCase = true) == true -> e.message ?: "HTTP 400 Bad Request from server"
                e.message?.contains("rejected", ignoreCase = true) == true -> e.message ?: "Server rejected HTTP tunnel"
                e.message?.contains("handshake", ignoreCase = true) == true -> e.message ?: "Transport handshake failed"
                e.message?.contains("banner", ignoreCase = true) == true -> e.message ?: "Invalid SSH server banner"
                else -> e.message ?: "Error starting SSH engine"
            }
            AppLogger.e(TAG, userFriendlyMsg, e)
            stop()
            throw IllegalStateException(userFriendlyMsg, e)
        }
    }

    internal fun createSshUserInfo(password: String, passphrase: String): UserInfo {
        return object : UserInfo, UIKeyboardInteractive {
            override fun getPassphrase(): String? = passphrase.ifEmpty { null }
            override fun getPassword(): String? = password.ifEmpty { null }
            override fun promptPassword(message: String?): Boolean = password.isNotEmpty()
            override fun promptPassphrase(message: String?): Boolean = passphrase.isNotEmpty()
            override fun promptYesNo(message: String?): Boolean = true
            override fun showMessage(message: String?) {
                if (!message.isNullOrBlank()) {
                    AppLogger.d(TAG, "[SSH-Banner] ${AppLogger.redact(message.trim())}")
                }
            }

            override fun promptKeyboardInteractive(
                destination: String?,
                name: String?,
                instruction: String?,
                prompt: Array<out String>?,
                echo: BooleanArray?
            ): Array<String>? {
                if (prompt == null || prompt.isEmpty()) return emptyArray()
                if (password.isEmpty()) return null
                return Array(prompt.size) { password }
            }
        }
    }

    private fun verifySshOutboundForwarding(session: Session, profile: VpnProfile): ConnectivityCheckResult {
        val dnsProbeHost = profile.dnsPrimary.ifBlank { "1.1.1.1" }
        val startMs = System.currentTimeMillis()
        return try {
            val probeChannel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            probeChannel.setHost(dnsProbeHost)
            probeChannel.setPort(53)
            probeChannel.connect(3500)
            val rtt = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
            probeChannel.disconnect()
            AppLogger.i(TAG, "Verified SSH direct-tcpip outbound forwarding via $dnsProbeHost:53 (${rtt} ms)")
            ConnectivityCheckResult(
                verified = true,
                rttMs = rtt,
                endpoint = "$dnsProbeHost:53",
                failureCategory = ProbeFailureCategory.NONE,
                diagnosticMessage = "Internet Verified (${rtt} ms via SSH direct-tcpip)"
            )
        } catch (e: Exception) {
            val errMsg = e.message ?: "SSH direct-tcpip channel failed"
            AppLogger.w(
                TAG,
                "SSH direct-tcpip probe to $dnsProbeHost:53 failed ($errMsg); tunnel is up but internet forwarding is unverified"
            )
            ConnectivityCheckResult(
                verified = false,
                rttMs = null,
                endpoint = "$dnsProbeHost:53",
                failureCategory = ProbeFailureCategory.BLOCKED_PROBE,
                diagnosticMessage = "Tunnel Connected — Internet Unverified (SSH forward probe: $errMsg)"
            )
        }
    }

    private fun pruneClosedChannels() {
        activeChannels.removeAll { it.isClosed || it.isEOF || !it.isConnected }
    }

    private fun startSocksServer(serverSocket: ServerSocket) {
        serverJob?.cancel()
        serverJob = engineScope.launch {
            while (isActive && !serverSocket.isClosed) {
                try {
                    val clientSocket = serverSocket.accept()
                    val session = jschSession
                    if (session == null || !session.isConnected) {
                        try { clientSocket.close() } catch (_: Exception) {}
                        continue
                    }
                    launch { handleSocksClient(clientSocket, session) }
                } catch (e: Exception) {
                    if (serverSocket.isClosed) break
                }
            }
        }
    }

    internal fun handleSocksClient(clientSocket: Socket, session: Session) {
        try {
            try {
                clientSocket.tcpNoDelay = true
                clientSocket.keepAlive = true
                clientSocket.soTimeout = 120_000
                clientSocket.receiveBufferSize = 131072
                clientSocket.sendBufferSize = 131072
            } catch (_: Exception) {}

            val rawIn = clientSocket.getInputStream()
            val rawOut = clientSocket.getOutputStream()
            val bufferedIn = BufferedInputStream(rawIn, 32768)
            val input = DataInputStream(bufferedIn)

            // SOCKS5 greeting
            val ver = input.readByte().toInt()
            if (ver != 0x05) {
                clientSocket.close()
                return
            }
            val nmethods = input.readByte().toInt() and 0xFF
            val methods = ByteArray(nmethods)
            input.readFully(methods)

            // Respond NO_AUTH (0x05, 0x00) directly to rawOut
            rawOut.write(byteArrayOf(0x05, 0x00))
            rawOut.flush()

            // SOCKS5 request
            val reqVer = input.readByte().toInt()
            val cmd = input.readByte().toInt() // 0x01 = CONNECT
            val rsv = input.readByte().toInt()
            val atyp = input.readByte().toInt()

            if (cmd != 0x01) {
                rawOut.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                rawOut.flush()
                clientSocket.close()
                return
            }

            val targetHost: String = when (atyp) {
                0x01 -> { // IPv4
                    val ip = ByteArray(4)
                    input.readFully(ip)
                    InetAddress.getByAddress(ip).hostAddress ?: "127.0.0.1"
                }
                0x03 -> { // Domain name
                    val len = input.readByte().toInt() and 0xFF
                    val domainBytes = ByteArray(len)
                    input.readFully(domainBytes)
                    String(domainBytes, Charsets.UTF_8)
                }
                0x04 -> { // IPv6
                    val ip6 = ByteArray(16)
                    input.readFully(ip6)
                    InetAddress.getByAddress(ip6).hostAddress ?: "::1"
                }
                else -> {
                    clientSocket.close()
                    return
                }
            }
            val targetPort = input.readUnsignedShort()

            if (activeChannels.size > 24) {
                pruneClosedChannels()
            }

            // Open SSH Direct-TCPIP Channel
            val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(targetHost)
            channel.setPort(targetPort)

            // Send SOCKS5 success response BEFORE binding JSch streams to clientSocket
            // so remote payload bytes never interleave with the SOCKS5 handshake reply
            rawOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            rawOut.flush()

            val cleanedUp = AtomicBoolean(false)
            fun releaseChannelAndSocket() {
                if (cleanedUp.compareAndSet(false, true)) {
                    activeChannels.remove(channel)
                    try {
                        if (!channel.isClosed) {
                            channel.disconnect()
                        }
                    } catch (_: Exception) {}
                    try {
                        if (!clientSocket.isClosed) {
                            clientSocket.close()
                        }
                    } catch (_: Exception) {}
                }
            }

            // Lifecycle-aware InputStream: when local socket reaches EOF or errors,
            // immediately closes clientSocket and disconnects the SSH channel so JSch's DirectTCPIP thread exits cleanly.
            val managedIn: InputStream = object : FilterInputStream(bufferedIn) {
                override fun read(): Int {
                    return try {
                        val r = super.read()
                        if (r == -1) releaseChannelAndSocket()
                        r
                    } catch (e: IOException) {
                        releaseChannelAndSocket()
                        throw e
                    }
                }

                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    return try {
                        val r = super.read(b, off, len)
                        if (r == -1) releaseChannelAndSocket()
                        r
                    } catch (e: IOException) {
                        releaseChannelAndSocket()
                        throw e
                    }
                }

                override fun close() {
                    try {
                        super.close()
                    } finally {
                        releaseChannelAndSocket()
                    }
                }
            }

            // CRITICAL: Do NOT wrap rawOut in BufferedOutputStream here!
            // JSch's Session.run() writes SSH_MSG_CHANNEL_DATA via out.write(buf, s, len) WITHOUT calling out.flush().
            // Writing directly to rawOut guarantees immediate delivery of TLS ServerHello, HTTP headers, and tail frames,
            // while close() guarantees clientSocket is closed when the remote server closes the SSH channel.
            val managedOut: OutputStream = object : OutputStream() {
                override fun write(b: Int) {
                    try {
                        rawOut.write(b)
                    } catch (e: IOException) {
                        releaseChannelAndSocket()
                        throw e
                    }
                }

                override fun write(b: ByteArray, off: Int, len: Int) {
                    try {
                        rawOut.write(b, off, len)
                    } catch (e: IOException) {
                        releaseChannelAndSocket()
                        throw e
                    }
                }

                override fun flush() {
                    try {
                        rawOut.flush()
                    } catch (e: IOException) {
                        releaseChannelAndSocket()
                        throw e
                    }
                }

                override fun close() {
                    releaseChannelAndSocket()
                }
            }

            channel.setInputStream(managedIn)
            channel.setOutputStream(managedOut)
            try {
                channel.connect(8000)
                activeChannels.add(channel)
            } catch (e: Exception) {
                releaseChannelAndSocket()
            }
        } catch (e: Exception) {
            try { clientSocket.close() } catch (ignored: Exception) {}
        }
    }

    override suspend fun stop() = withContext(Dispatchers.IO) {
        try {
            AppLogger.i(TAG, "Stopping SSH Engine and releasing resources")
            isEngineRunning = false
            activeVpnService = null
            HevTunnelManager.stop()

            serverJob?.cancel()
            serverJob = null

            try {
                serverSocket?.close()
                serverSocket = null
            } catch (e: Exception) {}

            for (ch in activeChannels) {
                try { ch.disconnect() } catch (e: Exception) {}
            }
            activeChannels.clear()

            jschSession?.let {
                if (it.isConnected) {
                    it.disconnect()
                }
            }
            jschSession = null
        } catch (e: Throwable) {
            AppLogger.e(TAG, "Error stopping SSH engine: ${e.message}", e)
        }
    }
}

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
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

class SshEngineAdapter : VpnEngineAdapter {
    private val TAG = "SshEngine"
    private var jschSession: Session? = null
    private var serverSocket: ServerSocket? = null
    private var isEngineRunning = false
    private val localSocksPort = 10809
    private var serverJob: Job? = null
    private val activeChannels = CopyOnWriteArrayList<ChannelDirectTCPIP>()
    private val engineScope = CoroutineScope(Dispatchers.IO + Job())
    private var currentMode: SshTunnelMode = SshTunnelMode.DIRECT
    private var activeProfile: VpnProfile? = null
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

    override suspend fun start(
        profile: VpnProfile,
        vpnService: CustomTunnelVpnService,
        tunFd: Int
    ): Boolean = withContext(Dispatchers.IO) {
        var advertisedAuthMethods = ""
        try {
            currentMode = profile.sshMode

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

            val jsch = JSch()

            // 1. Configure Private Key identity if provided
            if (hasKey) {
                val keyBytes = effectiveProfile.sshPrivateKey.trim().toByteArray(Charsets.UTF_8)
                val passBytes = if (effectiveProfile.sshPassphrase.isNotBlank()) {
                    effectiveProfile.sshPassphrase.toByteArray(Charsets.UTF_8)
                } else null
                jsch.addIdentity("user_key", keyBytes, null, passBytes)
                AppLogger.i(TAG, "Configured SSH private key authentication for user '${effectiveProfile.sshUsername}'")
            }

            // 2. Set custom transport socket factory supporting all modes
            val customSocketFactory = SshSocketFactory(effectiveProfile, vpnService)

            val session = jsch.getSession(effectiveProfile.sshUsername, effectiveProfile.server, effectiveProfile.port)
            if (hasPass) {
                session.setPassword(effectiveProfile.password)
            }
            // Provide UserInfo + UIKeyboardInteractive so servers using PAM / keyboard-interactive password prompts succeed
            session.userInfo = createSshUserInfo(effectiveProfile.password, effectiveProfile.sshPassphrase)
            session.setSocketFactory(customSocketFactory)

            // 3. Security, handshake stage logging, and connection configuration
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
            // NOTE: JSch timeouts and serverAliveInterval are in MILLISECONDS (not seconds).
            session.timeout = 30_000
            session.serverAliveCountMax = 3

            AppLogger.i(TAG, "Connecting SSH session (handshake and authentication)...")
            session.connect(30_000)

            if (!session.isConnected) {
                AppLogger.e(TAG, "SSH session connection failed")
                throw IllegalStateException("SSH session failed to establish connection to ${effectiveProfile.server}:${effectiveProfile.port}")
            }

            session.serverAliveInterval = 30_000
            AppLogger.i(TAG, "SSH session authenticated (${session.serverVersion})")
            jschSession = session

            vpnService.notifyTunnelEstablished(
                effectiveProfile.name,
                "SSH session authenticated, verifying internet forwarding..."
            )
            lastConnectivityResult = verifySshOutboundForwarding(session, effectiveProfile)

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
            val sSocket = ServerSocket(localSocksPort, 50, InetAddress.getByName("127.0.0.1"))
            serverSocket = sSocket

            startSocksServer(sSocket, session)

            // 6. Attach HEV SOCKS5 tunnel forwarder to our local SOCKS5 router
            val hevStarted = HevTunnelManager.start(
                context = vpnService,
                tunFd = tunFd,
                socksAddress = "127.0.0.1",
                socksPort = localSocksPort
            )

            if (!hevStarted) {
                AppLogger.e(TAG, "HEV forwarder failed to attach to SSH SOCKS5 port")
                stop()
                throw IllegalStateException("Failed to attach TUN-to-SOCKS5 forwarder to SSH engine")
            }

            isEngineRunning = true
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
            probeChannel.connect(8000)
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

    private fun startSocksServer(serverSocket: ServerSocket, session: Session) {
        serverJob?.cancel()
        serverJob = engineScope.launch {
            while (isActive && !serverSocket.isClosed) {
                try {
                    val clientSocket = serverSocket.accept()
                    launch { handleSocksClient(clientSocket, session) }
                } catch (e: Exception) {
                    if (serverSocket.isClosed) break
                }
            }
        }
    }

    private fun handleSocksClient(clientSocket: Socket, session: Session) {
        try {
            val input = DataInputStream(clientSocket.getInputStream())
            val output = DataOutputStream(clientSocket.getOutputStream())

            // SOCKS5 greeting
            val ver = input.readByte().toInt()
            if (ver != 0x05) {
                clientSocket.close()
                return
            }
            val nmethods = input.readByte().toInt()
            val methods = ByteArray(nmethods)
            input.readFully(methods)

            // Respond NO_AUTH (0x05, 0x00)
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // SOCKS5 request
            val reqVer = input.readByte().toInt()
            val cmd = input.readByte().toInt() // 0x01 = CONNECT
            val rsv = input.readByte().toInt()
            val atyp = input.readByte().toInt()

            if (cmd != 0x01) {
                output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                output.flush()
                clientSocket.close()
                return
            }

            val targetHost: String
            when (atyp) {
                0x01 -> { // IPv4
                    val ip = ByteArray(4)
                    input.readFully(ip)
                    targetHost = InetAddress.getByAddress(ip).hostAddress ?: "127.0.0.1"
                }
                0x03 -> { // Domain name
                    val len = input.readByte().toInt() and 0xFF
                    val domainBytes = ByteArray(len)
                    input.readFully(domainBytes)
                    targetHost = String(domainBytes, Charsets.UTF_8)
                }
                0x04 -> { // IPv6
                    val ip6 = ByteArray(16)
                    input.readFully(ip6)
                    targetHost = InetAddress.getByAddress(ip6).hostAddress ?: "::1"
                }
                else -> {
                    clientSocket.close()
                    return
                }
            }
            val targetPort = input.readUnsignedShort()

            // Prune already closed channels to prevent unbounded memory growth during long sessions
            activeChannels.removeAll { it.isClosed || !it.isConnected }

            // Open SSH Direct-TCPIP Channel
            val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(targetHost)
            channel.setPort(targetPort)

            // Send SOCKS5 success response BEFORE binding JSch streams to clientSocket
            // so remote payload bytes never interleave with the SOCKS5 handshake reply
            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()

            channel.setInputStream(clientSocket.getInputStream())
            channel.setOutputStream(clientSocket.getOutputStream())
            channel.connect(8000)

            activeChannels.add(channel)
        } catch (e: Exception) {
            try { clientSocket.close() } catch (ignored: Exception) {}
        }
    }

    override suspend fun stop() = withContext(Dispatchers.IO) {
        try {
            AppLogger.i(TAG, "Stopping SSH Engine and releasing resources")
            isEngineRunning = false
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

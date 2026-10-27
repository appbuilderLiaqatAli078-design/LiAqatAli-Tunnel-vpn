package com.example.vpn.engine

import com.example.data.AppLogger
import com.example.model.SshTunnelMode
import com.example.model.VpnProfile
import com.example.parser.SshTargetParser
import com.example.vpn.AegisVpnService
import com.example.vpn.engine.ssh.SshSocketFactory
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
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

    override fun getEngineName(): String = "SSH Engine (${currentMode.badge})"
    override fun getLocalSocksPort(): Int = localSocksPort
    override fun isRunning(): Boolean = isEngineRunning

    override suspend fun start(
        profile: VpnProfile,
        vpnService: AegisVpnService,
        tunFd: Int
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            currentMode = profile.sshMode

            // Normalize target string if server contains user/pass/port info (e.g. www.openx.com:80@Test:Test1)
            val parsedTarget = if (profile.server.contains("@") || profile.server.startsWith("ssh://")) {
                SshTargetParser.parse(profile.server, profile.port)
            } else null

            val effectiveServer = parsedTarget?.host ?: profile.server
            val effectivePort = parsedTarget?.port ?: profile.port
            val effectiveUser = if (profile.sshUsername.isNotBlank()) profile.sshUsername else (parsedTarget?.username?.ifBlank { "root" } ?: "root")
            val effectivePass = if (profile.password.isNotBlank()) profile.password else (parsedTarget?.password ?: "")
            val effectiveProfile = profile.copy(
                server = effectiveServer,
                port = effectivePort,
                sshUsername = effectiveUser,
                password = effectivePass
            )

            AppLogger.i(TAG, "Initializing SSH [${effectiveProfile.sshMode.displayName}] to ${effectiveProfile.server}:${effectiveProfile.port}")
            val jsch = JSch()

            // 1. Configure Private Key identity if provided
            if (effectiveProfile.sshPrivateKey.isNotBlank()) {
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
            if (effectiveProfile.password.isNotBlank()) {
                session.setPassword(effectiveProfile.password)
            }
            session.setSocketFactory(customSocketFactory)

            // 3. Security and connection configuration
            val config = java.util.Properties()
            config["StrictHostKeyChecking"] = "no"
            config["PreferredAuthentications"] = "publickey,password,keyboard-interactive"
            session.setConfig(config)
            session.serverAliveInterval = 30
            session.serverAliveCountMax = 3

            AppLogger.i(TAG, "Connecting SSH session (handshake and authentication)...")
            session.connect(30000)

            if (!session.isConnected) {
                AppLogger.e(TAG, "SSH session connection failed")
                return@withContext false
            }

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
                return@withContext false
            }

            isEngineRunning = true
            AppLogger.i(TAG, "SSH Tunnel Engine and HEV forwarder successfully running [${profile.sshMode.displayName}]")
            true
        } catch (e: Throwable) {
            val userFriendlyMsg = when {
                e is java.net.ConnectException -> "Connection refused: Unable to connect to ${profile.server}:${profile.port}"
                e is java.net.SocketTimeoutException -> "Connection timed out connecting to ${profile.server}:${profile.port}"
                e.message?.contains("Auth fail", ignoreCase = true) == true -> "SSH Authentication failed: Invalid username or password/key"
                e.message?.contains("rekeying", ignoreCase = true) == true -> "SSH key exchange timed out or transport desynchronized: ${e.message}"
                e.message?.contains("rejected", ignoreCase = true) == true -> e.message ?: "Server rejected HTTP tunnel"
                e.message?.contains("handshake", ignoreCase = true) == true -> e.message ?: "Transport handshake failed"
                else -> "Error starting SSH engine: ${e.message}"
            }
            AppLogger.e(TAG, userFriendlyMsg, e)
            stop()
            false
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

            // Open SSH Direct-TCPIP Channel
            val channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(targetHost)
            channel.setPort(targetPort)
            channel.setInputStream(clientSocket.getInputStream())
            channel.setOutputStream(clientSocket.getOutputStream())
            channel.connect(8000)

            activeChannels.add(channel)

            // Success response
            output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            output.flush()
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

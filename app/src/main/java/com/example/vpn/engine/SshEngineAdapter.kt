package com.example.vpn.engine

import com.example.data.AppLogger
import com.example.model.VpnProfile
import com.example.vpn.AegisVpnService
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
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

    override fun getEngineName(): String = "SSH / Injector Engine"
    override fun getLocalSocksPort(): Int = localSocksPort
    override fun isRunning(): Boolean = isEngineRunning

    override suspend fun start(
        profile: VpnProfile,
        vpnService: AegisVpnService,
        tunFd: Int
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            AppLogger.i(TAG, "Initializing SSH connection to ${profile.server}:${profile.port}")
            val jsch = JSch()

            val customSocketFactory = object : SocketFactory {
                override fun createSocket(host: String, port: Int): Socket {
                    val socket = Socket()
                    AppLogger.i(TAG, "Protecting upstream SSH socket with VpnService.protect()")
                    vpnService.protect(socket)

                    PayloadInjector.injectAndConnect(
                        socket = socket,
                        targetHost = host,
                        targetPort = port,
                        proxyHost = profile.proxyHost,
                        proxyPort = profile.proxyPort,
                        payload = profile.sshPayload,
                        timeoutMs = 12000
                    )
                    return socket
                }

                override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()
                override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()
            }

            val session = jsch.getSession(profile.sshUsername, profile.server, profile.port)
            session.setPassword(profile.password)
            session.setSocketFactory(customSocketFactory)

            // SSH configuration
            val config = java.util.Properties()
            config["StrictHostKeyChecking"] = "no"
            config["PreferredAuthentications"] = "password,publickey,keyboard-interactive"
            session.setConfig(config)
            session.serverAliveInterval = 30
            session.serverAliveCountMax = 3

            AppLogger.i(TAG, "Connecting SSH session (handshake and authentication)...")
            session.connect(15000)

            if (!session.isConnected) {
                AppLogger.e(TAG, "SSH session connection failed")
                return@withContext false
            }

            AppLogger.i(TAG, "SSH connected. Starting local SOCKS5 proxy server on 127.0.0.1:$localSocksPort")
            val sSocket = ServerSocket(localSocksPort, 50, InetAddress.getByName("127.0.0.1"))
            serverSocket = sSocket
            jschSession = session

            startSocksServer(sSocket, session)

            // Now start HEV SOCKS5 tunnel pointing to this local SOCKS5 proxy
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
            AppLogger.i(TAG, "SSH Engine and HEV TUN forwarder successfully running")
            true
        } catch (e: Throwable) {
            AppLogger.e(TAG, "Error starting SSH engine: ${e.message}", e)
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
                // Command not supported
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
            AppLogger.i(TAG, "Stopping SSH Engine and releasing ports")
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

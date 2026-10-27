package com.example.vpn.engine.ssh

import com.example.data.AppLogger
import com.example.model.SshTunnelMode
import com.example.model.VpnProfile
import com.example.vpn.AegisVpnService
import com.example.vpn.engine.PayloadInjector
import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

class SshSocketFactory(
    private val profile: VpnProfile,
    private val vpnService: AegisVpnService,
    private val timeoutMs: Int = 30000
) : SocketFactory {

    private val TAG = "SshSocketFactory"

    override fun createSocket(host: String, port: Int): Socket {
        val rawSocket = Socket()
        try {
            // Pre-bind to an ephemeral local port so Android's PlainSocketImpl allocates
            // the native OS FileDescriptor before VpnService.protect(), while preserving
            // standard full-duplex SocketInputStream/SocketOutputStream without NIO blockingLock contention.
            rawSocket.bind(null)
        } catch (_: Exception) {}
        val isProtected = try {
            vpnService.protect(rawSocket)
        } catch (e: Exception) {
            false
        }
        AppLogger.i(TAG, "Protecting upstream SSH socket with VpnService.protect(): success=$isProtected")

        val sniHost = profile.sshSni.ifBlank { profile.sni.ifBlank { host } }
        val hostHeader = sniHost.ifBlank { "$host:$port" }

        AppLogger.i(TAG, "Establishing transport for SSH mode: ${profile.sshMode.displayName} to $host:$port")

        return when (profile.sshMode) {
            SshTunnelMode.DIRECT -> {
                if (profile.sshPayload.isNotBlank()) {
                    PayloadInjector.injectAndConnect(
                        socket = rawSocket,
                        targetHost = host,
                        targetPort = port,
                        proxyHost = "",
                        proxyPort = 0,
                        payload = profile.sshPayload,
                        proxyUser = profile.sshProxyUser,
                        proxyPass = profile.sshProxyPass,
                        timeoutMs = timeoutMs,
                        onConnected = { vpnService.protect(it) }
                    )
                } else {
                    rawSocket.connect(InetSocketAddress(host, port), timeoutMs)
                    try { vpnService.protect(rawSocket) } catch (ignored: Exception) {}
                    rawSocket
                }
            }

            SshTunnelMode.HTTP_PROXY, SshTunnelMode.HTTP_CONNECT -> {
                val pHost = profile.proxyHost.ifBlank { host }
                val pPort = if (profile.proxyPort > 0) profile.proxyPort else 8080
                SshProxyHandler.connectHttpProxy(
                    socket = rawSocket,
                    proxyHost = pHost,
                    proxyPort = pPort,
                    targetHost = host,
                    targetPort = port,
                    proxyUser = profile.sshProxyUser,
                    proxyPass = profile.sshProxyPass,
                    customHeaders = profile.sshCustomHeaders,
                    timeoutMs = timeoutMs
                )
                try { vpnService.protect(rawSocket) } catch (ignored: Exception) {}
                rawSocket
            }

            SshTunnelMode.CUSTOM_PAYLOAD -> {
                PayloadInjector.injectAndConnect(
                    socket = rawSocket,
                    targetHost = host,
                    targetPort = port,
                    proxyHost = profile.proxyHost,
                    proxyPort = profile.proxyPort,
                    payload = profile.sshPayload,
                    proxyUser = profile.sshProxyUser,
                    proxyPass = profile.sshProxyPass,
                    timeoutMs = timeoutMs,
                    onConnected = { vpnService.protect(it) }
                )
            }

            SshTunnelMode.SSL_TLS -> {
                if (profile.proxyHost.isNotBlank() && profile.proxyPort > 0) {
                    SshProxyHandler.connectHttpProxy(
                        socket = rawSocket,
                        proxyHost = profile.proxyHost,
                        proxyPort = profile.proxyPort,
                        targetHost = host,
                        targetPort = port,
                        proxyUser = profile.sshProxyUser,
                        proxyPass = profile.sshProxyPass,
                        timeoutMs = timeoutMs
                    )
                } else {
                    rawSocket.connect(InetSocketAddress(host, port), timeoutMs)
                }
                try { vpnService.protect(rawSocket) } catch (ignored: Exception) {}
                SshTlsHandler.wrapTls(
                    underlyingSocket = rawSocket,
                    sniHost = sniHost,
                    targetPort = port,
                    allowInsecure = profile.allowInsecureSsl,
                    handshakeTimeoutMs = timeoutMs
                )
            }

            SshTunnelMode.WEBSOCKET -> {
                val connectHost = if (profile.proxyHost.isNotBlank() && profile.proxyPort > 0) profile.proxyHost else host
                val connectPort = if (profile.proxyHost.isNotBlank() && profile.proxyPort > 0) profile.proxyPort else port
                rawSocket.connect(InetSocketAddress(connectHost, connectPort), timeoutMs)
                try { vpnService.protect(rawSocket) } catch (ignored: Exception) {}

                SshWebSocketHandler.upgradeWebSocket(
                    socket = rawSocket,
                    wsPath = profile.sshWsPath.ifBlank { "/ssh" },
                    hostHeader = hostHeader,
                    customHeaders = profile.sshCustomHeaders,
                    timeoutMs = timeoutMs
                )
            }

            SshTunnelMode.SECURE_WEBSOCKET, SshTunnelMode.SSL_WEBSOCKET -> {
                val connectHost = if (profile.proxyHost.isNotBlank() && profile.proxyPort > 0) profile.proxyHost else host
                val connectPort = if (profile.proxyHost.isNotBlank() && profile.proxyPort > 0) profile.proxyPort else port
                rawSocket.connect(InetSocketAddress(connectHost, connectPort), timeoutMs)
                try { vpnService.protect(rawSocket) } catch (ignored: Exception) {}

                val tlsSocket = SshTlsHandler.wrapTls(
                    underlyingSocket = rawSocket,
                    sniHost = sniHost,
                    targetPort = port,
                    allowInsecure = profile.allowInsecureSsl,
                    handshakeTimeoutMs = timeoutMs
                )

                SshWebSocketHandler.upgradeWebSocket(
                    socket = tlsSocket,
                    wsPath = profile.sshWsPath.ifBlank { "/ssh" },
                    hostHeader = hostHeader,
                    customHeaders = profile.sshCustomHeaders,
                    timeoutMs = timeoutMs
                )
            }

            SshTunnelMode.SOCKS4 -> {
                val pHost = profile.proxyHost.ifBlank { "127.0.0.1" }
                val pPort = if (profile.proxyPort > 0) profile.proxyPort else 1080
                SshProxyHandler.connectSocks4(
                    socket = rawSocket,
                    proxyHost = pHost,
                    proxyPort = pPort,
                    targetHost = host,
                    targetPort = port,
                    userId = profile.sshProxyUser.ifBlank { "aegis" },
                    timeoutMs = timeoutMs
                )
                rawSocket
            }

            SshTunnelMode.SOCKS5 -> {
                val pHost = profile.proxyHost.ifBlank { "127.0.0.1" }
                val pPort = if (profile.proxyPort > 0) profile.proxyPort else 1080
                SshProxyHandler.connectSocks5(
                    socket = rawSocket,
                    proxyHost = pHost,
                    proxyPort = pPort,
                    targetHost = host,
                    targetPort = port,
                    username = profile.sshProxyUser,
                    password = profile.sshProxyPass,
                    timeoutMs = timeoutMs
                )
                rawSocket
            }

            SshTunnelMode.PROXY_CHAIN -> {
                val hop1Host = profile.proxyHost.ifBlank { "127.0.0.1" }
                val hop1Port = if (profile.proxyPort > 0) profile.proxyPort else 1080
                val hop2Host = profile.sshChainProxyHost.ifBlank { host }
                val hop2Port = if (profile.sshChainProxyPort > 0) profile.sshChainProxyPort else 8080
                SshProxyHandler.connectProxyChain(
                    socket = rawSocket,
                    hop1Host = hop1Host,
                    hop1Port = hop1Port,
                    hop1Type = "SOCKS5",
                    hop2Host = hop2Host,
                    hop2Port = hop2Port,
                    hop2Type = profile.sshChainProxyType,
                    targetHost = host,
                    targetPort = port,
                    timeoutMs = timeoutMs
                )
                rawSocket
            }

            SshTunnelMode.LOCAL_PORT_FORWARDING,
            SshTunnelMode.REMOTE_PORT_FORWARDING,
            SshTunnelMode.DYNAMIC_PORT_FORWARDING -> {
                // If proxy configured, route through proxy; otherwise direct
                if (profile.proxyHost.isNotBlank() && profile.proxyPort > 0) {
                    SshProxyHandler.connectHttpProxy(
                        socket = rawSocket,
                        proxyHost = profile.proxyHost,
                        proxyPort = profile.proxyPort,
                        targetHost = host,
                        targetPort = port,
                        proxyUser = profile.sshProxyUser,
                        proxyPass = profile.sshProxyPass,
                        timeoutMs = timeoutMs
                    )
                } else {
                    rawSocket.connect(InetSocketAddress(host, port), timeoutMs)
                }
                rawSocket
            }
        }
    }

    override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()
    override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()
}

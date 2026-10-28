package com.example.vpn.engine.ssh

import android.util.Base64
import com.example.data.AppLogger
import com.example.vpn.engine.PayloadInjector
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

object SshProxyHandler {
    private const val TAG = "SshProxyHandler"

    fun connectHttpProxy(
        socket: Socket,
        proxyHost: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int,
        proxyUser: String = "",
        proxyPass: String = "",
        customHeaders: String = "",
        timeoutMs: Int = 10000
    ) {
        if (!socket.isConnected) {
            AppLogger.i(TAG, "Connecting TCP to HTTP proxy $proxyHost:$proxyPort")
            socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
        }
        socket.soTimeout = timeoutMs

        val authHeader = if (proxyUser.isNotBlank()) {
            val creds = Base64.encodeToString("$proxyUser:$proxyPass".toByteArray(), Base64.NO_WRAP)
            "Proxy-Authorization: Basic $creds\r\n"
        } else ""

        val request = StringBuilder()
        request.append("CONNECT $targetHost:$targetPort HTTP/1.1\r\n")
        request.append("Host: $targetHost:$targetPort\r\n")
        request.append("Proxy-Connection: Keep-Alive\r\n")
        request.append("User-Agent: Mozilla/5.0 (Android; Mobile; CustomTunnelPro)\r\n")
        if (authHeader.isNotEmpty()) request.append(authHeader)

        if (customHeaders.isNotBlank()) {
            customHeaders.split("\n").forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isNotEmpty() && trimmed.contains(":")) {
                    request.append("$trimmed\r\n")
                }
            }
        }
        request.append("\r\n")

        val output: OutputStream = socket.getOutputStream()
        output.write(request.toString().toByteArray(Charsets.UTF_8))
        output.flush()

        val input: InputStream = socket.getInputStream()
        val statusLine = PayloadInjector.readLine(input)
        AppLogger.i(TAG, "HTTP Proxy status: $statusLine")

        if (statusLine == null || !statusLine.contains("200")) {
            val hint = if (statusLine?.contains("400") == true) {
                " ($proxyHost:$proxyPort returned HTTP 400 Bad Request to CONNECT — this server is an HTTP/CDN endpoint that does not allow raw HTTP CONNECT proxying; use SSH Direct with Custom Payload or WebSocket mode instead)"
            } else ""
            throw IllegalStateException("HTTP Proxy CONNECT rejected: $statusLine$hint")
        }

        // Consume remaining headers
        var line = PayloadInjector.readLine(input)
        while (!line.isNullOrEmpty()) {
            line = PayloadInjector.readLine(input)
        }
        socket.soTimeout = 0
    }

    fun connectSocks4(
        socket: Socket,
        proxyHost: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int,
        userId: String = "customtunnel",
        timeoutMs: Int = 10000
    ) {
        if (!socket.isConnected) {
            AppLogger.i(TAG, "Connecting TCP to SOCKS4 proxy $proxyHost:$proxyPort")
            socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
        }
        socket.soTimeout = timeoutMs

        val out = DataOutputStream(socket.getOutputStream())
        val inStream = DataInputStream(socket.getInputStream())

        val isIp = try {
            InetAddress.getByName(targetHost)
            true
        } catch (e: Exception) {
            false
        }

        out.writeByte(0x04) // SOCKS version 4
        out.writeByte(0x01) // Command: CONNECT
        out.writeShort(targetPort)

        if (isIp) {
            val addr = InetAddress.getByName(targetHost).address
            out.write(addr)
            out.write(userId.toByteArray(Charsets.UTF_8))
            out.writeByte(0x00)
        } else {
            // SOCKS4a domain support: IP is 0.0.0.x
            out.write(byteArrayOf(0, 0, 0, 1))
            out.write(userId.toByteArray(Charsets.UTF_8))
            out.writeByte(0x00)
            out.write(targetHost.toByteArray(Charsets.UTF_8))
            out.writeByte(0x00)
        }
        out.flush()

        // Read 8-byte reply
        val vn = inStream.readByte().toInt()
        val cd = inStream.readByte().toInt() and 0xFF
        val ignored = ByteArray(6)
        inStream.readFully(ignored)

        if (cd != 0x5A) {
            val msg = when (cd) {
                0x5B -> "Request rejected or failed"
                0x5C -> "Cannot connect to identd on client"
                0x5D -> "Identd reported different user-id"
                else -> "Error code $cd"
            }
            throw IllegalStateException("SOCKS4 proxy error: $msg (cd=$cd)")
        }
        socket.soTimeout = 0
        AppLogger.i(TAG, "SOCKS4 proxy tunnel established to $targetHost:$targetPort")
    }

    fun connectSocks5(
        socket: Socket,
        proxyHost: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int,
        username: String = "",
        password: String = "",
        timeoutMs: Int = 10000
    ) {
        if (!socket.isConnected) {
            AppLogger.i(TAG, "Connecting TCP to SOCKS5 proxy $proxyHost:$proxyPort")
            socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
        }
        socket.soTimeout = timeoutMs

        val out = DataOutputStream(socket.getOutputStream())
        val inStream = DataInputStream(socket.getInputStream())

        // 1. Send version & auth methods
        if (username.isNotBlank()) {
            out.write(byteArrayOf(0x05, 0x02, 0x00, 0x02)) // NO_AUTH and USER/PASS
        } else {
            out.write(byteArrayOf(0x05, 0x01, 0x00)) // NO_AUTH only
        }
        out.flush()

        val ver = inStream.readByte().toInt()
        val authMethod = inStream.readByte().toInt()
        if (ver != 0x05) {
            throw IllegalStateException("Invalid SOCKS5 version reply: $ver")
        }

        // 2. Perform Username/Password subnegotiation if requested
        if (authMethod == 0x02) {
            val userBytes = username.toByteArray(Charsets.UTF_8)
            val passBytes = password.toByteArray(Charsets.UTF_8)
            out.writeByte(0x01) // Subnegotiation version
            out.writeByte(userBytes.size)
            out.write(userBytes)
            out.writeByte(passBytes.size)
            out.write(passBytes)
            out.flush()

            val subVer = inStream.readByte().toInt()
            val status = inStream.readByte().toInt()
            if (status != 0x00) {
                throw IllegalStateException("SOCKS5 authentication failed (status=$status)")
            }
        } else if (authMethod != 0x00) {
            throw IllegalStateException("SOCKS5 unsupported authentication method: $authMethod")
        }

        // 3. Send CONNECT request
        out.writeByte(0x05) // Version
        out.writeByte(0x01) // CONNECT
        out.writeByte(0x00) // Reserved

        // Target address: Domain vs IP
        val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
        out.writeByte(0x03) // Domain name
        out.writeByte(hostBytes.size)
        out.write(hostBytes)
        out.writeShort(targetPort)
        out.flush()

        // 4. Read reply
        val repVer = inStream.readByte().toInt()
        val repStatus = inStream.readByte().toInt()
        val rsv = inStream.readByte().toInt()
        val atyp = inStream.readByte().toInt()

        when (atyp) {
            0x01 -> { val ip = ByteArray(4); inStream.readFully(ip) }
            0x03 -> { val len = inStream.readByte().toInt() and 0xFF; val d = ByteArray(len); inStream.readFully(d) }
            0x04 -> { val ip6 = ByteArray(16); inStream.readFully(ip6) }
        }
        val boundPort = inStream.readUnsignedShort()

        if (repStatus != 0x00) {
            val reason = when (repStatus) {
                0x01 -> "General SOCKS server failure"
                0x02 -> "Connection not allowed by ruleset"
                0x03 -> "Network unreachable"
                0x04 -> "Host unreachable"
                0x05 -> "Connection refused"
                0x06 -> "TTL expired"
                0x07 -> "Command not supported"
                0x08 -> "Address type not supported"
                else -> "Error code $repStatus"
            }
            throw IllegalStateException("SOCKS5 CONNECT failed: $reason (status=$repStatus)")
        }

        socket.soTimeout = 0
        AppLogger.i(TAG, "SOCKS5 proxy tunnel established to $targetHost:$targetPort (bound port $boundPort)")
    }

    fun connectProxyChain(
        socket: Socket,
        hop1Host: String,
        hop1Port: Int,
        hop1Type: String,
        hop2Host: String,
        hop2Port: Int,
        hop2Type: String,
        targetHost: String,
        targetPort: Int,
        timeoutMs: Int = 12000
    ) {
        AppLogger.i(TAG, "Initiating proxy chain: Hop1($hop1Host:$hop1Port $hop1Type) -> Hop2($hop2Host:$hop2Port $hop2Type) -> Target($targetHost:$targetPort)")

        // 1. Connect socket to Hop 1
        socket.connect(InetSocketAddress(hop1Host, hop1Port), timeoutMs)

        // 2. Tunnel from Hop 1 to Hop 2
        if (hop1Type.equals("HTTP", ignoreCase = true)) {
            connectHttpProxy(socket, hop1Host, hop1Port, hop2Host, hop2Port, timeoutMs = timeoutMs)
        } else {
            connectSocks5(socket, hop1Host, hop1Port, hop2Host, hop2Port, timeoutMs = timeoutMs)
        }

        // 3. Tunnel from Hop 2 to final target
        if (hop2Type.equals("HTTP", ignoreCase = true)) {
            connectHttpProxy(socket, hop2Host, hop2Port, targetHost, targetPort, timeoutMs = timeoutMs)
        } else {
            connectSocks5(socket, hop2Host, hop2Port, targetHost, targetPort, timeoutMs = timeoutMs)
        }

        AppLogger.i(TAG, "Proxy chain successfully established to $targetHost:$targetPort")
    }
}

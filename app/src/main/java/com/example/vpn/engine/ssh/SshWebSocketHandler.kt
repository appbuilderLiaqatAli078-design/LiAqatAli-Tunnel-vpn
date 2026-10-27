package com.example.vpn.engine.ssh

import android.util.Base64
import com.example.data.AppLogger
import com.example.vpn.engine.PayloadInjector
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.MessageDigest
import kotlin.random.Random

object SshWebSocketHandler {
    private const val TAG = "SshWebSocketHandler"
    private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    fun computeAcceptKey(secWebSocketKey: String): String {
        val sha1 = MessageDigest.getInstance("SHA-1")
        val digest = sha1.digest((secWebSocketKey.trim() + WS_GUID).toByteArray(Charsets.US_ASCII))
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    fun upgradeWebSocket(
        socket: Socket,
        wsPath: String,
        hostHeader: String,
        customHeaders: String = "",
        timeoutMs: Int = 20000
    ): Socket {
        val path = if (wsPath.startsWith("/")) wsPath else "/$wsPath"
        AppLogger.i(TAG, "Upgrading socket to WebSocket (path='$path', host='$hostHeader')")

        val randomBytes = ByteArray(16).apply { Random.nextBytes(this) }
        val secKey = Base64.encodeToString(randomBytes, Base64.NO_WRAP)
        val expectedAccept = computeAcceptKey(secKey)

        val headerBuilder = StringBuilder()
        headerBuilder.append("GET $path HTTP/1.1\r\n")
        headerBuilder.append("Host: $hostHeader\r\n")
        headerBuilder.append("Upgrade: websocket\r\n")
        headerBuilder.append("Connection: Upgrade\r\n")
        headerBuilder.append("Sec-WebSocket-Key: $secKey\r\n")
        headerBuilder.append("Sec-WebSocket-Version: 13\r\n")
        headerBuilder.append("User-Agent: Mozilla/5.0 (Android; Mobile; AegisTunnel)\r\n")

        if (customHeaders.isNotBlank()) {
            val lines = customHeaders.split("\n")
            for (line in lines) {
                val trimmed = line.trim()
                if (trimmed.isNotEmpty() && trimmed.contains(":")) {
                    headerBuilder.append("$trimmed\r\n")
                }
            }
        }
        headerBuilder.append("\r\n")

        socket.soTimeout = timeoutMs

        val output: OutputStream = socket.getOutputStream()
        output.write(headerBuilder.toString().toByteArray(Charsets.UTF_8))
        output.flush()

        val input: InputStream = socket.getInputStream()
        val statusLine = PayloadInjector.readLine(input)
        AppLogger.i(TAG, "WebSocket upgrade status line: $statusLine")

        if (statusLine == null || !statusLine.contains("101")) {
            throw IllegalStateException("WebSocket Upgrade failed: $statusLine")
        }

        // Consume remaining HTTP headers and validate RFC 6455 headers if present
        val responseHeaders = mutableMapOf<String, String>()
        while (true) {
            val line = PayloadInjector.readLine(input) ?: break
            if (line.isEmpty()) break
            val colonIdx = line.indexOf(':')
            if (colonIdx > 0) {
                val key = line.substring(0, colonIdx).trim().lowercase()
                val value = line.substring(colonIdx + 1).trim()
                responseHeaders[key] = value
            }
        }

        val serverAccept = responseHeaders["sec-websocket-accept"]
        if (serverAccept != null && serverAccept != expectedAccept) {
            throw IllegalStateException(
                "Invalid Sec-WebSocket-Accept header: expected '$expectedAccept', got '$serverAccept'"
            )
        }

        AppLogger.i(TAG, "WebSocket 101 handshake completed. Verifying SSH stream...")
        return PayloadInjector.verifyAndWrapUpgradedSocket(
            socket = socket,
            statusCode = 101,
            responseHeaders = responseHeaders,
            timeoutMs = timeoutMs
        )
    }
}

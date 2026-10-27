package com.example.vpn.engine.ssh

import android.util.Base64
import com.example.data.AppLogger
import com.example.vpn.engine.PayloadInjector
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import kotlin.random.Random

object SshWebSocketHandler {
    private const val TAG = "SshWebSocketHandler"

    fun upgradeWebSocket(
        socket: Socket,
        wsPath: String,
        hostHeader: String,
        customHeaders: String = "",
        timeoutMs: Int = 10000
    ) {
        val path = if (wsPath.startsWith("/")) wsPath else "/$wsPath"
        AppLogger.i(TAG, "Upgrading socket to WebSocket (path='$path', host='$hostHeader')")

        val randomBytes = ByteArray(16).apply { Random.nextBytes(this) }
        val secKey = Base64.encodeToString(randomBytes, Base64.NO_WRAP)

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

        val prevTimeout = socket.soTimeout
        socket.soTimeout = timeoutMs

        val output: OutputStream = socket.getOutputStream()
        output.write(headerBuilder.toString().toByteArray(Charsets.UTF_8))
        output.flush()

        val input: InputStream = socket.getInputStream()
        val statusLine = PayloadInjector.readLine(input)
        AppLogger.i(TAG, "WebSocket upgrade status line: $statusLine")

        if (!statusLine.contains("101")) {
            throw IllegalStateException("WebSocket Upgrade failed: $statusLine")
        }

        // Consume remaining HTTP headers
        var line = PayloadInjector.readLine(input)
        while (line.isNotEmpty()) {
            line = PayloadInjector.readLine(input)
        }

        socket.soTimeout = prevTimeout
        AppLogger.i(TAG, "WebSocket 101 handshake completed. Raw duplex channel open.")
    }
}

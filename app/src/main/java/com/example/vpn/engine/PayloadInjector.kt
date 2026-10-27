package com.example.vpn.engine

import android.util.Base64
import com.example.data.AppLogger
import com.example.vpn.engine.ssh.UpgradedSocket
import com.example.vpn.engine.ssh.WebSocketFramedSocket
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.random.Random

object PayloadInjector {
    private const val TAG = "PayloadInjector"

    fun formatPayload(
        rawTemplate: String,
        targetHost: String,
        targetPort: Int,
        proxyUser: String = "",
        proxyPass: String = "",
        method: String = "CONNECT"
    ): String {
        if (rawTemplate.isBlank()) {
            return ""
        }

        val authReplacement = if (proxyUser.isNotBlank()) {
            val creds = Base64.encodeToString("$proxyUser:$proxyPass".toByteArray(), Base64.NO_WRAP)
            "Proxy-Authorization: Basic $creds\r\n"
        } else ""

        var result = rawTemplate
            .replace("[crlf]", "\r\n", ignoreCase = true)
            .replace("[cr]", "\r", ignoreCase = true)
            .replace("[lf]", "\n", ignoreCase = true)
            .replace("[host_port]", "$targetHost:$targetPort", ignoreCase = true)
            .replace("[host]", targetHost, ignoreCase = true)
            .replace("[port]", targetPort.toString(), ignoreCase = true)
            .replace("[method]", method, ignoreCase = true)
            .replace("[protocol]", "HTTP/1.1", ignoreCase = true)
            .replace("[auth]", authReplacement, ignoreCase = true)
            .replace("[ua]", "Mozilla/5.0 (Android; Mobile; AegisTunnel)", ignoreCase = true)
            .replace("[reverse_proxy]", "X-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1", ignoreCase = true)
            .replace("[raw]", "", ignoreCase = true)

        if (!result.contains("[split]", ignoreCase = true) && !result.endsWith("\r\n\r\n")) {
            result += if (result.endsWith("\r\n")) "\r\n" else "\r\n\r\n"
        }
        return result
    }

    fun injectAndConnect(
        socket: Socket,
        targetHost: String,
        targetPort: Int,
        proxyHost: String,
        proxyPort: Int,
        payload: String,
        proxyUser: String = "",
        proxyPass: String = "",
        timeoutMs: Int = 12000
    ): Socket {
        val connectHost = if (proxyHost.isNotBlank() && proxyPort > 0) proxyHost else targetHost
        val connectPort = if (proxyHost.isNotBlank() && proxyPort > 0) proxyPort else targetPort

        if (!socket.isConnected) {
            AppLogger.i(TAG, "Connecting socket to $connectHost:$connectPort (timeout: ${timeoutMs}ms)")
            socket.connect(InetSocketAddress(connectHost, connectPort), timeoutMs)
        }
        socket.soTimeout = timeoutMs

        if (payload.isNotBlank()) {
            val formatted = formatPayload(payload, targetHost, targetPort, proxyUser, proxyPass)
            val output: OutputStream = socket.getOutputStream()

            if (formatted.contains("[split]", ignoreCase = true)) {
                val chunks = formatted.split(Regex("\\[split\\]", RegexOption.IGNORE_CASE))
                AppLogger.i(TAG, "Injecting split HTTP payload (${chunks.size} chunks)")
                for ((index, chunk) in chunks.withIndex()) {
                    output.write(chunk.toByteArray(Charsets.UTF_8))
                    output.flush()
                    if (index < chunks.size - 1) {
                        try { Thread.sleep(50) } catch (ignored: Exception) {}
                    }
                }
            } else {
                AppLogger.i(TAG, "Injecting HTTP payload into upstream stream (exact single transmission)")
                output.write(formatted.toByteArray(Charsets.UTF_8))
                output.flush()
            }

            // CRITICAL: Read and consume the HTTP response headers
            // so the socket stream is cleanly positioned for SSH handshake without desynchronization.
            AppLogger.i(TAG, "Awaiting HTTP transport response from $connectHost:$connectPort...")
            val input: InputStream = socket.getInputStream()
            var statusLine: String? = null
            for (i in 0..5) {
                val line = readLine(input) ?: throw IllegalStateException("Server closed connection without sending an HTTP status response")
                if (line.isNotBlank()) {
                    statusLine = line
                    break
                }
            }
            if (statusLine == null) {
                throw IllegalStateException("Server sent only empty lines without an HTTP status response")
            }
            AppLogger.i(TAG, "Transport response: $statusLine")

            val statusCode = extractStatusCode(statusLine)
            if (statusCode != 101 && statusCode != 200) {
                throw IllegalStateException("Server rejected HTTP tunnel (status $statusCode): $statusLine")
            }

            // Read remaining headers until blank line (\r\n\r\n)
            while (true) {
                val headerLine = readLine(input) ?: break
                if (headerLine.isEmpty()) break
            }
            AppLogger.i(TAG, "HTTP transport handshake verified ($statusLine). Consumed headers cleanly.")

            socket.soTimeout = 0
            return UpgradedSocket(socket, socket.getInputStream())
        }

        socket.soTimeout = 0
        return socket
    }

    private fun extractStatusCode(statusLine: String): Int {
        val parts = statusLine.trim().split(Regex("\\s+"))
        if (parts.size >= 2) {
            val code = parts[1].toIntOrNull()
            if (code != null) return code
        }
        return -1
    }

    fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        var b: Int
        var bytesRead = 0
        while (input.read().also { b = it } != -1) {
            bytesRead++
            val c = b.toChar()
            if (c == '\n') break
            if (c != '\r') sb.append(c)
        }
        if (bytesRead == 0 && b == -1) return null
        return sb.toString()
    }
}

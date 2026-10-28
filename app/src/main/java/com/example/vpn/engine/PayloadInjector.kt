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
            .replace("[ua]", "Mozilla/5.0 (Android; Mobile; CustomTunnelPro)", ignoreCase = true)
            .replace("[reverse_proxy]", "X-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1", ignoreCase = true)
            .replace("[raw]", "", ignoreCase = true)

        var cleaned = result.trimEnd(' ', '\t')
        if (!cleaned.contains("[split]", ignoreCase = true) && !cleaned.endsWith("\r\n\r\n")) {
            cleaned += if (cleaned.endsWith("\r\n")) "\r\n" else "\r\n\r\n"
        }
        return cleaned
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
        timeoutMs: Int = 30000,
        onConnected: ((Socket) -> Unit)? = null
    ): Socket {
        val connectHost = if (proxyHost.isNotBlank() && proxyPort > 0) proxyHost else targetHost
        val connectPort = if (proxyHost.isNotBlank() && proxyPort > 0) proxyPort else targetPort

        if (!socket.isConnected) {
            AppLogger.i(TAG, "Connecting socket to $connectHost:$connectPort (timeout: ${timeoutMs}ms)")
            socket.connect(InetSocketAddress(connectHost, connectPort), timeoutMs)
            onConnected?.invoke(socket)
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
                val printable = formatted.replace("\r", "\\r").replace("\n", "\\n")
                AppLogger.i(TAG, "Injecting HTTP payload into upstream stream ($printable)")
                output.write(formatted.toByteArray(Charsets.UTF_8))
                output.flush()
            }

            // CRITICAL: Read and consume the HTTP response headers byte-by-byte
            // so the socket stream is cleanly positioned at the exact end of "\r\n\r\n".
            AppLogger.i(TAG, "Awaiting HTTP transport response from $connectHost:$connectPort (read timeout: ${timeoutMs}ms)...")
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
                val hint = when (statusCode) {
                    400 -> " — HTTP 400 Bad Request: endpoint rejected the request syntax or Host header (if connecting through a CDN/Cloudflare host on port 80, use GET / with a valid Host header and Upgrade: websocket rather than raw CONNECT)"
                    403 -> " — HTTP 403 Forbidden: CDN or firewall blocked this Host/path"
                    407 -> " — HTTP 407 Proxy Authentication Required: check proxy username/password"
                    502, 503, 521, 522, 524 -> " — Upstream origin SSH/WebSocket backend is unreachable from CDN edge"
                    else -> ""
                }
                throw IllegalStateException("Server rejected HTTP tunnel (status $statusCode): $statusLine$hint")
            }

            // Read remaining headers until blank line (\r\n\r\n)
            val responseHeaders = mutableMapOf<String, String>()
            while (true) {
                val headerLine = readLine(input) ?: break
                if (headerLine.isEmpty()) break
                val colonIdx = headerLine.indexOf(':')
                if (colonIdx > 0) {
                    val key = headerLine.substring(0, colonIdx).trim().lowercase()
                    val value = headerLine.substring(colonIdx + 1).trim()
                    responseHeaders[key] = value
                }
            }
            AppLogger.i(TAG, "HTTP transport handshake headers consumed ($statusLine). Verifying SSH transport stream...")

            return verifyAndWrapUpgradedSocket(
                socket = socket,
                statusCode = statusCode,
                responseHeaders = responseHeaders,
                timeoutMs = timeoutMs
            )
        }

        socket.soTimeout = 0
        return socket
    }

    fun verifyAndWrapUpgradedSocket(
        socket: Socket,
        statusCode: Int,
        responseHeaders: Map<String, String>,
        timeoutMs: Int
    ): Socket {
        val pushback = PushbackInputStream(socket.getInputStream(), 8192)
        socket.soTimeout = minOf(timeoutMs, 15000)

        val b0 = try {
            pushback.read()
        } catch (e: java.net.SocketTimeoutException) {
            if (statusCode == 101 && responseHeaders.containsKey("sec-websocket-accept")) {
                AppLogger.i(TAG, "RFC 6455 WebSocket server awaiting client frame first; wrapping in WebSocketFramedSocket")
                socket.soTimeout = 0
                return WebSocketFramedSocket(socket, pushback)
            }
            throw IllegalStateException("Timed out waiting for SSH banner after HTTP $statusCode response", e)
        }

        if (b0 == -1) {
            throw IllegalStateException("Endpoint returned HTTP $statusCode but closed the connection before SSH handshake")
        }

        if (b0 == 0x88) {
            throw IllegalStateException("WebSocket endpoint rejected tunnel with Close frame (0x88) immediately after HTTP 101")
        }

        val isWebSocketFrameByte = b0 in listOf(0x81, 0x82, 0x89, 0x8A, 0x01, 0x02)
        if (isWebSocketFrameByte) {
            pushback.unread(b0)
            val wsSocket = WebSocketFramedSocket(socket, pushback)
            val wsPushback = wsSocket.pushbackInputStream
            val decodedBannerBytes = readBannerBytes(wsPushback)
            if (decodedBannerBytes.isEmpty()) {
                throw IllegalStateException("WebSocket endpoint closed stream without sending an SSH banner")
            }
            val decodedBanner = String(decodedBannerBytes, Charsets.UTF_8)
            wsPushback.unread(decodedBannerBytes)
            if (!decodedBanner.contains("SSH-")) {
                throw IllegalStateException(
                    "WebSocket endpoint does not support SSH-over-WebSocket (received: ${decodedBanner.take(80).trim()})"
                )
            }
            AppLogger.i(TAG, "Verified WebSocket-framed SSH server banner: ${decodedBanner.trim()}")
            socket.soTimeout = 0
            return wsSocket
        }

        // Raw stream after HTTP 101 / 200
        val baos = java.io.ByteArrayOutputStream()
        baos.write(b0)
        val restBytes = readBannerBytes(pushback)
        if (restBytes.isNotEmpty()) {
            baos.write(restBytes)
        }
        val allPeeked = baos.toByteArray()
        val bannerText = String(allPeeked, Charsets.UTF_8)
        pushback.unread(allPeeked)

        if (!bannerText.contains("SSH-")) {
            throw IllegalStateException(
                "Endpoint returned HTTP $statusCode but did not provide a valid SSH protocol banner (received: ${bannerText.take(80).trim()})"
            )
        }

        AppLogger.i(TAG, "Verified upstream SSH server banner: ${bannerText.trim()}")
        socket.soTimeout = 0
        return UpgradedSocket(socket, pushback, socket.getOutputStream())
    }

    private fun readBannerBytes(input: InputStream, maxBytes: Int = 256): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        while (baos.size() < maxBytes) {
            val b = input.read()
            if (b == -1) break
            baos.write(b)
            if (b == '\n'.code) break
        }
        return baos.toByteArray()
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

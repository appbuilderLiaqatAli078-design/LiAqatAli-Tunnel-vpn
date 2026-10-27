package com.example.vpn.engine

import android.util.Base64
import com.example.data.AppLogger
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

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
            val authHeader = if (proxyUser.isNotBlank()) {
                val creds = Base64.encodeToString("$proxyUser:$proxyPass".toByteArray(), Base64.NO_WRAP)
                "Proxy-Authorization: Basic $creds\r\n"
            } else ""
            return "CONNECT $targetHost:$targetPort HTTP/1.1\r\nHost: $targetHost\r\n${authHeader}Proxy-Connection: Keep-Alive\r\n\r\n"
        }

        val authReplacement = if (proxyUser.isNotBlank()) {
            val creds = Base64.encodeToString("$proxyUser:$proxyPass".toByteArray(), Base64.NO_WRAP)
            "Proxy-Authorization: Basic $creds\r\n"
        } else ""

        var result = rawTemplate
            .replace("[host_port]", "$targetHost:$targetPort", ignoreCase = true)
            .replace("[host]", targetHost, ignoreCase = true)
            .replace("[port]", targetPort.toString(), ignoreCase = true)
            .replace("[method]", method, ignoreCase = true)
            .replace("[protocol]", "HTTP/1.1", ignoreCase = true)
            .replace("[auth]", authReplacement, ignoreCase = true)
            .replace("[crlf]", "\r\n", ignoreCase = true)
            .replace("[cr]", "\r", ignoreCase = true)
            .replace("[lf]", "\n", ignoreCase = true)
            .replace("[ua]", "Mozilla/5.0 (Android; Mobile; AegisTunnel)", ignoreCase = true)
            .replace("[reverse_proxy]", "X-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1", ignoreCase = true)
            .replace("[raw]", "", ignoreCase = true)

        if (!result.contains("[split]") && !result.endsWith("\r\n\r\n")) {
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
        timeoutMs: Int = 10000
    ) {
        val connectHost = if (proxyHost.isNotBlank() && proxyPort > 0) proxyHost else targetHost
        val connectPort = if (proxyHost.isNotBlank() && proxyPort > 0) proxyPort else targetPort

        AppLogger.i(TAG, "Connecting socket to $connectHost:$connectPort (timeout: ${timeoutMs}ms)")
        socket.connect(InetSocketAddress(connectHost, connectPort), timeoutMs)
        socket.soTimeout = timeoutMs

        if (payload.isNotBlank() || (proxyHost.isNotBlank() && proxyPort > 0)) {
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
                AppLogger.i(TAG, "Injecting HTTP payload into upstream stream")
                output.write(formatted.toByteArray(Charsets.UTF_8))
                output.flush()
            }

            // If connecting via an HTTP proxy or CONNECT request, read the HTTP response status
            if (proxyHost.isNotBlank() && proxyPort > 0) {
                AppLogger.i(TAG, "Awaiting HTTP Proxy tunnel response...")
                val input: InputStream = socket.getInputStream()
                val line = readLine(input)
                AppLogger.i(TAG, "Proxy response: $line")
                if (!line.contains("200") && !line.contains("101")) {
                    throw IllegalStateException("Proxy tunnel returned non-200 status: $line")
                }
                // Read remaining headers until blank line
                var headerLine = readLine(input)
                while (headerLine.isNotEmpty()) {
                    headerLine = readLine(input)
                }
            }
        }
        socket.soTimeout = 0 // Reset to infinite for tunnel session
    }

    fun readLine(input: InputStream): String {
        val sb = StringBuilder()
        var b: Int
        while (input.read().also { b = it } != -1) {
            val c = b.toChar()
            if (c == '\n') break
            if (c != '\r') sb.append(c)
        }
        return sb.toString()
    }
}

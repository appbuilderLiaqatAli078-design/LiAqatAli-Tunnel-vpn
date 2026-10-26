package com.example.vpn.engine

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
        targetPort: Int
    ): String {
        if (rawTemplate.isBlank()) {
            return "CONNECT $targetHost:$targetPort HTTP/1.1\r\nHost: $targetHost\r\nProxy-Connection: Keep-Alive\r\n\r\n"
        }

        var result = rawTemplate
            .replace("[host_port]", "$targetHost:$targetPort", ignoreCase = true)
            .replace("[host]", targetHost, ignoreCase = true)
            .replace("[port]", targetPort.toString(), ignoreCase = true)
            .replace("[protocol]", "HTTP/1.1", ignoreCase = true)
            .replace("[crlf]", "\r\n", ignoreCase = true)
            .replace("[cr]", "\r", ignoreCase = true)
            .replace("[lf]", "\n", ignoreCase = true)
            .replace("[ua]", "Mozilla/5.0 (Android; Mobile; AegisTunnel)", ignoreCase = true)

        if (!result.endsWith("\r\n\r\n")) {
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
        timeoutMs: Int = 10000
    ) {
        val connectHost = if (proxyHost.isNotBlank() && proxyPort > 0) proxyHost else targetHost
        val connectPort = if (proxyHost.isNotBlank() && proxyPort > 0) proxyPort else targetPort

        AppLogger.i(TAG, "Connecting socket to $connectHost:$connectPort (timeout: ${timeoutMs}ms)")
        socket.connect(InetSocketAddress(connectHost, connectPort), timeoutMs)
        socket.soTimeout = timeoutMs

        if (payload.isNotBlank() || (proxyHost.isNotBlank() && proxyPort > 0)) {
            val formatted = formatPayload(payload, targetHost, targetPort)
            AppLogger.i(TAG, "Injecting HTTP payload into upstream stream")
            val output: OutputStream = socket.getOutputStream()
            output.write(formatted.toByteArray(Charsets.UTF_8))
            output.flush()

            // If connecting via an HTTP proxy or CONNECT request, read the HTTP response status
            if (proxyHost.isNotBlank() && proxyPort > 0) {
                AppLogger.i(TAG, "Awaiting HTTP Proxy tunnel response...")
                val input: InputStream = socket.getInputStream()
                val line = readLine(input)
                AppLogger.i(TAG, "Proxy response: $line")
                if (!line.contains("200")) {
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

    private fun readLine(input: InputStream): String {
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

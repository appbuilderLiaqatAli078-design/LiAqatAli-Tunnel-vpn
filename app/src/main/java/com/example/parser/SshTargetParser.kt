package com.example.parser

import java.net.URLDecoder

data class SshTargetInfo(
    val host: String,
    val port: Int,
    val username: String,
    val password: String,
    val name: String? = null
)

object SshTargetParser {

    /**
     * Parses target strings such as:
     * - www.openx.com:80@Test:Test1
     * - Test:Test1@www.openx.com:80
     * - user:12345@host.com:22 (numeric password must NOT be mistaken for host:port)
     * - ssh://www.openx.com:80@Test:Test1
     * - ssh://Test:Test1@www.openx.com:80#MyNode
     */
    fun parse(rawInput: String, defaultPort: Int = 22): SshTargetInfo? {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) return null

        val isSshScheme = trimmed.startsWith("ssh://", ignoreCase = true)
        val withoutScheme = if (isSshScheme) {
            trimmed.substring(6)
        } else {
            trimmed
        }

        val name = if (withoutScheme.contains("#")) {
            decodeIfUrlEncoded(withoutScheme.substringAfter("#").trim(), isSshScheme).ifEmpty { null }
        } else null

        val withoutFragment = withoutScheme.substringBefore("#")
        val withoutQuery = withoutFragment.substringBefore("?")
        val target = withoutQuery.trim()

        if (!target.contains("@")) {
            // Just host or host:port
            if (target.contains(":")) {
                val lastColon = target.lastIndexOf(":")
                val possiblePort = target.substring(lastColon + 1).toIntOrNull()
                if (possiblePort != null && possiblePort in 1..65535) {
                    val host = target.substring(0, lastColon).trim()
                    return SshTargetInfo(host = host, port = possiblePort, username = "", password = "", name = name)
                }
            }
            return SshTargetInfo(host = target, port = defaultPort, username = "", password = "", name = name)
        }

        // Split on the LAST '@' if right side looks like a host, or FIRST '@' if left side looks like a host
        val firstAt = target.indexOf('@')
        val lastAt = target.lastIndexOf('@')
        val part0 = target.substring(0, firstAt).trim()
        val part1 = target.substring(firstAt + 1).trim()

        val part0HostCandidate = extractHostPart(part0)
        val part1HostCandidate = extractHostPart(target.substring(lastAt + 1).trim())

        val part0LooksLikeHost = looksLikeHost(part0HostCandidate)
        val part1LooksLikeHost = looksLikeHost(part1HostCandidate)

        val part0Port = extractPortOrNull(part0)
        val part1Port = extractPortOrNull(target.substring(lastAt + 1).trim())

        // Determine whether format is host[:port]@user[:pass] (Case 1) or user[:pass]@host[:port] (Case 2)
        val isHostFirst = when {
            part0LooksLikeHost && !part1LooksLikeHost -> true
            !part0LooksLikeHost && part1LooksLikeHost -> false
            part0LooksLikeHost && part1LooksLikeHost -> {
                // Both sides contain dots; if ssh:// scheme is used, standard URI is user:pass@host:port unless part0 has a valid port and part1 does not
                if (isSshScheme && part1Port != null) false
                else part0Port != null && part1Port == null
            }
            else -> {
                // Neither side has a dot (e.g. localhost or single-label hostname)
                if (part1Port != null && part0Port == null) false
                else if (part0Port != null && part1Port == null) true
                else false
            }
        }

        return if (isHostFirst) {
            val host = part0HostCandidate
            val port = part0Port ?: defaultPort
            val userRaw = part1.substringBefore(":").trim()
            val passRaw = if (part1.contains(":")) part1.substringAfter(":") else ""
            val user = decodeIfUrlEncoded(userRaw, isSshScheme)
            val pass = decodeIfUrlEncoded(passRaw, isSshScheme)
            SshTargetInfo(
                host = host,
                port = port,
                username = user,
                password = pass,
                name = name ?: "SSH-$host:$port"
            )
        } else {
            val credsPart = target.substring(0, lastAt).trim()
            val hostPortPart = target.substring(lastAt + 1).trim()
            val host = extractHostPart(hostPortPart)
            val port = extractPortOrNull(hostPortPart) ?: defaultPort
            val userRaw = credsPart.substringBefore(":").trim()
            val passRaw = if (credsPart.contains(":")) credsPart.substringAfter(":") else ""
            val user = decodeIfUrlEncoded(userRaw, isSshScheme)
            val pass = decodeIfUrlEncoded(passRaw, isSshScheme)
            SshTargetInfo(
                host = host,
                port = port,
                username = user,
                password = pass,
                name = name ?: "SSH-$host:$port"
            )
        }
    }

    private fun extractHostPart(input: String): String {
        val trimmed = input.trim()
        if (trimmed.startsWith("[") && trimmed.contains("]")) {
            return trimmed.substring(1, trimmed.indexOf(']'))
        }
        val port = extractPortOrNull(trimmed)
        return if (port != null && trimmed.contains(":")) {
            trimmed.substringBeforeLast(":").trim()
        } else {
            trimmed
        }
    }

    private fun extractPortOrNull(input: String): Int? {
        val trimmed = input.trim()
        if (!trimmed.contains(":")) return null
        val afterColon = trimmed.substringAfterLast(":").trim()
        val p = afterColon.toIntOrNull() ?: return null
        return if (p in 1..65535) p else null
    }

    private fun looksLikeHost(candidate: String): Boolean {
        val c = candidate.trim()
        if (c.isEmpty()) return false
        if (c.equals("localhost", ignoreCase = true)) return true
        // IPv4 or domain name with at least one dot and valid hostname characters
        if (c.contains(".") && c.all { it.isLetterOrDigit() || it == '.' || it == '-' }) {
            return true
        }
        // Bracketed IPv6
        if (c.contains(":")) return true
        return false
    }

    private fun decodeIfUrlEncoded(value: String, enabled: Boolean): String {
        if (!enabled || !value.contains("%")) return value
        return try {
            URLDecoder.decode(value, "UTF-8")
        } catch (_: Exception) {
            value
        }
    }
}

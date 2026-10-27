package com.example.parser

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
     * - ssh://www.openx.com:80@Test:Test1
     * - ssh://Test:Test1@www.openx.com:80#MyNode
     */
    fun parse(rawInput: String, defaultPort: Int = 22): SshTargetInfo? {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) return null

        val withoutScheme = if (trimmed.startsWith("ssh://", ignoreCase = true)) {
            trimmed.substring(6)
        } else {
            trimmed
        }

        val name = if (withoutScheme.contains("#")) {
            withoutScheme.substringAfter("#").trim().ifEmpty { null }
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

        val atParts = target.split("@", limit = 2)
        val part0 = atParts[0].trim()
        val part1 = atParts[1].trim()

        // Check Case 1: host:port@user:pass (e.g. www.openx.com:80@Test:Test1)
        val part0Port = if (part0.contains(":")) part0.substringAfterLast(":").toIntOrNull() else null
        if (part0Port != null && part0Port in 1..65535) {
            val host = part0.substringBeforeLast(":").trim()
            val user = part1.substringBefore(":").trim()
            val pass = if (part1.contains(":")) part1.substringAfter(":").trim() else ""
            return SshTargetInfo(
                host = host,
                port = part0Port,
                username = user,
                password = pass,
                name = name ?: "SSH-$host:$part0Port"
            )
        }

        // Check Case 2: user:pass@host:port (e.g. Test:Test1@www.openx.com:80)
        val part1Port = if (part1.contains(":")) part1.substringAfterLast(":").toIntOrNull() else null
        if (part1Port != null && part1Port in 1..65535) {
            val host = part1.substringBeforeLast(":").trim()
            val user = part0.substringBefore(":").trim()
            val pass = if (part0.contains(":")) part0.substringAfter(":").trim() else ""
            return SshTargetInfo(
                host = host,
                port = part1Port,
                username = user,
                password = pass,
                name = name ?: "SSH-$host:$part1Port"
            )
        }

        // Case 3: host@user:pass or user:pass@host (no numeric port, use defaultPort)
        if (part0.contains(".") && !part1.contains(".")) {
            val host = part0
            val user = part1.substringBefore(":").trim()
            val pass = if (part1.contains(":")) part1.substringAfter(":").trim() else ""
            return SshTargetInfo(host = host, port = defaultPort, username = user, password = pass, name = name ?: "SSH-$host:$defaultPort")
        } else {
            val host = part1
            val user = part0.substringBefore(":").trim()
            val pass = if (part0.contains(":")) part0.substringAfter(":").trim() else ""
            return SshTargetInfo(host = host, port = defaultPort, username = user, password = pass, name = name ?: "SSH-$host:$defaultPort")
        }
    }
}

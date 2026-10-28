package com.example.parser

import android.content.Context
import android.net.Uri
import android.util.Base64
import com.example.model.ProtocolType
import com.example.model.SshTunnelMode
import com.example.model.VpnProfile
import com.example.security.CtpConfigCrypto
import com.example.security.CtpDecryptResult
import com.example.security.CtpExportOptions
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.UUID

sealed class ParseResult {
    data class Success(val profile: VpnProfile) : ParseResult()
    data class Failure(
        val reason: String,
        val details: String? = null,
        val requiresPassword: Boolean = false
    ) : ParseResult()
}

object ConfigParser {

    fun parse(
        rawInput: String,
        unlockPassword: String = "",
        context: Context? = null
    ): ParseResult {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            return ParseResult.Failure("Empty configuration string")
        }

        return try {
            when {
                CtpConfigCrypto.isCtpContent(trimmed) -> parseCtp(trimmed, unlockPassword, context)
                trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmess(trimmed)
                trimmed.startsWith("vless://", ignoreCase = true) -> parseVless(trimmed)
                trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojan(trimmed)
                trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(trimmed)
                trimmed.startsWith("ssh://", ignoreCase = true) -> parseSshUri(trimmed)
                trimmed.startsWith("{") -> parseJson(trimmed)
                trimmed.contains("@") && !trimmed.contains("://") -> parseSshUri(trimmed)
                else -> ParseResult.Failure("Unsupported format. Expected .ctp file, vmess://, vless://, trojan://, ss://, ssh://, or Xray JSON.")
            }
        } catch (e: Exception) {
            ParseResult.Failure("Failed to parse configuration: ${e.message}", e.stackTraceToString())
        }
    }

    private fun parseCtp(
        rawCtp: String,
        unlockPassword: String,
        context: Context?
    ): ParseResult {
        return when (val decrypted = CtpConfigCrypto.decryptCtpToProfileJson(rawCtp, unlockPassword, context)) {
            is CtpDecryptResult.Success -> {
                val parsed = parseJson(decrypted.profileJson)
                if (parsed is ParseResult.Success) {
                    // Always assign a fresh local ID on import if needed or keep profile fields
                    ParseResult.Success(parsed.profile)
                } else {
                    parsed
                }
            }
            is CtpDecryptResult.PasswordRequired -> {
                ParseResult.Failure(
                    reason = decrypted.hint,
                    requiresPassword = true
                )
            }
            is CtpDecryptResult.Failure -> {
                ParseResult.Failure(reason = decrypted.reason)
            }
        }
    }

    private fun parseVmess(uriStr: String): ParseResult {
        val base64Data = uriStr.substring(8).trim()
        val decoded = try {
            String(Base64.decode(base64Data, Base64.DEFAULT or Base64.URL_SAFE), StandardCharsets.UTF_8)
        } catch (e: Exception) {
            return ParseResult.Failure("Invalid VMess Base64 payload", e.message)
        }

        val json = JSONObject(decoded)
        val server = json.optString("add").trim()
        val port = json.optInt("port", 0)
        val id = json.optString("id").trim()

        if (server.isEmpty()) return ParseResult.Failure("VMess config is missing server address ('add')")
        if (port !in 1..65535) return ParseResult.Failure("VMess invalid port: $port")
        if (id.isEmpty()) return ParseResult.Failure("VMess config is missing UUID ('id')")

        val name = json.optString("ps", "VMess-$server")
        val network = json.optString("net", "tcp").lowercase()
        val security = json.optString("tls", "none")
        val wsHost = json.optString("host", "")
        val sni = json.optString("sni", "").ifBlank { wsHost }
        val path = json.optString("path", "")
        val alpn = json.optString("alpn", "")
        val fp = json.optString("fp", "chrome").ifBlank { "chrome" }
        val headerType = json.optString("type", "none").ifBlank { "none" }

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name.ifEmpty { "VMess-$server:$port" },
            protocol = ProtocolType.VMESS,
            server = server,
            port = port,
            password = id,
            security = if (security.equals("tls", true)) "tls" else "none",
            network = network,
            path = path,
            sni = sni,
            wsHost = wsHost,
            headerType = headerType,
            fingerprint = fp,
            alpn = alpn
        )
        return ParseResult.Success(profile)
    }

    private val SUPPORTED_VLESS_NETWORKS = setOf(
        "tcp", "ws", "websocket", "grpc", "gun", "httpupgrade", "xhttp", "splithttp", "h2", "http", "kcp"
    )
    private val SUPPORTED_VLESS_SECURITIES = setOf("none", "tls", "reality", "")

    private fun parseVless(uriStr: String): ParseResult {
        val uri = Uri.parse(uriStr)
        val rawUserInfo = uri.encodedUserInfo?.let { decodeUrlComponent(it) } ?: uri.userInfo
        val uuid = rawUserInfo?.trim() ?: ""
        if (uuid.isEmpty()) {
            return ParseResult.Failure("VLESS missing UUID in user info")
        }

        val rawHost = uri.host?.trim()?.removePrefix("[")?.removeSuffix("]") ?: ""
        if (rawHost.isEmpty()) {
            return ParseResult.Failure("VLESS missing server hostname")
        }

        val port = uri.port
        if (port !in 1..65535) {
            return ParseResult.Failure("VLESS invalid port: $port")
        }

        val rawQuery = uriStr.substringAfter("?", "").substringBefore("#")
        val queryParams = parseQueryParams(rawQuery.ifEmpty { uri. encodedQuery })
        val rawFragment = if (uriStr.contains("#")) uriStr.substringAfter("#") else null
        val name = rawFragment?.let { decodeUrlComponent(it) }?.ifBlank { null } ?: "VLESS-$rawHost:$port"

        val encryption = (queryParams["encryption"] ?: "none").trim().ifEmpty { "none" }
        if (!encryption.equals("none", ignoreCase = true)) {
            return ParseResult.Failure("Unsupported VLESS encryption '$encryption' (VLESS standard requires encryption=none)")
        }

        val rawSecurity = (queryParams["security"] ?: "none").trim().lowercase().ifEmpty { "none" }
        if (rawSecurity !in SUPPORTED_VLESS_SECURITIES) {
            return ParseResult.Failure("Unsupported VLESS security mode: '$rawSecurity'")
        }
        val security = if (rawSecurity.isEmpty()) "none" else rawSecurity

        val rawNetwork = (queryParams["type"] ?: queryParams["network"] ?: "tcp").trim().lowercase().ifEmpty { "tcp" }
        if (rawNetwork !in SUPPORTED_VLESS_NETWORKS) {
            return ParseResult.Failure("Unsupported VLESS transport type: '$rawNetwork'")
        }
        val network = when (rawNetwork) {
            "websocket" -> "ws"
            "gun" -> "grpc"
            "splithttp" -> "xhttp"
            else -> rawNetwork
        }

        val wsHost = (queryParams["host"] ?: "").trim()
        val sni = (queryParams["sni"] ?: queryParams["peer"] ?: "").trim().ifEmpty { wsHost }
        val headerType = (queryParams["headerType"] ?: "none").trim().ifEmpty { "none" }
        val grpcMode = (queryParams["mode"] ?: "gun").trim().ifEmpty { "gun" }
        val grpcAuthority = (queryParams["authority"] ?: "").trim()

        val path = when (network) {
            "grpc" -> (queryParams["serviceName"] ?: queryParams["path"] ?: "").trim()
            else -> (queryParams["path"] ?: queryParams["serviceName"] ?: "").trim()
        }

        val pbk = (queryParams["pbk"] ?: "").trim()
        val sid = (queryParams["sid"] ?: "").trim()
        val spx = (queryParams["spx"] ?: "").trim()
        val fp = (queryParams["fp"] ?: "chrome").trim().ifEmpty { "chrome" }
        val alpn = (queryParams["alpn"] ?: "").trim()
        val flow = (queryParams["flow"] ?: "").trim()

        if (security == "reality" && pbk.isEmpty()) {
            return ParseResult.Failure("VLESS REALITY configuration is missing required public key ('pbk')")
        }

        val allowInsecure = listOf("allowInsecure", "insecure", "allow_insecure").any { key ->
            val v = queryParams[key]?.trim()
            v == "1" || v.equals("true", ignoreCase = true)
        }

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.VLESS,
            server = rawHost,
            port = port,
            password = uuid,
            security = security,
            network = network,
            path = path,
            sni = sni,
            wsHost = wsHost,
            headerType = headerType,
            grpcMode = grpcMode,
            grpcAuthority = grpcAuthority,
            publicKey = pbk,
            shortId = sid,
            spiderX = spx,
            fingerprint = fp,
            alpn = alpn,
            flow = flow,
            encryption = "none",
            allowInsecureSsl = allowInsecure
        )
        return ParseResult.Success(profile)
    }

    private fun parseTrojan(uriStr: String): ParseResult {
        val uri = Uri.parse(uriStr)
        val password = uri.encodedUserInfo?.let { decodeUrlComponent(it) } ?: uri.userInfo
            ?: return ParseResult.Failure("Trojan missing password")
        val host = uri.host?.trim()?.removePrefix("[")?.removeSuffix("]")
            ?: return ParseResult.Failure("Trojan missing host")
        val port = uri.port
        if (port !in 1..65535) return ParseResult.Failure("Trojan invalid port: $port")

        val rawQuery = uriStr.substringAfter("?", "").substringBefore("#")
        val queryParams = parseQueryParams(rawQuery.ifEmpty { uri.encodedQuery })
        val name = uri.fragment?.let { decodeUrlComponent(it) } ?: "Trojan-$host:$port"
        val wsHost = (queryParams["host"] ?: "").trim()
        val sni = (queryParams["sni"] ?: queryParams["peer"] ?: "").trim().ifEmpty { wsHost.ifEmpty { host } }
        val network = (queryParams["type"] ?: "tcp").trim().lowercase().ifEmpty { "tcp" }
        val path = (queryParams["path"] ?: queryParams["serviceName"] ?: "").trim()
        val security = (queryParams["security"] ?: "tls").trim().lowercase().ifEmpty { "tls" }
        val alpn = (queryParams["alpn"] ?: "").trim()
        val fp = (queryParams["fp"] ?: "chrome").trim().ifEmpty { "chrome" }
        val allowInsecure = listOf("allowInsecure", "insecure", "allow_insecure").any { key ->
            val v = queryParams[key]?.trim()
            v == "1" || v.equals("true", ignoreCase = true)
        }

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.TROJAN,
            server = host,
            port = port,
            password = password,
            security = security,
            network = network,
            path = path,
            sni = sni,
            wsHost = wsHost,
            fingerprint = fp,
            alpn = alpn,
            allowInsecureSsl = allowInsecure
        )
        return ParseResult.Success(profile)
    }

    private fun parseShadowsocks(uriStr: String): ParseResult {
        // ss://BASE64(method:password)@host:port#name or ss://BASE64(method:password@host:port)#name
        val withoutScheme = uriStr.substring(5)
        val parts = withoutScheme.split("#", limit = 2)
        val mainPart = parts[0]
        val name = if (parts.size > 1) decodeUrlComponent(parts[1]) else "Shadowsocks"

        if (mainPart.contains("@")) {
            val atSplit = mainPart.split("@", limit = 2)
            val userInfoDecoded = try {
                String(Base64.decode(atSplit[0], Base64.DEFAULT or Base64.URL_SAFE), StandardCharsets.UTF_8)
            } catch (e: Exception) {
                atSplit[0]
            }
            val hostPort = atSplit[1].split(":")
            val host = hostPort[0]
            val port = hostPort.getOrNull(1)?.toIntOrNull() ?: 8388
            return ParseResult.Success(
                VpnProfile(
                    id = UUID.randomUUID().toString(),
                    name = name,
                    protocol = ProtocolType.SHADOWSOCKS,
                    server = host,
                    port = port,
                    password = userInfoDecoded
                )
            )
        } else {
            val decoded = try {
                String(Base64.decode(mainPart, Base64.DEFAULT or Base64.URL_SAFE), StandardCharsets.UTF_8)
            } catch (e: Exception) {
                return ParseResult.Failure("Invalid Shadowsocks Base64 string", e.message)
            }
            // decoded is method:password@host:port
            val atSplit = decoded.split("@", limit = 2)
            if (atSplit.size < 2) return ParseResult.Failure("Malformed Shadowsocks URI: missing @")
            val hostPort = atSplit[1].split(":")
            val host = hostPort[0]
            val port = hostPort.getOrNull(1)?.toIntOrNull() ?: 8388
            return ParseResult.Success(
                VpnProfile(
                    id = UUID.randomUUID().toString(),
                    name = name,
                    protocol = ProtocolType.SHADOWSOCKS,
                    server = host,
                    port = port,
                    password = atSplit[0]
                )
            )
        }
    }

    private fun parseSshUri(uriStr: String): ParseResult {
        val targetInfo = SshTargetParser.parse(uriStr)
        val host = targetInfo?.host ?: ""
        if (host.isEmpty()) return ParseResult.Failure("SSH configuration missing host")
        val port = targetInfo?.port ?: 22
        val username = targetInfo?.username?.ifBlank { "root" } ?: "root"
        val password = targetInfo?.password ?: ""

        val queryParams = if (uriStr.contains("?")) {
            val queryStr = uriStr.substringAfter("?").substringBefore("#")
            parseQueryParams(queryStr)
        } else emptyMap()

        val name = targetInfo?.name ?: (if (uriStr.contains("#")) {
            decodeUrlComponent(uriStr.substringAfter("#"))
        } else "SSH-$host:$port")
        val payload = queryParams["payload"] ?: ""
        val proxyHost = queryParams["proxy_host"] ?: ""
        val proxyPort = queryParams["proxy_port"]?.toIntOrNull() ?: 0
        val modeStr = queryParams["mode"] ?: "DIRECT"
        val sshMode = try {
            SshTunnelMode.valueOf(modeStr.uppercase())
        } catch (e: Exception) {
            SshTunnelMode.DIRECT
        }
        val sni = queryParams["sni"] ?: ""
        val wsPath = queryParams["ws_path"] ?: "/ssh"
        val proxyUser = queryParams["proxy_user"] ?: ""
        val proxyPass = queryParams["proxy_pass"] ?: ""
        val chainHost = queryParams["chain_host"] ?: ""
        val chainPort = queryParams["chain_port"]?.toIntOrNull() ?: 0
        val chainType = queryParams["chain_type"] ?: "SOCKS5"
        val localFwdPort = queryParams["local_fwd_port"]?.toIntOrNull() ?: 10880
        val remoteFwdHost = queryParams["remote_fwd_host"] ?: "127.0.0.1"
        val remoteFwdPort = queryParams["remote_fwd_port"]?.toIntOrNull() ?: 80
        val remoteListenPort = queryParams["remote_listen_port"]?.toIntOrNull() ?: 8080

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.SSH,
            server = host,
            port = port,
            sshUsername = username,
            password = password,
            sshPayload = payload,
            proxyHost = proxyHost,
            proxyPort = proxyPort,
            sshMode = sshMode,
            sshSni = sni,
            sshWsPath = wsPath,
            sshProxyUser = proxyUser,
            sshProxyPass = proxyPass,
            sshChainProxyHost = chainHost,
            sshChainProxyPort = chainPort,
            sshChainProxyType = chainType,
            sshLocalForwardPort = localFwdPort,
            sshRemoteForwardHost = remoteFwdHost,
            sshRemoteForwardPort = remoteFwdPort,
            sshRemoteListenPort = remoteListenPort
        )
        return ParseResult.Success(profile)
    }

    private fun parseJson(jsonStr: String): ParseResult {
        val root = JSONObject(jsonStr)
        // Check if custom Aegis profile export
        if (root.has("protocol") && root.has("server")) {
            val proto = try {
                ProtocolType.valueOf(root.getString("protocol"))
            } catch (e: Exception) {
                ProtocolType.VLESS
            }
            return ParseResult.Success(
                VpnProfile(
                    id = root.optString("id", UUID.randomUUID().toString()),
                    name = root.optString("name", "Imported Profile"),
                    protocol = proto,
                    server = root.getString("server"),
                    port = root.getInt("port"),
                    password = root.optString("password", ""),
                    security = root.optString("security", "none"),
                    network = root.optString("network", "tcp"),
                    path = root.optString("path", ""),
                    sni = root.optString("sni", ""),
                    wsHost = root.optString("wsHost", ""),
                    headerType = root.optString("headerType", "none"),
                    grpcMode = root.optString("grpcMode", "gun"),
                    grpcAuthority = root.optString("grpcAuthority", ""),
                    publicKey = root.optString("publicKey", ""),
                    shortId = root.optString("shortId", ""),
                    spiderX = root.optString("spiderX", ""),
                    fingerprint = root.optString("fingerprint", "chrome"),
                    alpn = root.optString("alpn", ""),
                    flow = root.optString("flow", ""),
                    encryption = root.optString("encryption", "none"),
                    sshUsername = root.optString("sshUsername", ""),
                    sshPayload = root.optString("sshPayload", ""),
                    proxyHost = root.optString("proxyHost", ""),
                    proxyPort = root.optInt("proxyPort", 0),
                    sshMode = try {
                        SshTunnelMode.valueOf(root.optString("sshMode", SshTunnelMode.DIRECT.name))
                    } catch (e: Exception) {
                        SshTunnelMode.DIRECT
                    },
                    sshPrivateKey = root.optString("sshPrivateKey", ""),
                    sshPassphrase = root.optString("sshPassphrase", ""),
                    sshProxyUser = root.optString("sshProxyUser", ""),
                    sshProxyPass = root.optString("sshProxyPass", ""),
                    sshSni = root.optString("sshSni", ""),
                    sshWsPath = root.optString("sshWsPath", "/ssh"),
                    sshCustomHeaders = root.optString("sshCustomHeaders", ""),
                    sshChainProxyHost = root.optString("sshChainProxyHost", ""),
                    sshChainProxyPort = root.optInt("sshChainProxyPort", 0),
                    sshChainProxyType = root.optString("sshChainProxyType", "SOCKS5"),
                    sshLocalForwardPort = root.optInt("sshLocalForwardPort", 10880),
                    sshRemoteForwardHost = root.optString("sshRemoteForwardHost", "127.0.0.1"),
                    sshRemoteForwardPort = root.optInt("sshRemoteForwardPort", 80),
                    sshRemoteListenPort = root.optInt("sshRemoteListenPort", 8080),
                    allowInsecureSsl = root.optBoolean("allowInsecureSsl", false),
                    dnsPrimary = root.optString("dnsPrimary", "1.1.1.1"),
                    dnsSecondary = root.optString("dnsSecondary", "8.8.8.8"),
                    blockIpv6 = root.optBoolean("blockIpv6", true),
                    isLocked = root.optBoolean("isLocked", false),
                    lockPasswordHash = root.optString("lockPasswordHash", ""),
                    expiresAtMillis = root.optLong("expiresAtMillis", 0L),
                    lockedHwid = root.optString("lockedHwid", ""),
                    blockRoot = root.optBoolean("blockRoot", false),
                    creatorMessage = root.optString("creatorMessage", "")
                )
            )
        }

        // Standard Xray/V2Ray inbound/outbound JSON
        val outbounds = root.optJSONArray("outbounds")
        if (outbounds != null && outbounds.length() > 0) {
            val firstOutbound = outbounds.getJSONObject(0)
            val protocolStr = firstOutbound.optString("protocol", "vless").uppercase()
            val proto = when (protocolStr) {
                "VMESS" -> ProtocolType.VMESS
                "VLESS" -> ProtocolType.VLESS
                "TROJAN" -> ProtocolType.TROJAN
                "SHADOWSOCKS" -> ProtocolType.SHADOWSOCKS
                "SOCKS" -> ProtocolType.SOCKS5
                else -> ProtocolType.VLESS
            }
            val settings = firstOutbound.optJSONObject("settings")
            var server = ""
            var port = 443
            var id = ""
            var flow = ""
            var encryption = "none"
            if (settings != null) {
                val vnext = settings.optJSONArray("vnext")
                if (vnext != null && vnext.length() > 0) {
                    val target = vnext.getJSONObject(0)
                    server = target.optString("address", "")
                    port = target.optInt("port", 443)
                    val users = target.optJSONArray("users")
                    if (users != null && users.length() > 0) {
                        val user = users.getJSONObject(0)
                        id = user.optString("id", "")
                        flow = user.optString("flow", "")
                        encryption = user.optString("encryption", "none")
                    }
                } else if (settings.has("address")) {
                    // Xray v26 flat VLESS outbound settings
                    server = settings.optString("address", "")
                    port = settings.optInt("port", 443)
                    id = settings.optString("id", "")
                    flow = settings.optString("flow", "")
                    encryption = settings.optString("encryption", "none")
                }
            }
            if (server.isEmpty()) return ParseResult.Failure("Cannot parse outbound server address from Xray JSON")

            val streamSettings = firstOutbound.optJSONObject("streamSettings")
            val network = streamSettings?.optString("network", "tcp")?.lowercase() ?: "tcp"
            val security = streamSettings?.optString("security", "none")?.lowercase() ?: "none"

            var sni = ""
            var fingerprint = "chrome"
            var alpn = ""
            var allowInsecure = false
            var publicKey = ""
            var shortId = ""
            var spiderX = ""
            var path = ""
            var wsHost = ""
            var grpcMode = "gun"
            var grpcAuthority = ""

            if (security == "tls") {
                val tls = streamSettings?.optJSONObject("tlsSettings")
                if (tls != null) {
                    sni = tls.optString("serverName", "")
                    fingerprint = tls.optString("fingerprint", "chrome").ifBlank { "chrome" }
                    allowInsecure = tls.optBoolean("allowInsecure", false)
                    val alpnArr = tls.optJSONArray("alpn")
                    if (alpnArr != null && alpnArr.length() > 0) {
                        val list = mutableListOf<String>()
                        for (i in 0 until alpnArr.length()) {
                            list.add(alpnArr.getString(i))
                        }
                        alpn = list.joinToString(",")
                    }
                }
            } else if (security == "reality") {
                val reality = streamSettings?.optJSONObject("realitySettings")
                if (reality != null) {
                    sni = reality.optString("serverName", "")
                    fingerprint = reality.optString("fingerprint", "chrome").ifBlank { "chrome" }
                    publicKey = reality.optString("publicKey", "")
                    shortId = reality.optString("shortId", "")
                    spiderX = reality.optString("spiderX", "")
                }
            }

            if (network == "ws") {
                val ws = streamSettings?.optJSONObject("wsSettings")
                if (ws != null) {
                    path = ws.optString("path", "")
                    wsHost = ws.optString("host", "").ifBlank {
                        ws.optJSONObject("headers")?.optString("Host", "") ?: ""
                    }
                }
            } else if (network == "grpc") {
                val grpc = streamSettings?.optJSONObject("grpcSettings")
                if (grpc != null) {
                    path = grpc.optString("serviceName", "")
                    grpcMode = if (grpc.optBoolean("multiMode", false)) "multi" else "gun"
                    grpcAuthority = grpc.optString("authority", "")
                }
            }

            return ParseResult.Success(
                VpnProfile(
                    id = UUID.randomUUID().toString(),
                    name = root.optString("remarks", "Xray-$server:$port"),
                    protocol = proto,
                    server = server,
                    port = port,
                    password = id,
                    security = security,
                    network = network,
                    path = path,
                    sni = sni.ifBlank { wsHost },
                    wsHost = wsHost,
                    grpcMode = grpcMode,
                    grpcAuthority = grpcAuthority,
                    publicKey = publicKey,
                    shortId = shortId,
                    spiderX = spiderX,
                    fingerprint = fingerprint,
                    alpn = alpn,
                    flow = flow,
                    encryption = encryption,
                    allowInsecureSsl = allowInsecure
                )
            )
        }

        return ParseResult.Failure("JSON does not contain recognized Xray outbounds or Aegis profile schema")
    }

    private fun decodeUrlComponent(encoded: String): String {
        return try {
            // Preserve '+' as literal plus in query/fragment values unless %2B
            URLDecoder.decode(encoded.replace("+", "%2B"), "UTF-8")
        } catch (e: Exception) {
            encoded
        }
    }

    private fun parseQueryParams(query: String?): Map<String, String> {
        if (query.isNullOrEmpty()) return emptyMap()
        val map = mutableMapOf<String, String>()
        val pairs = query.split("&")
        for (pair in pairs) {
            val idx = pair.indexOf("=")
            if (idx > 0) {
                val key = decodeUrlComponent(pair.substring(0, idx)).trim()
                val value = decodeUrlComponent(pair.substring(idx + 1))
                map[key] = value
            }
        }
        return map
    }

    fun exportProfileToUri(profile: VpnProfile): String {
        return when (profile.protocol) {
            ProtocolType.VLESS -> {
                val params = mutableListOf<String>()
                params.add("encryption=${Uri.encode(profile.encryption.ifBlank { "none" })}")
                params.add("security=${Uri.encode(profile.security.ifBlank { "none" })}")
                params.add("type=${Uri.encode(profile.network.ifBlank { "tcp" })}")
                if (profile.sni.isNotBlank()) params.add("sni=${Uri.encode(profile.sni)}")
                if (profile.wsHost.isNotBlank()) params.add("host=${Uri.encode(profile.wsHost)}")
                if (profile.network.equals("grpc", ignoreCase = true)) {
                    if (profile.path.isNotBlank()) params.add("serviceName=${Uri.encode(profile.path)}")
                    if (profile.grpcMode.isNotBlank()) params.add("mode=${Uri.encode(profile.grpcMode)}")
                    if (profile.grpcAuthority.isNotBlank()) params.add("authority=${Uri.encode(profile.grpcAuthority)}")
                } else if (profile.path.isNotBlank()) {
                    params.add("path=${Uri.encode(profile.path)}")
                }
                if (profile.headerType.isNotBlank() && profile.headerType != "none") {
                    params.add("headerType=${Uri.encode(profile.headerType)}")
                }
                if (profile.flow.isNotBlank()) params.add("flow=${Uri.encode(profile.flow)}")
                if (profile.fingerprint.isNotBlank()) params.add("fp=${Uri.encode(profile.fingerprint)}")
                if (profile.alpn.isNotBlank()) params.add("alpn=${Uri.encode(profile.alpn)}")
                if (profile.publicKey.isNotBlank()) params.add("pbk=${Uri.encode(profile.publicKey)}")
                if (profile.shortId.isNotBlank()) params.add("sid=${Uri.encode(profile.shortId)}")
                if (profile.spiderX.isNotBlank()) params.add("spx=${Uri.encode(profile.spiderX)}")
                if (profile.allowInsecureSsl) params.add("allowInsecure=1")
                "vless://${profile.password}@${profile.server}:${profile.port}?${params.joinToString("&")}#${Uri.encode(profile.name)}"
            }
            ProtocolType.TROJAN -> {
                "trojan://${profile.password}@${profile.server}:${profile.port}?sni=${profile.sni}#${Uri.encode(profile.name)}"
            }
            ProtocolType.VMESS -> {
                val json = JSONObject().apply {
                    put("v", "2")
                    put("ps", profile.name)
                    put("add", profile.server)
                    put("port", profile.port)
                    put("id", profile.password)
                    put("net", profile.network)
                    put("tls", profile.security)
                    put("sni", profile.sni)
                    put("host", profile.wsHost.ifBlank { profile.sni })
                    put("path", profile.path)
                }
                "vmess://${Base64.encodeToString(json.toString().toByteArray(), Base64.NO_WRAP)}"
            }
            ProtocolType.SSH -> {
                "ssh://${profile.sshUsername}:${profile.password}@${profile.server}:${profile.port}?mode=${profile.sshMode.name}&proxy_host=${profile.proxyHost}&proxy_port=${profile.proxyPort}&sni=${profile.sshSni}&ws_path=${profile.sshWsPath}#${Uri.encode(profile.name)}"
            }
            else -> {
                exportProfileToJson(profile)
            }
        }
    }

    fun exportProfileToJson(profile: VpnProfile): String {
        val obj = JSONObject().apply {
            put("id", profile.id)
            put("name", profile.name)
            put("protocol", profile.protocol.name)
            put("server", profile.server)
            put("port", profile.port)
            put("password", profile.password)
            put("security", profile.security)
            put("network", profile.network)
            put("path", profile.path)
            put("sni", profile.sni)
            put("wsHost", profile.wsHost)
            put("headerType", profile.headerType)
            put("grpcMode", profile.grpcMode)
            put("grpcAuthority", profile.grpcAuthority)
            put("publicKey", profile.publicKey)
            put("shortId", profile.shortId)
            put("spiderX", profile.spiderX)
            put("fingerprint", profile.fingerprint)
            put("alpn", profile.alpn)
            put("flow", profile.flow)
            put("encryption", profile.encryption)
            put("sshUsername", profile.sshUsername)
            put("sshPayload", profile.sshPayload)
            put("proxyHost", profile.proxyHost)
            put("proxyPort", profile.proxyPort)
            put("dnsPrimary", profile.dnsPrimary)
            put("dnsSecondary", profile.dnsSecondary)
            put("blockIpv6", profile.blockIpv6)
            put("sshMode", profile.sshMode.name)
            put("sshPrivateKey", profile.sshPrivateKey)
            put("sshPassphrase", profile.sshPassphrase)
            put("sshProxyUser", profile.sshProxyUser)
            put("sshProxyPass", profile.sshProxyPass)
            put("sshSni", profile.sshSni)
            put("sshWsPath", profile.sshWsPath)
            put("sshCustomHeaders", profile.sshCustomHeaders)
            put("sshChainProxyHost", profile.sshChainProxyHost)
            put("sshChainProxyPort", profile.sshChainProxyPort)
            put("sshChainProxyType", profile.sshChainProxyType)
            put("sshLocalForwardPort", profile.sshLocalForwardPort)
            put("sshRemoteForwardHost", profile.sshRemoteForwardHost)
            put("sshRemoteForwardPort", profile.sshRemoteForwardPort)
            put("sshRemoteListenPort", profile.sshRemoteListenPort)
            put("allowInsecureSsl", profile.allowInsecureSsl)
            put("isLocked", profile.isLocked)
            put("lockPasswordHash", profile.lockPasswordHash)
            put("expiresAtMillis", profile.expiresAtMillis)
            put("lockedHwid", profile.lockedHwid)
            put("blockRoot", profile.blockRoot)
            put("creatorMessage", profile.creatorMessage)
        }
        return obj.toString(2)
    }

    fun exportProfileToCtp(
        profile: VpnProfile,
        options: CtpExportOptions = CtpExportOptions()
    ): String {
        val baseJson = exportProfileToJson(profile)
        return CtpConfigCrypto.encryptProfileJsonToCtp(baseJson, options)
    }
}

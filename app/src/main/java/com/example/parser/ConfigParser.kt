package com.example.parser

import android.net.Uri
import android.util.Base64
import com.example.model.ProtocolType
import com.example.model.SshTunnelMode
import com.example.model.VpnProfile
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.UUID

sealed class ParseResult {
    data class Success(val profile: VpnProfile) : ParseResult()
    data class Failure(val reason: String, val details: String? = null) : ParseResult()
}

object ConfigParser {

    fun parse(rawInput: String): ParseResult {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            return ParseResult.Failure("Empty configuration string")
        }

        return try {
            when {
                trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmess(trimmed)
                trimmed.startsWith("vless://", ignoreCase = true) -> parseVless(trimmed)
                trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojan(trimmed)
                trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(trimmed)
                trimmed.startsWith("ssh://", ignoreCase = true) -> parseSshUri(trimmed)
                trimmed.startsWith("{") -> parseJson(trimmed)
                trimmed.contains("@") && !trimmed.contains("://") -> parseSshUri(trimmed)
                else -> ParseResult.Failure("Unsupported format. Expected vmess://, vless://, trojan://, ss://, ssh://, or Xray JSON.")
            }
        } catch (e: Exception) {
            ParseResult.Failure("Failed to parse configuration: ${e.message}", e.stackTraceToString())
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
        val network = json.optString("net", "tcp")
        val security = json.optString("tls", "none")
        val sni = json.optString("sni", json.optString("host", ""))
        val path = json.optString("path", "")
        val alpn = json.optString("alpn", "")

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
            alpn = alpn
        )
        return ParseResult.Success(profile)
    }

    private fun parseVless(uriStr: String): ParseResult {
        val uri = Uri.parse(uriStr)
        val uuid = uri.userInfo ?: return ParseResult.Failure("VLESS missing UUID in user info")
        val host = uri.host ?: return ParseResult.Failure("VLESS missing host")
        val port = uri.port
        if (port !in 1..65535) return ParseResult.Failure("VLESS invalid port: $port")

        val queryParams = parseQueryParams(uri.query)
        val name = uri.fragment?.let { URLDecoder.decode(it, "UTF-8") } ?: "VLESS-$host:$port"
        val security = queryParams["security"] ?: "none"
        val network = queryParams["type"] ?: "tcp"
        val sni = queryParams["sni"] ?: queryParams["host"] ?: ""
        val path = queryParams["path"] ?: ""
        val pbk = queryParams["pbk"] ?: ""
        val sid = queryParams["sid"] ?: ""
        val fp = queryParams["fp"] ?: "chrome"
        val alpn = queryParams["alpn"] ?: ""
        val flow = queryParams["flow"] ?: ""

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.VLESS,
            server = host,
            port = port,
            password = uuid,
            security = security,
            network = network,
            path = path,
            sni = sni,
            publicKey = pbk,
            shortId = sid,
            fingerprint = fp,
            alpn = alpn,
            flow = flow
        )
        return ParseResult.Success(profile)
    }

    private fun parseTrojan(uriStr: String): ParseResult {
        val uri = Uri.parse(uriStr)
        val password = uri.userInfo ?: return ParseResult.Failure("Trojan missing password")
        val host = uri.host ?: return ParseResult.Failure("Trojan missing host")
        val port = uri.port
        if (port !in 1..65535) return ParseResult.Failure("Trojan invalid port: $port")

        val queryParams = parseQueryParams(uri.query)
        val name = uri.fragment?.let { URLDecoder.decode(it, "UTF-8") } ?: "Trojan-$host:$port"
        val sni = queryParams["sni"] ?: queryParams["peer"] ?: host
        val network = queryParams["type"] ?: "tcp"
        val alpn = queryParams["alpn"] ?: ""

        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = name,
            protocol = ProtocolType.TROJAN,
            server = host,
            port = port,
            password = password,
            security = "tls",
            network = network,
            sni = sni,
            alpn = alpn
        )
        return ParseResult.Success(profile)
    }

    private fun parseShadowsocks(uriStr: String): ParseResult {
        // ss://BASE64(method:password)@host:port#name or ss://BASE64(method:password@host:port)#name
        val withoutScheme = uriStr.substring(5)
        val parts = withoutScheme.split("#", limit = 2)
        val mainPart = parts[0]
        val name = if (parts.size > 1) URLDecoder.decode(parts[1], "UTF-8") else "Shadowsocks"

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
            URLDecoder.decode(uriStr.substringAfter("#"), "UTF-8")
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
                    publicKey = root.optString("publicKey", ""),
                    shortId = root.optString("shortId", ""),
                    fingerprint = root.optString("fingerprint", "chrome"),
                    alpn = root.optString("alpn", "h2,http/1.1"),
                    sshUsername = root.optString("sshUsername", ""),
                    sshPayload = root.optString("sshPayload", ""),
                    proxyHost = root.optString("proxyHost", ""),
                    proxyPort = root.optInt("proxyPort", 0),
                    flow = root.optString("flow", ""),
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
                    allowInsecureSsl = root.optBoolean("allowInsecureSsl", false)
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
            if (settings != null) {
                val vnext = settings.optJSONArray("vnext")
                if (vnext != null && vnext.length() > 0) {
                    val target = vnext.getJSONObject(0)
                    server = target.optString("address", "")
                    port = target.optInt("port", 443)
                    val users = target.optJSONArray("users")
                    if (users != null && users.length() > 0) {
                        id = users.getJSONObject(0).optString("id", "")
                    }
                }
            }
            if (server.isEmpty()) return ParseResult.Failure("Cannot parse outbound server address from Xray JSON")

            return ParseResult.Success(
                VpnProfile(
                    id = UUID.randomUUID().toString(),
                    name = "Xray-$server:$port",
                    protocol = proto,
                    server = server,
                    port = port,
                    password = id
                )
            )
        }

        return ParseResult.Failure("JSON does not contain recognized Xray outbounds or Aegis profile schema")
    }

    private fun parseQueryParams(query: String?): Map<String, String> {
        if (query.isNullOrEmpty()) return emptyMap()
        val map = mutableMapOf<String, String>()
        val pairs = query.split("&")
        for (pair in pairs) {
            val idx = pair.indexOf("=")
            if (idx > 0) {
                val key = URLDecoder.decode(pair.substring(0, idx), "UTF-8")
                val value = URLDecoder.decode(pair.substring(idx + 1), "UTF-8")
                map[key] = value
            }
        }
        return map
    }

    fun exportProfileToUri(profile: VpnProfile): String {
        return when (profile.protocol) {
            ProtocolType.VLESS -> {
                val flowParam = if (profile.flow.isNotBlank()) "&flow=${profile.flow}" else ""
                "vless://${profile.password}@${profile.server}:${profile.port}?security=${profile.security}&type=${profile.network}&sni=${profile.sni}&path=${profile.path}$flowParam#${Uri.encode(profile.name)}"
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
            put("publicKey", profile.publicKey)
            put("shortId", profile.shortId)
            put("fingerprint", profile.fingerprint)
            put("alpn", profile.alpn)
            put("sshUsername", profile.sshUsername)
            put("sshPayload", profile.sshPayload)
            put("proxyHost", profile.proxyHost)
            put("proxyPort", profile.proxyPort)
            put("dnsPrimary", profile.dnsPrimary)
            put("dnsSecondary", profile.dnsSecondary)
            put("blockIpv6", profile.blockIpv6)
            put("flow", profile.flow)
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
        }
        return obj.toString(2)
    }
}

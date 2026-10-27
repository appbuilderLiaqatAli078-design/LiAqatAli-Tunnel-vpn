package com.example

import com.example.data.AppLogger
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.model.VpnState
import com.example.parser.ConfigParser
import com.example.parser.ParseResult
import com.example.vpn.engine.PayloadInjector
import com.example.vpn.engine.XrayEngineAdapter
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleUnitTest {

    @Test
    fun testVlessConfigParser() {
        val vlessUri = "vless://d342d110-d4a3-4513-bfa6-07a5e0f0ff37@example.com:443?security=tls&type=ws&sni=example.com&path=/vless#MyVlessNode"
        val result = ConfigParser.parse(vlessUri)

        assertTrue(result is ParseResult.Success)
        val profile = (result as ParseResult.Success).profile
        assertEquals("MyVlessNode", profile.name)
        assertEquals(ProtocolType.VLESS, profile.protocol)
        assertEquals("example.com", profile.server)
        assertEquals(443, profile.port)
        assertEquals("d342d110-d4a3-4513-bfa6-07a5e0f0ff37", profile.password)
        assertEquals("tls", profile.security)
        assertEquals("ws", profile.network)
        assertEquals("/vless", profile.path)
        assertEquals("example.com", profile.sni)
    }

    @Test
    fun testTrojanConfigParser() {
        val trojanUri = "trojan://secretPass123@gateway.trojan.org:443?sni=gateway.trojan.org#SecureTrojan"
        val result = ConfigParser.parse(trojanUri)

        assertTrue(result is ParseResult.Success)
        val profile = (result as ParseResult.Success).profile
        assertEquals("SecureTrojan", profile.name)
        assertEquals(ProtocolType.TROJAN, profile.protocol)
        assertEquals("gateway.trojan.org", profile.server)
        assertEquals(443, profile.port)
        assertEquals("secretPass123", profile.password)
    }

    @Test
    fun testSshConfigParser() {
        val sshUri = "ssh://root:mySecretPass@192.168.1.100:22#SSH-Direct"
        val result = ConfigParser.parse(sshUri)

        assertTrue(result is ParseResult.Success)
        val profile = (result as ParseResult.Success).profile
        assertEquals("SSH-Direct", profile.name)
        assertEquals(ProtocolType.SSH, profile.protocol)
        assertEquals("192.168.1.100", profile.server)
        assertEquals(22, profile.port)
        assertEquals("root", profile.sshUsername)
        assertEquals("mySecretPass", profile.password)
    }

    @Test
    fun testInvalidConfigParsingFailsGracefully() {
        val invalidUri = "unsupported://bad-protocol.com"
        val result = ConfigParser.parse(invalidUri)
        assertTrue(result is ParseResult.Failure)

        val emptyResult = ConfigParser.parse("")
        assertTrue(emptyResult is ParseResult.Failure)
    }

    @Test
    fun testPayloadInjectorMacroFormatting() {
        val raw = "GET / HTTP/1.1[crlf]Host: [host][crlf]X-Target: [host_port][crlf][crlf]"
        val formatted = PayloadInjector.formatPayload(raw, "api.myisp.com", 8080)

        assertTrue(formatted.contains("Host: api.myisp.com"))
        assertTrue(formatted.contains("X-Target: api.myisp.com:8080"))
        assertTrue(formatted.contains("\r\n"))
        assertFalse(formatted.contains("[crlf]"))
    }

    @Test
    fun testCredentialRedactionInLogger() {
        val sensitiveMsg = "User connected with uuid=d342d110-d4a3-4513-bfa6-07a5e0f0ff37 and password=SuperSecretPass! on ssh://user:secret123@1.2.3.4:22"
        val redacted = AppLogger.redact(sensitiveMsg)

        assertFalse(redacted.contains("SuperSecretPass!"))
        assertFalse(redacted.contains("d342d110-d4a3-4513-bfa6-07a5e0f0ff37"))
        assertFalse(redacted.contains("secret123"))
        assertTrue(redacted.contains("password=******"))
        assertTrue(redacted.contains(":******@"))
    }

    @Test
    fun testXrayConfigBuilderProducesValidJson() {
        val adapter = XrayEngineAdapter()
        val profile = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = "Test VLESS",
            protocol = ProtocolType.VLESS,
            server = "vpn.example.com",
            port = 443,
            password = "uuid-test-value",
            security = "tls",
            network = "ws",
            path = "/ws-path",
            sni = "vpn.example.com"
        )

        val jsonStr = adapter.buildXrayConfig(profile, 10808)
        val json = JSONObject(jsonStr)

        assertNotNull(json.optJSONArray("inbounds"))
        val inbounds = json.getJSONArray("inbounds")
        assertEquals(1, inbounds.length())
        assertEquals(10808, inbounds.getJSONObject(0).getInt("port"))
        assertEquals("socks", inbounds.getJSONObject(0).getString("protocol"))

        assertNotNull(json.optJSONArray("outbounds"))
        val outbounds = json.getJSONArray("outbounds")
        assertTrue(outbounds.length() >= 2)
        assertEquals("proxy", outbounds.getJSONObject(0).getString("tag"))
        assertEquals("vless", outbounds.getJSONObject(0).getString("protocol"))
    }

    @Test
    fun testVpnStateProperties() {
        val disconnected = VpnState.Disconnected
        assertFalse(disconnected.isConnected)
        assertFalse(disconnected.isBusy)

        val connecting = VpnState.Connecting("Test Server")
        assertFalse(connecting.isConnected)
        assertTrue(connecting.isBusy)

        val connected = VpnState.Connected("Test Server", System.currentTimeMillis(), "Xray")
        assertTrue(connected.isConnected)
        assertFalse(connected.isBusy)
    }

    @Test
    fun testAllSshTunnelModesEnum() {
        val modes = com.example.model.SshTunnelMode.values()
        assertEquals(14, modes.size)
        modes.forEach { mode ->
            assertTrue(mode.displayName.isNotBlank())
            assertTrue(mode.badge.isNotBlank())
            assertTrue(mode.description.isNotBlank())
        }
    }

    @Test
    fun testSshModesUriParsing() {
        val wssUri = "ssh://myuser:mypass@ssh.server.net:443?mode=SECURE_WEBSOCKET&sni=cdn.cloudflare.net&ws_path=/custom-ssh#CloudflareWSS"
        val result = ConfigParser.parse(wssUri)

        assertTrue(result is ParseResult.Success)
        val profile = (result as ParseResult.Success).profile
        assertEquals("CloudflareWSS", profile.name)
        assertEquals(ProtocolType.SSH, profile.protocol)
        assertEquals(com.example.model.SshTunnelMode.SECURE_WEBSOCKET, profile.sshMode)
        assertEquals("ssh.server.net", profile.server)
        assertEquals(443, profile.port)
        assertEquals("myuser", profile.sshUsername)
        assertEquals("mypass", profile.password)
        assertEquals("cdn.cloudflare.net", profile.sshSni)
        assertEquals("/custom-ssh", profile.sshWsPath)
    }

    @Test
    fun testSshSocks5AndPortForwardingUriParsing() {
        val fwdUri = "ssh://root:admin123@10.0.0.1:22?mode=LOCAL_PORT_FORWARDING&local_fwd_port=9090&remote_fwd_host=192.168.1.50&remote_fwd_port=3306#DatabaseTunnel"
        val result = ConfigParser.parse(fwdUri)

        assertTrue(result is ParseResult.Success)
        val profile = (result as ParseResult.Success).profile
        assertEquals(com.example.model.SshTunnelMode.LOCAL_PORT_FORWARDING, profile.sshMode)
        assertEquals(9090, profile.sshLocalForwardPort)
        assertEquals("192.168.1.50", profile.sshRemoteForwardHost)
        assertEquals(3306, profile.sshRemoteForwardPort)
    }

    @Test
    fun testSshJsonSerializationAndDeserialization() {
        val original = VpnProfile(
            id = UUID.randomUUID().toString(),
            name = "SSH Pro Multi-Hop Node",
            protocol = ProtocolType.SSH,
            server = "ssh.node.org",
            port = 22,
            sshMode = com.example.model.SshTunnelMode.PROXY_CHAIN,
            sshUsername = "pro_user",
            sshPrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
            sshPassphrase = "passphrase-test",
            proxyHost = "hop1.proxy.net",
            proxyPort = 1080,
            sshChainProxyHost = "hop2.proxy.net",
            sshChainProxyPort = 8080,
            sshChainProxyType = "HTTP",
            allowInsecureSsl = true
        )

        val jsonStr = ConfigParser.exportProfileToJson(original)
        val parseResult = ConfigParser.parse(jsonStr)

        assertTrue(parseResult is ParseResult.Success)
        val restored = (parseResult as ParseResult.Success).profile
        assertEquals(original.name, restored.name)
        assertEquals(original.protocol, restored.protocol)
        assertEquals(original.sshMode, restored.sshMode)
        assertEquals(original.sshUsername, restored.sshUsername)
        assertEquals(original.sshPrivateKey, restored.sshPrivateKey)
        assertEquals(original.sshPassphrase, restored.sshPassphrase)
        assertEquals(original.proxyHost, restored.proxyHost)
        assertEquals(original.proxyPort, restored.proxyPort)
        assertEquals(original.sshChainProxyHost, restored.sshChainProxyHost)
        assertEquals(original.sshChainProxyPort, restored.sshChainProxyPort)
        assertEquals(original.sshChainProxyType, restored.sshChainProxyType)
        assertTrue(restored.allowInsecureSsl)
    }

    @Test
    fun testPayloadInjectorExtendedMacrosAndSplit() {
        val template = "[method] [host_port] [protocol][crlf]Host: [host][crlf][auth]X-Custom: [ua][split]Connection: Keep-Alive[crlf][crlf]"
        val formatted = PayloadInjector.formatPayload(
            rawTemplate = template,
            targetHost = "target.ssh.com",
            targetPort = 22,
            proxyUser = "proxyUser",
            proxyPass = "proxyPass",
            method = "POST"
        )

        assertTrue(formatted.contains("POST target.ssh.com:22 HTTP/1.1\r\n"))
        assertTrue(formatted.contains("Host: target.ssh.com\r\n"))
        assertTrue(formatted.contains("Proxy-Authorization: Basic"))
        assertTrue(formatted.contains("[split]"))
        assertTrue(formatted.contains("Connection: Keep-Alive\r\n\r\n"))
    }

    @Test
    fun testSshTargetParserReferenceFormat() {
        // Reference target format: www.openx.com:80@Test:Test1
        val parsed = com.example.parser.SshTargetParser.parse("www.openx.com:80@Test:Test1")
        assertNotNull(parsed)
        assertEquals("www.openx.com", parsed!!.host)
        assertEquals(80, parsed.port)
        assertEquals("Test", parsed.username)
        assertEquals("Test1", parsed.password)

        // Alternate user:pass@host:port format
        val parsedAlt = com.example.parser.SshTargetParser.parse("Test:Test1@www.openx.com:80")
        assertNotNull(parsedAlt)
        assertEquals("www.openx.com", parsedAlt!!.host)
        assertEquals(80, parsedAlt.port)
        assertEquals("Test", parsedAlt.username)
        assertEquals("Test1", parsedAlt.password)

        // ConfigParser handles direct target string
        val configResult = ConfigParser.parse("www.openx.com:80@Test:Test1")
        assertTrue(configResult is ParseResult.Success)
        val profile = (configResult as ParseResult.Success).profile
        assertEquals("www.openx.com", profile.server)
        assertEquals(80, profile.port)
        assertEquals("Test", profile.sshUsername)
        assertEquals("Test1", profile.password)
        assertEquals(ProtocolType.SSH, profile.protocol)
    }

    @Test
    fun testPayloadInjectorReferenceWebSocketPayload() {
        // Reference payload: GET / HTTP/1.1[crlf]Host: geeksvpn.kevintechtutorials.fun[crlf]Upgrade: websocket[crlf][crlf]
        val payload = "GET / HTTP/1.1[crlf]Host: geeksvpn.kevintechtutorials.fun[crlf]Upgrade: websocket[crlf][crlf]"
        val formatted = PayloadInjector.formatPayload(
            rawTemplate = payload,
            targetHost = "www.openx.com",
            targetPort = 80
        )

        // Exact CRLF replacement without unexpected extra headers or spaces
        assertEquals("GET / HTTP/1.1\r\nHost: geeksvpn.kevintechtutorials.fun\r\nUpgrade: websocket\r\n\r\n", formatted)
        assertFalse(formatted.contains("[crlf]", ignoreCase = true))
    }

    @Test
    fun testEmptyPayloadDoesNotSendConnectInDirectMode() {
        val formatted = PayloadInjector.formatPayload(
            rawTemplate = "",
            targetHost = "www.openx.com",
            targetPort = 80
        )
        // Must not generate CONNECT for direct mode when payload is empty
        assertEquals("", formatted)
    }

    @Test
    fun testLiveSshConnection() {
        val target = "www.openx.com:80@Test:Test1"
        val payload = "GET / HTTP/1.1[crlf]Host: geeksvpn.kevintechtutorials.fun[crlf]Upgrade: websocket[crlf][crlf]"
        val parsed = com.example.parser.SshTargetParser.parse(target)!!

        val rawSocket = java.net.Socket()
        val upgraded = PayloadInjector.injectAndConnect(
            socket = rawSocket,
            targetHost = parsed.host,
            targetPort = parsed.port,
            proxyHost = "",
            proxyPort = 0,
            payload = payload
        )

        val jsch = com.jcraft.jsch.JSch()
        val session = jsch.getSession(parsed.username, parsed.host, parsed.port)
        session.setPassword(parsed.password)
        val config = java.util.Properties()
        config["StrictHostKeyChecking"] = "no"
        config["PreferredAuthentications"] = "publickey,password,keyboard-interactive"
        session.setConfig(config)

        session.setSocketFactory(object : com.jcraft.jsch.SocketFactory {
            override fun createSocket(host: String, port: Int): java.net.Socket = upgraded
            override fun getInputStream(socket: java.net.Socket): java.io.InputStream = socket.getInputStream()
            override fun getOutputStream(socket: java.net.Socket): java.io.OutputStream = socket.getOutputStream()
        })

        try {
            session.connect(10000)
            println("SESSION CONNECTED: " + session.isConnected + ", serverVersion: " + session.serverVersion)
            session.disconnect()
        } catch (e: Exception) {
            println("SESSION FAILED WITH: " + e.javaClass.name + ": " + e.message)
            e.printStackTrace()
            throw e
        }
    }
}

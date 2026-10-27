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
    fun testPayloadInjectorWithSpacesAndTrailingWhitespace() {
        val payload = "GET   / HTTP/1.1 [crlf]Host: geeksvpn.kevintechtutorials.fun[crlf]Upgrade: websocket[crlf][crlf] "
        val formatted = PayloadInjector.formatPayload(
            rawTemplate = payload,
            targetHost = "www.openx.com",
            targetPort = 80
        )
        assertTrue(formatted.startsWith("GET   / HTTP/1.1 \r\nHost: geeksvpn.kevintechtutorials.fun\r\nUpgrade: websocket\r\n\r\n"))
        assertTrue(formatted.endsWith("\r\n\r\n"))
        assertFalse(formatted.contains("[crlf]"))
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
    fun testWebSocketAcceptHeaderComputation() {
        // RFC 6455 Section 1.3 standard test vector
        val key = "dGhlIHNhbXBsZSBub25jZQ=="
        val accept = com.example.vpn.engine.ssh.SshWebSocketHandler.computeAcceptKey(key)
        assertEquals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept)
    }

    @Test
    fun testWebSocketBinaryFramingExtendedLengthsAndPingPong() {
        // Test client-to-server masking across small (<126), 16-bit (1024), and 64-bit (70000) payloads
        for (size in listOf(42, 1024, 70_000)) {
            val rawOut = java.io.ByteArrayOutputStream()
            val wsOut = com.example.vpn.engine.ssh.WebSocketFramedOutputStream(rawOut)
            val original = ByteArray(size) { (it * 31 + 7).toByte() }
            wsOut.write(original)

            val framed = rawOut.toByteArray()
            assertEquals(0x82, framed[0].toInt() and 0xFF) // FIN=1, Binary opcode=2
            val b1 = framed[1].toInt() and 0xFF
            assertTrue("Client frames must set MASK bit (0x80)", (b1 and 0x80) != 0)

            // Feed the masked frame into WebSocketFramedInputStream and verify exact decoded bytes
            val replyOut = java.io.ByteArrayOutputStream()
            val wsIn = com.example.vpn.engine.ssh.WebSocketFramedInputStream(
                java.io.ByteArrayInputStream(framed),
                replyOut
            )
            val decoded = ByteArray(size)
            var totalRead = 0
            while (totalRead < size) {
                val n = wsIn.read(decoded, totalRead, size - totalRead)
                assertTrue(n > 0)
                totalRead += n
            }
            org.junit.Assert.assertArrayEquals(original, decoded)
            assertEquals(-1, wsIn.read())
        }

        // Test server Ping (0x89) -> automatic masked client Pong (0x8A) + subsequent binary SSH frame
        val serverStream = java.io.ByteArrayOutputStream()
        val pingPayload = "keepalive".toByteArray(Charsets.UTF_8)
        serverStream.write(0x89) // FIN=1, Ping
        serverStream.write(pingPayload.size)
        serverStream.write(pingPayload)

        val sshBanner = "SSH-2.0-OpenSSH_9.6p1\r\n".toByteArray(Charsets.UTF_8)
        serverStream.write(0x82) // FIN=1, Binary
        serverStream.write(sshBanner.size)
        serverStream.write(sshBanner)

        // Close frame (0x88)
        serverStream.write(0x88)
        serverStream.write(0x00)

        val clientOut = java.io.ByteArrayOutputStream()
        val wsIn = com.example.vpn.engine.ssh.WebSocketFramedInputStream(
            java.io.ByteArrayInputStream(serverStream.toByteArray()),
            clientOut
        )
        val received = ByteArray(sshBanner.size)
        val n = wsIn.read(received)
        assertEquals(sshBanner.size, n)
        assertEquals("SSH-2.0-OpenSSH_9.6p1\r\n", String(received, Charsets.UTF_8))
        assertEquals(-1, wsIn.read()) // Close frame returns EOF

        val sentBytes = clientOut.toByteArray()
        // First control reply must be masked Pong (0x8A) with length = pingPayload.size
        assertEquals(0x8A, sentBytes[0].toInt() and 0xFF)
        assertEquals(0x80 or pingPayload.size, sentBytes[1].toInt() and 0xFF)
        val pongMask = sentBytes.sliceArray(2..5)
        val unmaskedPong = ByteArray(pingPayload.size) { i ->
            (sentBytes[6 + i].toInt() xor pongMask[i and 3].toInt()).toByte()
        }
        org.junit.Assert.assertArrayEquals(pingPayload, unmaskedPong)
    }

    @Test
    fun testWebSocketHandshakeAndFramedSshStreamForwarding() {
        val serverSocket = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        val port = serverSocket.localPort
        val serverBanner = "SSH-2.0-OpenSSH_9.6p1_WS\r\n"

        val serverThread = Thread {
            serverSocket.use { srv ->
                val client = srv.accept()
                client.use { sock ->
                    val inp = sock.getInputStream()
                    val out = sock.getOutputStream()
                    // Read client HTTP Upgrade request until blank line
                    while (true) {
                        val line = PayloadInjector.readLine(inp) ?: break
                        if (line.isEmpty()) break
                    }
                    // Send HTTP 101 Switching Protocols followed immediately by a WebSocket binary frame containing SSH banner
                    val responseHeaders = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                    out.write(responseHeaders.toByteArray(Charsets.UTF_8))
                    val bannerBytes = serverBanner.toByteArray(Charsets.UTF_8)
                    out.write(byteArrayOf(0x82.toByte(), bannerBytes.size.toByte()))
                    out.write(bannerBytes)
                    out.flush()
                }
            }
        }
        serverThread.start()

        val clientSocket = java.net.Socket()
        val upgraded = PayloadInjector.injectAndConnect(
            socket = clientSocket,
            targetHost = "127.0.0.1",
            targetPort = port,
            proxyHost = "",
            proxyPort = 0,
            payload = "GET / HTTP/1.1[crlf]Host: 127.0.0.1[crlf]Upgrade: websocket[crlf][crlf]",
            timeoutMs = 5000
        )

        assertTrue("Expected WebSocketFramedSocket when server sends WS binary frames", upgraded is com.example.vpn.engine.ssh.WebSocketFramedSocket)
        val readLine = PayloadInjector.readLine(upgraded.getInputStream())
        assertEquals("SSH-2.0-OpenSSH_9.6p1_WS", readLine)
        upgraded.close()
        serverThread.join(2000)
    }

    @Test
    fun testHttp101WithoutSshSupportIsRejected() {
        val serverSocket = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        val port = serverSocket.localPort

        val serverThread = Thread {
            serverSocket.use { srv ->
                val client = srv.accept()
                client.use { sock ->
                    val inp = sock.getInputStream()
                    val out = sock.getOutputStream()
                    while (true) {
                        val line = PayloadInjector.readLine(inp) ?: break
                        if (line.isEmpty()) break
                    }
                    // Respond 101 Switching Protocols but send non-SSH HTML payload
                    out.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n<html>Not an SSH Server</html>\r\n".toByteArray(Charsets.UTF_8))
                    out.flush()
                }
            }
        }
        serverThread.start()

        var rejected = false
        try {
            PayloadInjector.injectAndConnect(
                socket = java.net.Socket(),
                targetHost = "127.0.0.1",
                targetPort = port,
                proxyHost = "",
                proxyPort = 0,
                payload = "GET / HTTP/1.1[crlf]Host: 127.0.0.1[crlf]Upgrade: websocket[crlf][crlf]",
                timeoutMs = 5000
            )
        } catch (e: IllegalStateException) {
            rejected = e.message?.contains("SSH", ignoreCase = true) == true
        }
        assertTrue("101 response without SSH banner must be rejected", rejected)
        serverThread.join(2000)
    }

    @Test
    fun testLiveSshConnection() {
        val target = "www.openx.com:80@Test:Test1"
        val payload = "GET / HTTP/1.1[crlf]Host: geeksvpn.kevintechtutorials.fun[crlf]Upgrade: websocket[crlf][crlf]"
        val parsed = com.example.parser.SshTargetParser.parse(target)!!

        val rawSocket = java.net.Socket()
        try { rawSocket.bind(null) } catch (_: Exception) {}
        val upgraded = PayloadInjector.injectAndConnect(
            socket = rawSocket,
            targetHost = parsed.host,
            targetPort = parsed.port,
            proxyHost = "",
            proxyPort = 0,
            payload = payload,
            timeoutMs = 30000
        )

        val jsch = com.jcraft.jsch.JSch()
        val session = jsch.getSession(parsed.username, parsed.host, parsed.port)
        session.setPassword(parsed.password)
        val config = java.util.Properties()
        config["StrictHostKeyChecking"] = "no"
        config["PreferredAuthentications"] = "publickey,password,keyboard-interactive"
        session.setConfig(config)
        // Regression test: verify session timeout and serverAliveInterval in milliseconds
        // (matching SshEngineAdapter configuration so KEX does not fail with "timeout in waiting for rekeying process")
        session.timeout = 30_000
        session.serverAliveCountMax = 3

        session.setSocketFactory(object : com.jcraft.jsch.SocketFactory {
            override fun createSocket(host: String, port: Int): java.net.Socket = upgraded
            override fun getInputStream(socket: java.net.Socket): java.io.InputStream = socket.getInputStream()
            override fun getOutputStream(socket: java.net.Socket): java.io.OutputStream = socket.getOutputStream()
        })

        try {
            session.connect(30_000)
            session.serverAliveInterval = 30_000
            assertTrue(session.isConnected)
            assertTrue(session.serverVersion.startsWith("SSH-2.0-"))
            println("SESSION CONNECTED: " + session.isConnected + ", serverVersion: " + session.serverVersion)
            session.disconnect()
        } catch (e: Exception) {
            println("SESSION FAILED WITH: " + e.javaClass.name + ": " + e.message)
            e.printStackTrace()
            throw e
        }
    }
}
